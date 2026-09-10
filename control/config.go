package control

import (
	"fmt"
	"net"
	"time"

	"github.com/wsm25/swan/eap"
	"github.com/wsm25/swan/wire/payload"
	"github.com/wsm25/swan/xcrypto"
)

// Config is the protocol configuration consumed by the control plane. The
// public swan.Config is decomposed into this layer-specific shape by the
// Session.
type Config struct {
	// PeerIP / LocalIP feed NAT-D hashes and the transport address
	// tracking. Ports are irrelevant here: NAT-D always uses the logical
	// NAT-T port 4500.
	PeerIP  net.IP
	LocalIP net.IP

	// IKE / ESP proposals in local preference order (already parsed).
	IKE []xcrypto.Proposal
	ESP []xcrypto.Proposal

	// IDI is the initiator identity (already classified to a wire ID).
	IDI payload.ID
	// RightID is the expected responder identity:
	// zero Type means wildcard (%any-equivalent).
	RightID payload.ID
	// AAAIdentity is the PEAP/TLS server name; it may differ from RightID.
	AAAIdentity string

	// EAP carries method selection and credentials.
	EAP eap.Config

	// InsecureSkipPeerCertVerify disables responder chain verification
	// only (used by AUTH method 14); identity/signature remain mandatory.
	InsecureSkipPeerCertVerify bool

	// StrongswanCompatible mirrors swan2's compatibility knob: TLS 1.3
	// PEAP MSK export label and AEAD ESP proposals omitting NO_EXT_SEQ.
	StrongswanCompatible bool

	// Rekey carries lifetime/PFS/rekey policy (copied by value from swan).
	Rekey RekeyConfig

	// Timeouts control the exchange helpers.
	Timeouts Timeouts
	// FragmentPlaintextLimit is the plaintext size above which outbound
	// protected requests are fragmented (SKF), and only when the peer
	// advertised FRAGMENTATION_SUPPORTED. Default 1024.
	FragmentPlaintextLimit int

	// DataUpdates receives rekey/lease updates for the public Session's
	// data-plane wiring. Send-only, bounded, consumed by Session.
	DataUpdates chan<- DataplaneUpdate
	// NearWrap receives the data plane's non-blocking emergency child-rekey
	// trigger.
	NearWrap <-chan struct{}
}

// Lifetime limits one SA family. Zero Time is replaced in normalizeConfig
// for the MVP profile; byte/packet limits may be zero.
type Lifetime struct {
	Time    time.Duration
	Bytes   uint64
	Packets uint64
}

// RekeyConfig mirrors swan.RekeyConfig for the control layer.
type RekeyConfig struct {
	IKE   Lifetime
	Child Lifetime

	// ChildPFS makes a CHILD_SA rekey include KEi/KEr (RFC 7296 2.17).
	ChildPFS bool
	// RandTime is the caller-level backoff cap; zero derives 10% of each
	// SA family soft lifetime in Running's deadline arithmetic.
	RandTime          time.Duration
	RetryInterval     time.Duration
	NearWrapThreshold float64
}

// Timeouts are exchange-level timings. Zero values are replaced by New.
type Timeouts struct {
	InitialRTO           time.Duration
	MaxRTO               time.Duration
	MaxRetries           uint8
	Keepalive            time.Duration
	SkfReassemblyTimeout time.Duration
}

// DefaultTimeouts mirrors swan2: 1s initial RTO doubling up to a cap, 5
// retransmit attempts, 15s SKF reassembly lifetime.
func DefaultTimeouts() Timeouts {
	return Timeouts{
		InitialRTO:           time.Second,
		MaxRTO:               8 * time.Second,
		MaxRetries:           5,
		Keepalive:            DefaultKeepaliveInterval,
		SkfReassemblyTimeout: 15 * time.Second,
	}
}

// Validate checks proposal presence, non-empty AAA identity (required for
// PEAP), positive bounds and duration sanity.
func (c *Config) Validate() error {
	if len(c.IKE) == 0 {
		return fmt.Errorf("control: IKE proposals are required")
	}
	if len(c.ESP) == 0 {
		return fmt.Errorf("control: ESP proposals are required")
	}
	if len(c.IDI.Data) == 0 {
		return fmt.Errorf("control: IDI identity is required")
	}
	if c.EAP.Method == "peap" && c.AAAIdentity == "" {
		return fmt.Errorf("control: AAAIdentity is required for peap")
	}
	if c.Timeouts.InitialRTO <= 0 {
		return fmt.Errorf("control: InitialRTO must be > 0")
	}
	if c.Timeouts.MaxRTO <= 0 {
		return fmt.Errorf("control: MaxRTO must be > 0")
	}
	if c.Timeouts.MaxRetries == 0 {
		return fmt.Errorf("control: MaxRetries must be > 0")
	}
	if c.Timeouts.Keepalive <= 0 {
		return fmt.Errorf("control: Keepalive must be > 0")
	}
	if c.Timeouts.SkfReassemblyTimeout <= 0 {
		return fmt.Errorf("control: SkfReassemblyTimeout must be > 0")
	}
	if c.FragmentPlaintextLimit <= 0 {
		return fmt.Errorf("control: FragmentPlaintextLimit must be > 0")
	}
	if c.Rekey.IKE.Time <= 0 {
		return fmt.Errorf("control: Rekey.IKE.Time must be > 0")
	}
	if c.Rekey.Child.Time <= 0 {
		return fmt.Errorf("control: Rekey.Child.Time must be > 0")
	}
	if c.Rekey.RetryInterval <= 0 {
		return fmt.Errorf("control: Rekey.RetryInterval must be > 0")
	}
	if c.Rekey.ChildPFS {
		pfsOK := false
		for _, esp := range c.ESP {
			if len(esp.DH) > 0 {
				pfsOK = true
				break
			}
		}
		if !pfsOK {
			return fmt.Errorf("control: ChildPFS requires at least one ESP proposal with a DH group")
		}
	}
	return nil
}
