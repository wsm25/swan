package swan

import (
	"fmt"
	"net"
	"time"

	"github.com/wsm25/swan/eap"
	"github.com/wsm25/swan/transport"
	"github.com/wsm25/swan/xcrypto"
)

// LogicalNatTPort is the logical NAT-T/IKE port used inside the protocol.
// The injected stream wire hides the real socket, so every NAT-D hash,
// keepalive and packet classification treats the port as 4500 regardless of
// any backend-specific local port.
const LogicalNatTPort = transport.LogicalNatTPort

// Config describes one initiator handshake against a fixed responder.
//
// This is facility-level configuration: protocol knobs are grouped here,
// while worker concurrency knobs live in QueueSizes/Timeouts so the caller
// can reason about both at once.
type Config struct {
	// PeerIP is the responder address used for NAT-D hashing. With a stream
	// wire the library cannot learn it from the socket, so the caller must
	// supply the address the backend is talking to.
	PeerIP net.IP
	// LocalIP is the address the backend reports locally. Optional: when
	// empty the transport layer treats the local side as unknown and NAT-D
	// still uses the logical port 4500.
	LocalIP net.IP

	// IKEProposals / ESPProposals are strongswan-style proposals
	// ("aes256gcm16-prfsha512-curve25519"); parse with
	// xcrypto.ParseProposals before filling this field.
	IKEProposals []xcrypto.Proposal
	ESPProposals []xcrypto.Proposal

	// IDI is the initiator identity string, parsed with wire.ClassifyID
	// (supports "@fqdn", "#keyid", "keyid:", "ipv4:", bare IP, email etc).
	IDI string
	// RightID is the expected responder identity, e.g. "@stu.vpn.sjtu.edu.cn".
	// "%any" and "*" mean wildcard.
	RightID string
	// AAAIdentity is the PEAP/TLS server name, e.g. "@radius.net.sjtu.edu.cn".
	// It is verified by the inner TLS engine and may differ from RightID.
	AAAIdentity string

	// EAP carries the method selection and credentials.
	EAP eap.Config

	// InsecureSkipPeerCertVerify disables responder certificate chain
	// verification for AUTH method 14. Identity and signature checks remain.
	InsecureSkipPeerCertVerify bool

	Queue    QueueSizes
	Timeouts Timeouts
	Rekey    RekeyConfig
}

// Lifetime limits one SA family. Zero time means disabled. For the IKE SA
// the soft rekey is time-driven; Bytes and Packets are currently ignored
// for IKE (they apply to the CHILD SA outbound path only).
type Lifetime struct {
	Time    time.Duration // soft rekey limit
	Bytes   uint64        // outbound byte limit, 0 = disabled
	Packets uint64        // outbound packet limit, 0 = disabled
}

// RekeyConfig groups rekey/lifetime policy.
type RekeyConfig struct {
	IKE   Lifetime
	Child Lifetime

	// ChildPFS makes a CHILD_SA rekey include KEi/KEr (RFC 7296 2.17).
	// The DH group comes from the selected ESP proposal's DH list.
	ChildPFS bool

	// RandTime is the maximum random backoff subtracted from soft rekey
	// deadlines before starting a rekey (RFC 7296 2.8 jitter). Zero uses
	// 10% of each SA family's soft lifetime.
	RandTime time.Duration

	// RetryInterval is the backoff before retrying a failed rekey.
	// The old SA stays alive across rekey failures.
	RetryInterval time.Duration

	// NearWrapThreshold is the fraction of the ESP sequence space at
	// which the data plane raises an emergency rekey trigger.
	// Values clamp to [0.1, 0.999]; 0 uses the default.
	NearWrapThreshold float64
}

// QueueSizes bounds every channel between layers. Zero values are replaced
// by DefaultConfig. Bounds provide backpressure: a slow consumer stalls the
// producer that feeds it, never growing memory unboundedly.
type QueueSizes struct {
	// Rx datagrams buffered inside transport between read and classify.
	Rx int
	// Ctl is the classified-IKE channel into the control layer.
	Ctl int
	// Esp is the classified-ESP channel into the data plane.
	Esp int
	// Data is the raw IP packet channel in each direction.
	Data int
	// Events is the event mailbox per subscriber (hub itself may drop when
	// a subscriber overflows; see swan/events).
	Events int
}

// Timeouts control request retransmission, keepalive cadence and fragment
// reassembly. All durations must be > 0; zero values are replaced by
// DefaultConfig.
type Timeouts struct {
	// InitialRTO is the first retransmit timeout (swan2: 1s).
	InitialRTO time.Duration
	// MaxRTO caps the exponential backoff after repeated retransmits.
	MaxRTO time.Duration
	// MaxRetries is the retransmit budget per request (swan2: 5).
	MaxRetries uint8
	// Keepalive drives the empty protected INFORMATIONAL keepalive cadence.
	// Like every other request, an unanswered keepalive retransmits on the
	// InitialRTO/MaxRTO ladder and exhausts the session after MaxRetries.
	Keepalive time.Duration
	// SkfReassemblyTimeout expires incomplete inbound SKF reassembly
	// (swan2: 15s).
	SkfReassemblyTimeout time.Duration
}

// DefaultConfig returns the MVP defaults for a given peer address.
// PEAP fragment size 1024, max 32 EAP messages, no PEAP length prefix,
// deterministic event ordering, and the swan2 queue/timeout defaults.
func DefaultConfig(peerIP net.IP) Config {
	return Config{
		PeerIP: append(net.IP(nil), peerIP...),
		EAP: eap.Config{
			Method:          "peap",
			FragmentSize:    1024,
			MaxMessageCount: 32,
			IncludeLength:   false,
		},
		Queue: QueueSizes{Rx: 128, Ctl: 128, Esp: 128, Data: 128, Events: 128},
		Timeouts: Timeouts{
			InitialRTO:           time.Second,
			MaxRTO:               8 * time.Second,
			MaxRetries:           5,
			Keepalive:            20 * time.Second,
			SkfReassemblyTimeout: 15 * time.Second,
		},
		Rekey: RekeyConfig{
			IKE:               Lifetime{Time: 4 * time.Hour},
			Child:             Lifetime{Time: time.Hour},
			ChildPFS:          true,
			RetryInterval:     30 * time.Second,
			NearWrapThreshold: 0.9,
		},
	}
}

// ParseStrongswanProposals parses the two strongswan-style proposal specs.
// An empty spec produces an empty slice (the caller must then fill the
// Config fields explicitly).
func ParseStrongswanProposals(ikeSpec, espSpec string) (ikePs, espPs []xcrypto.Proposal, err error) {
	if ikeSpec != "" {
		ikePs, err = xcrypto.ParseProposals(ikeSpec)
		if err != nil {
			return nil, nil, fmt.Errorf("swan: parse ike proposals: %w", err)
		}
	}
	if espSpec != "" {
		espPs, err = xcrypto.ParseProposals(espSpec)
		if err != nil {
			return nil, nil, fmt.Errorf("swan: parse esp proposals: %w", err)
		}
	}
	return ikePs, espPs, nil
}

// Validate checks protocol-level invariants (proposals present, non-empty
// identities, valid durations and positive queue sizes).
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("swan: nil config")
	}
	if c.PeerIP == nil {
		return fmt.Errorf("swan: PeerIP is required")
	}
	if len(c.IKEProposals) == 0 {
		return fmt.Errorf("swan: IKEProposals are required")
	}
	if len(c.ESPProposals) == 0 {
		return fmt.Errorf("swan: ESPProposals are required")
	}
	if c.IDI == "" {
		return fmt.Errorf("swan: IDI is required")
	}
	if c.EAP.Identity == "" {
		return fmt.Errorf("swan: EAP.Identity is required")
	}
	if c.EAP.Password == "" {
		return fmt.Errorf("swan: EAP.Password is required")
	}
	if c.EAP.Method == "peap" {
		if c.AAAIdentity == "" && c.EAP.ServerName == "" {
			return fmt.Errorf("swan: AAAIdentity (or EAP.ServerName) is required for peap")
		}
	}
	if c.Queue.Rx <= 0 || c.Queue.Ctl <= 0 || c.Queue.Esp <= 0 || c.Queue.Data <= 0 || c.Queue.Events <= 0 {
		return fmt.Errorf("swan: queue sizes must be > 0")
	}
	if c.Timeouts.InitialRTO <= 0 || c.Timeouts.MaxRTO <= 0 {
		return fmt.Errorf("swan: timeouts must be > 0")
	}
	if c.Timeouts.MaxRTO < c.Timeouts.InitialRTO {
		return fmt.Errorf("swan: MaxRTO must be >= InitialRTO")
	}
	if c.Timeouts.MaxRetries == 0 {
		return fmt.Errorf("swan: MaxRetries must be > 0")
	}
	if c.Timeouts.Keepalive <= 0 {
		return fmt.Errorf("swan: Keepalive must be > 0")
	}
	if c.Timeouts.SkfReassemblyTimeout <= 0 {
		return fmt.Errorf("swan: SkfReassemblyTimeout must be > 0")
	}
	if c.Rekey.IKE.Time <= 0 {
		return fmt.Errorf("swan: Rekey.IKE.Time must be > 0")
	}
	if c.Rekey.Child.Time <= 0 {
		return fmt.Errorf("swan: Rekey.Child.Time must be > 0")
	}
	if c.Rekey.RandTime > 0 {
		if c.Rekey.RandTime > c.Rekey.IKE.Time {
			return fmt.Errorf("swan: Rekey.RandTime must be <= Rekey.IKE.Time")
		}
		if c.Rekey.RandTime > c.Rekey.Child.Time {
			return fmt.Errorf("swan: Rekey.RandTime must be <= Rekey.Child.Time")
		}
	}
	if c.Rekey.RetryInterval <= 0 {
		return fmt.Errorf("swan: Rekey.RetryInterval must be > 0")
	}
	if c.Rekey.ChildPFS {
		pfsOK := false
		for _, esp := range c.ESPProposals {
			if len(esp.DH) > 0 {
				pfsOK = true
				break
			}
		}
		if !pfsOK {
			return fmt.Errorf("swan: ChildPFS requires at least one ESP proposal with a DH group")
		}
	}
	return nil
}
