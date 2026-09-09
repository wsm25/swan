package control

import (
	"net"
	"time"

	"swan/transport"
	"swan/wire"
	"swan/wire/payload"
	"swan/xcrypto"
)

// Phase is the control-plane session phase. Phases advance strictly forward:
//
//	Stopped -> Starting -> SAInitSent -> SAInitEstablished -> AuthBootstrap
//	  -> AuthEAPInProgress -> ChildInstalling -> Running
//	any phase                 -> Failed
type Phase uint8

const (
	PhaseStopped Phase = iota
	PhaseStarting
	PhaseSAInitSent
	PhaseSAInitEstablished
	PhaseAuthBootstrap
	PhaseAuthEAPInProgress
	PhaseChildInstalling
	PhaseRunning
	PhaseFailed
)

// Terminal reports whether no further phase transitions may occur without a
// Reset/Close.
func (p Phase) Terminal() bool {
	return p == PhaseStopped || p == PhaseRunning || p == PhaseFailed
}

// State is the live IKE SA state, owned by exactly one worker at a time
// (Handshake during the handshake, Running afterwards). Nil slices mean
// "not yet received". Checkpoint copies (SAInitRequest/Response, Cookie,
// nonces, certs) own their bytes; everything parsed elsewhere aliases input
// buffers only for the duration of the parse.
type State struct {
	Phase Phase

	// Message-id bookkeeping (RFC 7296 windowing, initiator view).
	NextRequestMessageID           uint32
	ExpectedResponseMessageID      uint32
	HasExpectedResponse            bool
	LastCompletedResponseMessageID uint32
	HasLastCompletedResponse       bool
	FirstIKEAuthSeen               bool

	InitiatorSPI uint64
	ResponderSPI uint64

	// SA_INIT checkpoints: full wire packets are kept because AUTH signing
	// needs the exact bytes.
	SAInitRequest  []byte
	SAInitResponse []byte
	Cookie         []byte

	InitiatorNonce []byte
	ResponderNonce []byte

	InitiatorKE payload.KeyExchange
	ResponderKE payload.KeyExchange
	LocalDH     *xcrypto.DHKey

	IKEKeys     *xcrypto.IKEKeys
	SelectedIKE *xcrypto.Selection
	SelectedESP *xcrypto.Selection

	NAT  NatState
	Auth AuthState

	NegotiatingChild *NegotiatingChildSA
	ActiveChild      *ChildSA

	// OutboundRequest is the retransmission checkpoint of the current
	// in-flight request (built frames kept for identical resends).
	OutboundRequest *Checkpoint
	// InboundHistory caches responses to peer requests (bounded, delete
	// replay support).
	InboundHistory []CachedResponse

	Peer             PeerCapabilities
	InboundFragments *FragmentReassembly

	Assigned      *AssignedConfig
	FailureReason string
	// SuppressAuthFailedNotify avoids echoing AUTHENTICATION_FAILED back at
	// the peer (swan2 behavior).
	SuppressAuthFailedNotify bool
}

// NatState tracks the four NAT-D hashes plus the detected verdict.
type NatState struct {
	SourceHashLocal       []byte
	DestinationHashLocal  []byte
	SourceHashRemote      []byte
	DestinationHashRemote []byte
	Detected              bool
}

// AuthState aggregates everything learned from IKE_AUTH responses.
type AuthState struct {
	FirstIDiPayload             []byte // IDi body sent in bootstrap AUTH
	PeerIDr                     []byte // latest IDr body
	PeerAuthMethod              uint8
	PeerSignatureHashAlgorithms []uint16
	PeerCerts                   [][]byte // X.509 DER chain (CERT payloads)
	LocalEAPMSK                 []byte
}

// NegotiatingChildSA holds the initiator-side CHILD_SA before the final
// IKE_AUTH confirms it.
type NegotiatingChildSA struct {
	InboundSPI uint32
}

// ChildSA is the active CHILD_SA identity: SPIs plus raw TSi/TSr bodies
// (for the installer/logging surface).
type ChildSA struct {
	InboundSPI  uint32
	OutboundSPI uint32
	TSi         []byte
	TSr         []byte
}

// AssignedConfig is the CP reply content (internal address + DNS).
type AssignedConfig struct {
	InternalIPv4       net.IP
	InternalIPv6       net.IP
	InternalIPv6Prefix uint8
	DNS4               []net.IP
	DNS6               []net.IP
	// AddressExpirySeconds is the CP lease lifetime from
	// INTERNAL_ADDRESS_EXPIRY, zero when the responder did not send one.
	// It is reported for the caller; renewing the lease is out of scope
	// for this implementation.
	AddressExpirySeconds uint32
}

// Checkpoint is an outbound request kept for retransmission.
type Checkpoint struct {
	MessageID uint32
	Packets   []*transport.Frame
}

// CachedResponse replays a previously built response for a duplicate peer
// request (bounded history; delete exchanges re-send the same bytes).
type CachedResponse struct {
	MessageID       uint32
	ResponsePackets []*transport.Frame
}

// PeerCapabilities aggregates negotiated NOTIFY capabilities.
type PeerCapabilities struct {
	SupportsEAPOnlyAuthentication bool
	SupportsMessageIDSync         bool
	SupportsFragmentation         bool
}

// FragmentReassembly accumulates inbound SKF fragments for one message.
type FragmentReassembly struct {
	ExchangeType      wire.ExchangeType
	MessageID         uint32
	FirstInnerPayload wire.PayloadType
	Fragments         [][]byte
	ExpiresAt         time.Time
}

// NewState returns the zero state in PhaseStopped.
func NewState() *State {
	return &State{Phase: PhaseStopped}
}

// Reset returns the state to zero (used at the start of a new handshake and
// during cleanup).
func (s *State) Reset() {
	*s = *NewState()
}

// ClearSession wipes key material, nonces, child state, checkpoints and
// fragment state — the cleanup half of a graceful close.
func (s *State) ClearSession() {
	s.IKEKeys = nil
	s.InitiatorNonce = nil
	s.ResponderNonce = nil
	s.Cookie = nil
	s.NegotiatingChild = nil
	s.ActiveChild = nil
	s.OutboundRequest = nil
	s.InboundHistory = s.InboundHistory[:0]
	s.InboundFragments = nil
	s.Assigned = nil
	s.LocalDH = nil
	s.Auth.LocalEAPMSK = nil
	s.Auth.FirstIDiPayload = nil
	s.Auth.PeerIDr = nil
	s.Auth.PeerSignatureHashAlgorithms = nil
	s.Auth.PeerCerts = nil
	s.SAInitRequest = nil
	s.SAInitResponse = nil
	s.HasExpectedResponse = false
	s.HasLastCompletedResponse = false
	s.FirstIKEAuthSeen = false
	s.SuppressAuthFailedNotify = false
}
