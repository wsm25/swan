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
	PhaseRekeyChildRequesting  // our CREATE_CHILD_SA child rekey in flight
	PhaseRekeyChildInstalling  // response accepted, installing new ESP SA
	PhaseRekeyChildDeletingOld // new child active, DELETE old child in flight
	PhaseRekeyIkeRequesting    // our CREATE_CHILD_SA IKE rekey in flight
	PhaseRekeyIkeInstalling    // response accepted, new IKE SA derived but not yet current
	PhaseRekeyIkeDeletingOld   // new IKE SA current, DELETE old IKE SA in flight
	PhaseFailed
)

// Terminal reports whether no further phase transitions may occur without a
// Reset/Close.
func (p Phase) Terminal() bool {
	return p == PhaseStopped || p == PhaseFailed
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

	// IsOriginalInitiator is true while the local peer is the original
	// initiator of the current IKE SA. It flips when the peer successfully
	// initiated an IKE SA rekey (RFC 7296 2.8.2).
	IsOriginalInitiator bool

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
	// OldChild is the replaced child while its DELETE is outstanding; its
	// inbound ESP codec remains decryptable until the DELETE response
	// arrives (or the peer deletes it).
	OldChild *ChildSA

	// Rekey is the single in-flight rekey context. The running actor has
	// window size 1: no overlapping rekey requests.
	Rekey *RekeyContext
	// OldIKE holds the replaced IKE SA context after a successful IKE
	// rekey, until the old IKE DELETE completes. Cap 1 in the MVP.
	OldIKE []OldIKEContext

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
	// LocalChildInitiator reports whether we initiated the exchange that
	// created this child. It determines which ChildKeys half is outbound
	// (SKei/SKai when true, SKer/SKar when false).
	LocalChildInitiator bool
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

// RekeyKind names the SA family being rekeyed.
type RekeyKind uint8

const (
	RekeyChild RekeyKind = iota
	RekeyIke
)

// RekeyTrigger records why a rekey started.
type RekeyTrigger uint8

const (
	RekeyTriggerTime RekeyTrigger = iota
	RekeyTriggerNearWrap
	RekeyTriggerFlow
)

// RekeyContext is the single in-flight rekey state. The running actor
// consumes it on response, and ClearSession wipes it on shutdown.
type RekeyContext struct {
	Kind      RekeyKind
	Trigger   RekeyTrigger
	StartedAt time.Time
	MessageID uint32 // old-SA MID used by the request
	Ni        []byte
	LocalDH   *xcrypto.DHKey
	LocalKE   *payload.KeyExchange

	// Child only
	OldChild   *ChildSA            // snapshot of ActiveChild
	NewChild   *NegotiatingChildSA // inbound SPI chosen for the new child
	NewPeerSPI uint32              // filled when response processed

	// IKE only
	NewInitiatorSPI uint64
	NewSelection    *xcrypto.Selection
	NewIKEKeys      *xcrypto.IKEKeys
	NewNonceN       []byte // responder nonce
	NewResponderSPI uint64

	// Collision bookkeeping, see design section 7.
	PeerPassive *PassiveRekey
}

// PassiveRekey holds a peer-initiated child rekey we answered while our
// own child rekey was already in flight.
type PassiveRekey struct {
	MessageID uint32
	Ni        []byte
	Nr        []byte
	Child     ChildSA
	Keys      *xcrypto.ChildKeys
	Selection *xcrypto.Selection
}

// OldIKEContext preserves the replaced IKE SA until its DELETE completes.
// The old SA keeps its own numbering (RFC 7296 2.8.2).
type OldIKEContext struct {
	InitiatorSPI        uint64
	ResponderSPI        uint64
	IsOriginalInitiator bool
	SelectedIKE         *xcrypto.Selection
	IKEKeys             *xcrypto.IKEKeys

	// Old SA keeps its own numbering (RFC 7296 2.8.2).
	NextRequestMessageID      uint32
	ExpectedResponseMessageID uint32
	HasExpectedResponse       bool
	OutboundRequest           *Checkpoint
	InboundHistory            []CachedResponse
	InboundFragments          *FragmentReassembly
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

// UpdateKind is the data-plane update type delivered by Running to Session.
type UpdateKind uint8

const (
	// UpdateChildInstalled installs a fresh ESP child (make-before-break).
	UpdateChildInstalled UpdateKind = iota
	// UpdateChildDeleted removes a replaced child's inbound codec, or ends
	// the tunnel when the active child was deleted.
	UpdateChildDeleted
	// UpdateAssigned refreshes the CP-assigned configuration.
	UpdateAssigned
)

// DataplaneUpdate is the control -> Session wiring message for child
// installs/deletes and CP lease renewal.
type DataplaneUpdate struct {
	Kind      UpdateKind
	Child     ChildSA
	Keys      *xcrypto.ChildKeys
	Selection *xcrypto.Selection
	Assigned  AssignedConfig
	// Ack replies to UpdateChildInstalled after the Session data plane has
	// atomically installed the child; Running waits for it before sending
	// the old-child DELETE.
	Ack chan<- struct{}
}

// NewState returns the zero state in PhaseStopped.
func NewState() *State {
	return &State{Phase: PhaseStopped, IsOriginalInitiator: true}
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
	s.OldChild = nil
	s.Rekey = nil
	s.OldIKE = nil
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
