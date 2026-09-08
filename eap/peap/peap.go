package peap

import (
	"errors"
	"fmt"

	"swan/eap"
	"swan/eap/mschapv2"
)

// Method name reported through eap.Method.Name.
const MethodName = "peap"

// Phase tracks the PEAP peer FSM (swan2 PeapPhase values).
type Phase uint8

const (
	PhaseIdle Phase = iota
	PhaseOuterIdentity
	PhaseTLSTunnel
	PhaseInnerMethod
	PhaseAwaitingOuterSuccess
	PhaseAwaitingOuterFailure
	PhaseCompleted
	PhaseFailed
)

// Options carries PEAP-specific tuning. FragmentSize must be positive
// (checked in Initialize); MaxMessageCount <= 0 disables the cap, matching
// swan2's `max_message_count > 0` check.
type Options struct {
	FragmentSize         int
	MaxMessageCount      int
	IncludeLength        bool
	StrongswanCompatible bool
	InsecureSkipVerify   bool
}

// Method is the PEAP peer FSM. Inner method is always MSCHAPv2 in the MVP
// profile. A fresh TLS engine is created at each Initialize.
type Method struct {
	serverName string
	identity   string
	password   string
	opts       Options

	inner *mschapv2.Method
	tls   *Engine

	phase      Phase
	round      uint16
	pendingOut *OutboundFragmenter
	pendingIn  *InboundFragmenter
	messages   int
	msk        []byte
}

// New builds a method with the supplied options; validation happens in
// Initialize.
func New(serverName, identity, password string, opts Options) (*Method, error) {
	return &Method{
		serverName: serverName,
		identity:   identity,
		password:   password,
		opts:       opts,
		phase:      PhaseIdle,
	}, nil
}

var _ eap.Method = (*Method)(nil)

// Name implements eap.Method.
func (m *Method) Name() string {
	return MethodName
}

// Initialize implements eap.Method: validates the option set and resets the
// FSM to the outer identity phase with a fresh inner MSCHAPv2 method and a
// fresh TLS engine.
func (m *Method) Initialize() error {
	if m.identity == "" {
		return errors.New("peap identity is empty")
	}
	if m.password == "" {
		return errors.New("peap password is empty")
	}
	if m.serverName == "" {
		return errors.New("peap aaa_identity is empty")
	}
	if m.opts.FragmentSize <= 0 {
		return errors.New("peap fragment_size must be > 0")
	}
	return m.reset()
}

// Handle implements eap.Method: one PEAP packet per call, threading phases
// per the package doc. Any error flips the FSM into PhaseFailed.
func (m *Method) Handle(packet []byte, round uint16) (eap.Result, error) {
	res, err := m.handleInner(packet, round)
	if err != nil {
		m.phase = PhaseFailed
		return eap.Result{}, err
	}
	return res, nil
}

// handleInner implements the per-phase FSM. Behavior mirrors
// swan2 eap/peap/mod.rs handle_packet_inner: message accounting first,
// then ACK pacing while outbound fragments are pending, then the phase
// match on the parsed outer packet.
func (m *Method) handleInner(packet []byte, round uint16) (eap.Result, error) {
	m.round = round

	outer, err := eap.Parse(packet)
	if err != nil {
		return eap.Result{}, err
	}

	// Parse PEAP request shape first; terminal outer packets are handled
	// per phase below.
	var (
		peap    *peapRequest
		peapErr error
	)
	if outer.Code == eap.CodeRequest && outer.Type == eap.TypePEAP {
		peap, peapErr = parsePeapRequest(outer.Identifier, outer.Data)
		if peapErr != nil {
			return eap.Result{}, peapErr
		}
		// swan2 processed_message_count: count every PEAP-stage packet and
		// fail before doing anything else once the budget is exceeded.
		m.messages++
		if m.opts.MaxMessageCount > 0 && m.messages > m.opts.MaxMessageCount {
			return eap.Result{}, errors.New("peap packet count exceeded")
		}

		// ACK pacing: while the outbound fragmenter is mid-message the
		// server must send an empty ACK between fragments.
		if m.pendingOut.Pending() {
			if !isAckRequest(peap) {
				return eap.Result{}, errors.New("expected peap ack while outbound fragments pending")
			}
			return m.emitNextFragment(peap.identifier)
		}
	}

	switch m.phase {
	case PhaseIdle:
		return eap.Result{}, errors.New("peap method was not initialized")

	case PhaseOuterIdentity:
		switch a := outer; {
		case a.Code == eap.CodeRequest && a.Type == eap.TypeIdentity:
			return eap.Result{Action: eap.ActionSend, Response: m.encodeIdentityResponse(a.Identifier)}, nil
		case peap != nil && a.Code == eap.CodeRequest && a.Type == eap.TypePEAP:
			if peap.flags&FlagStart == 0 {
				return eap.Result{}, errors.New("expected peap start flag")
			}
			if peap.hasLength || len(peap.data) != 0 {
				return eap.Result{}, errors.New("unexpected peap tls data on start")
			}
			m.phase = PhaseTLSTunnel
			hello, err := m.tls.Start()
			if err != nil {
				return eap.Result{}, fmt.Errorf("start peap tls handshake: %w", err)
			}
			return m.emitFragmentedOrSingle(peap.identifier, hello, 0)
		default:
			return eap.Result{}, errors.New("unexpected outer eap packet during peap outer identity phase")
		}

	case PhaseTLSTunnel:
		switch a := outer; {
		case a.Code == eap.CodeRequest && a.Type == eap.TypeIdentity:
			return eap.Result{}, errors.New("unexpected outer identity request during peap tls tunnel")
		case a.Code == eap.CodeFailure:
			return eap.Result{}, errors.New("peap authentication failed")
		case a.Code == eap.CodeSuccess:
			return eap.Result{}, fmt.Errorf("unexpected outer EAP success %d during peap tls tunnel", a.Identifier)
		case peap != nil && a.Code == eap.CodeRequest && a.Type == eap.TypePEAP:
			if peap.flags&FlagStart != 0 {
				return eap.Result{}, errors.New("unexpected peap start flag")
			}
			if isAckRequest(peap) {
				return eap.Result{Action: eap.ActionSend, Response: encodeEmptyAck(peap.identifier)}, nil
			}
			record, complete, err := m.collectTLSRecord(peap)
			if err != nil {
				return eap.Result{}, err
			}
			if !complete {
				return eap.Result{Action: eap.ActionSend, Response: encodeEmptyAck(peap.identifier)}, nil
			}
			out, step, err := m.tls.Feed(record)
			if err != nil {
				return eap.Result{}, fmt.Errorf("peap tls handshake: %w", err)
			}
			return m.onTLSStep(peap.identifier, out, step)
		default:
			return eap.Result{}, errors.New("unexpected outer eap packet during peap tls tunnel")
		}

	case PhaseInnerMethod:
		switch a := outer; {
		case a.Code == eap.CodeRequest && a.Type == eap.TypeIdentity:
			return eap.Result{}, errors.New("unexpected outer identity request during peap inner method")
		case a.Code == eap.CodeFailure:
			return eap.Result{}, errors.New("peap authentication failed")
		case a.Code == eap.CodeSuccess:
			return eap.Result{}, fmt.Errorf("unexpected outer EAP success %d during peap inner method", a.Identifier)
		case peap != nil && a.Code == eap.CodeRequest && a.Type == eap.TypePEAP:
			if peap.flags&FlagStart != 0 {
				return eap.Result{}, errors.New("unexpected peap start flag")
			}
			if isAckRequest(peap) {
				return eap.Result{Action: eap.ActionSend, Response: encodeEmptyAck(peap.identifier)}, nil
			}
			record, complete, err := m.collectTLSRecord(peap)
			if err != nil {
				return eap.Result{}, err
			}
			if !complete {
				return eap.Result{Action: eap.ActionSend, Response: encodeEmptyAck(peap.identifier)}, nil
			}
			plain, err := m.tls.Unprotect(record)
			if err != nil {
				return eap.Result{}, fmt.Errorf("peap tls unprotect: %w", err)
			}
			if len(plain) == 0 {
				return eap.Result{}, errors.New("unexpected empty inner tunneled payload")
			}
			return m.handleInnerMethod(peap.identifier, plain)
		default:
			return eap.Result{}, errors.New("unexpected outer eap packet during peap inner method")
		}

	case PhaseAwaitingOuterSuccess:
		switch outer.Code {
		case eap.CodeSuccess:
			msk, err := m.tls.ExportMSK()
			if err != nil {
				return eap.Result{}, err
			}
			m.msk = append([]byte(nil), msk...)
			m.phase = PhaseCompleted
			return eap.Result{Action: eap.ActionComplete, ExportedMSK: append([]byte(nil), m.msk...)}, nil
		case eap.CodeFailure:
			return eap.Result{}, fmt.Errorf("unexpected outer EAP failure %d after inner success", outer.Identifier)
		default:
			return eap.Result{}, errors.New("unexpected outer eap packet while awaiting outer success")
		}

	case PhaseAwaitingOuterFailure:
		switch outer.Code {
		case eap.CodeFailure:
			return eap.Result{}, errors.New("peap authentication failed")
		case eap.CodeSuccess:
			return eap.Result{}, fmt.Errorf("unexpected outer EAP success %d after inner failure", outer.Identifier)
		default:
			return eap.Result{}, errors.New("unexpected outer eap packet while awaiting outer failure")
		}

	case PhaseCompleted:
		if m.msk == nil {
			return eap.Result{}, errors.New("peap completed without exported msk")
		}
		return eap.Result{Action: eap.ActionComplete, ExportedMSK: append([]byte(nil), m.msk...)}, nil

	case PhaseFailed:
		return eap.Result{}, errors.New("peap method is in failure state")

	default:
		return eap.Result{}, errUnknownPhase(m.phase)
	}
}

// reset rebuilds run state. Callers must have validated config first.
func (m *Method) reset() error {
	if m.tls != nil {
		_ = m.tls.Close()
		m.tls = nil
	}
	tlsEngine, err := NewEngine(m.serverName, m.opts, nil)
	if err != nil {
		return err
	}
	m.inner = mschapv2.New(m.identity, m.password)
	m.tls = tlsEngine
	m.phase = PhaseOuterIdentity
	m.round = 0
	m.pendingOut = NewOutboundFragmenter(m.opts.FragmentSize, m.opts.IncludeLength)
	if m.pendingOut == nil {
		return errors.New("peap fragment_size must be > 0")
	}
	m.pendingIn = NewInboundFragmenter()
	m.messages = 0
	m.msk = nil
	return nil
}

// onTLSStep maps an engine feed outcome to the next FSM action, mirroring
// swan2 on_tls_step: identity verification happens the moment the tunnel
// becomes ready, before the accompanying outbound record is emitted.
func (m *Method) onTLSStep(id uint8, out []byte, step Step) (eap.Result, error) {
	switch step {
	case StepNeedMoreData:
		return eap.Result{Action: eap.ActionSend, Response: encodeEmptyAck(id)}, nil
	case StepOutbound:
		if m.phase == PhaseTLSTunnel && m.tls.Established() {
			if err := m.tls.VerifyServerIdentity(m.serverName); err != nil {
				return eap.Result{}, err
			}
			m.phase = PhaseInnerMethod
			if err := m.inner.Initialize(); err != nil {
				return eap.Result{}, err
			}
		}
		return m.emitFragmentedOrSingle(id, out, 0)
	case StepEstablished:
		if err := m.tls.VerifyServerIdentity(m.serverName); err != nil {
			return eap.Result{}, err
		}
		m.phase = PhaseInnerMethod
		if err := m.inner.Initialize(); err != nil {
			return eap.Result{}, err
		}
		return eap.Result{Action: eap.ActionSend, Response: encodeEmptyAck(id)}, nil
	default:
		return eap.Result{}, errors.New("peap tls engine produced unknown step")
	}
}

// handleInnerMethod feeds one tunneled inner EAP request to the inner
// MSCHAPv2 method and re-encapsulates the response inside the TLS tunnel.
func (m *Method) handleInnerMethod(id uint8, plain []byte) (eap.Result, error) {
	innerReq, err := DecodeInnerRequest(plain, id)
	if err != nil {
		return eap.Result{}, err
	}

	switch eap.Code(innerReq[0]) {
	case eap.CodeSuccess:
		tunneled, err := EncodeInnerResponse(innerReq)
		if err != nil {
			return eap.Result{}, err
		}
		protected, err := m.tls.Protect(tunneled)
		if err != nil {
			return eap.Result{}, err
		}
		m.phase = PhaseAwaitingOuterSuccess
		return m.emitFragmentedOrSingle(id, protected, 0)

	case eap.CodeFailure:
		tunneled, err := EncodeInnerResponse(innerReq)
		if err != nil {
			return eap.Result{}, err
		}
		protected, err := m.tls.Protect(tunneled)
		if err != nil {
			return eap.Result{}, err
		}
		m.phase = PhaseAwaitingOuterFailure
		return m.emitFragmentedOrSingle(id, protected, 0)

	default:
		innerResult, err := m.inner.Handle(innerReq, m.round)
		if err != nil {
			return eap.Result{}, err
		}
		if innerResult.Action == eap.ActionComplete {
			return eap.Result{}, errors.New("unexpected standalone mschapv2 completion without terminal inner packet")
		}
		tunneled, err := EncodeInnerResponse(innerResult.Response)
		if err != nil {
			return eap.Result{}, err
		}
		protected, err := m.tls.Protect(tunneled)
		if err != nil {
			return eap.Result{}, err
		}
		return m.emitFragmentedOrSingle(id, protected, 0)
	}
}

// emitFragmentedOrSingle starts the outbound fragmenter for one TLS
// message. FilledSuccessful single-packet path returns immediately; longer
// payloads leave the fragmenter pending and raise error only on overflow.
func (m *Method) emitFragmentedOrSingle(id uint8, payload []byte, baseFlags uint8) (eap.Result, error) {
	frag, _, err := m.pendingOut.Start(payload, baseFlags|SupportedVersion)
	if err != nil {
		return eap.Result{}, err
	}
	resp, err := m.encodePeapResponse(id, frag, false)
	if err != nil {
		return eap.Result{}, err
	}
	return eap.Result{Action: eap.ActionSend, Response: resp}, nil
}

// emitNextFragment advances one pending outbound fragment. done=true
// clears the fragmenter; emptyPayload always true for the first ACK.
func (m *Method) emitNextFragment(id uint8) (eap.Result, error) {
	frag, _, err := m.pendingOut.Next()
	if err != nil {
		return eap.Result{}, err
	}
	resp, err := m.encodePeapResponse(id, frag, false)
	if err != nil {
		return eap.Result{}, err
	}
	return eap.Result{Action: eap.ActionSend, Response: resp}, nil
}

// encodeIdentityResponse builds the outer identity EAP response.
func (m *Method) encodeIdentityResponse(id uint8) []byte {
	return eap.BuildRequest(eap.CodeResponse, id, eap.TypeIdentity, []byte(m.identity))
}

// encodePeapResponse wraps frag bytes produced by OutboundFragmenter into
// a complete outer EAP Response: [header 4][PEAP type 1][frag bytes].
// frag already contains the flags byte (and L length on first fragments).
func (m *Method) encodePeapResponse(id uint8, frag []byte, _ bool) ([]byte, error) {
	totalLen := 5 + len(frag)
	if totalLen > 0xFFFF {
		return nil, errors.New("peap packet too large")
	}
	out := make([]byte, 0, totalLen)
	out = append(out, byte(eap.CodeResponse), id, byte(totalLen>>8), byte(totalLen))
	out = append(out, byte(eap.TypePEAP))
	out = append(out, frag...)
	return out, nil
}

// encodeEmptyAck builds an empty PEAP ACK response (flags byte 0), which
// both acknowledges an inbound fragment and asks for the server's next
// chunk when no TLS data is produced.
func encodeEmptyAck(id uint8) []byte {
	return eap.BuildRequest(eap.CodeResponse, id, eap.TypePEAP, []byte{0})
}

// collectTLSRecord runs one inbound PEAP fragment through InboundFragmenter.
// complete=false means another fragment is expected.
func (m *Method) collectTLSRecord(peap *peapRequest) ([]byte, bool, error) {
	var lengthIncluded uint32
	if peap.flags&FlagLengthIncluded != 0 {
		lengthIncluded = peap.lengthIncluded
	}
	whole, complete, err := m.pendingIn.Push(peap.flags, lengthIncluded, peap.data)
	if err != nil {
		return nil, false, err
	}
	return whole, complete, nil
}

// peapRequest is the parsed PEAP payload area after the outer EAP header:
//
//	flags byte, optionally uint32 big-endian total length, TLS bytes.
type peapRequest struct {
	identifier     uint8
	flags          uint8
	hasLength      bool
	lengthIncluded uint32
	data           []byte
}

// parsePeapRequest parses and validates the PEAP request payload shape
// (version bits 0, L field bounds). It is separate from eap.Parse because
// the EAP layer knows nothing about PEAP flags.
func parsePeapRequest(identifier uint8, payload []byte) (*peapRequest, error) {
	if len(payload) < 1 {
		return nil, errors.New("peap request missing flags")
	}
	req := &peapRequest{identifier: identifier, flags: payload[0]}
	if req.flags&FlagVersionMask != SupportedVersion {
		return nil, fmt.Errorf("unsupported peap version %d", req.flags&FlagVersionMask)
	}
	rest := payload[1:]
	if req.flags&FlagLengthIncluded != 0 {
		if len(rest) < 4 {
			return nil, errors.New("peap request missing TLS message length")
		}
		req.hasLength = true
		req.lengthIncluded = uint32(rest[0])<<24 | uint32(rest[1])<<16 | uint32(rest[2])<<8 | uint32(rest[3])
		rest = rest[4:]
	}
	req.data = rest
	return req, nil
}

func isAckRequest(req *peapRequest) bool {
	return req != nil &&
		len(req.data) == 0 &&
		!req.hasLength &&
		req.flags&(FlagStart|FlagMoreFragments|FlagLengthIncluded) == 0
}

func errUnknownPhase(phase Phase) error {
	return fmt.Errorf("peap method in unknown phase %d", uint8(phase))
}
