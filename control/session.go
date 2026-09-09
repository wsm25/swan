package control

import (
	"context"
	"fmt"
	"time"

	"swan/events"
	"swan/transport"
	"swan/wire"
	"swan/wire/payload"
	"swan/xcrypto"
)

// Control is the top of the control-plane actor tree. It is stateless apart
// from configuration and the owned State; all IO flows through the
// Run/Close method parameters (Close is declared by the close stage file).
type Control struct {
	cfg    *Config
	state  *State
	events *events.Hub

	// handshake is nil for a freshly built Control and pinned once the
	// public Session or Handshake.Run starts the linear actor.
	handshake *Handshake
}

// Established is the handoff bundle delivered from Handshake to the running
// data plane: everything the esp pipeline and the public Tunnel need,
// without further interpretation of wire bytes.
type Established struct {
	Assigned  AssignedConfig
	Child     ChildSA
	State     *State
	IKEKeys   *xcrypto.IKEKeys
	ChildKeys *xcrypto.ChildKeys
	Selection *xcrypto.Selection

	// Arm starts the Running actor's serving loop. The public Session calls
	// it AFTER emitting HandshakeCompleted/ConfigAssigned/Started, so
	// Running terminal events can never reorder before the success
	// sequence.
	Arm func()
	// Terminated receives the Running actor's exit value exactly once:
	// nil = peer-initiated IKE delete (clean shutdown), ctx.Err() =
	// session-driven teardown, anything else = fatal with a Broken event.
	Terminated <-chan error
	// ChildClosed is closed once when the peer deletes the active
	// CHILD_SA; wire it into the ESP pipeline to stop the data plane.
	ChildClosed <-chan struct{}
}

// New validates the configuration (after filling default timeouts/limits)
// and allocates the state.
func New(cfg *Config, hub *events.Hub) (*Control, error) {
	if cfg == nil {
		return nil, fmt.Errorf("control: nil config")
	}
	normalizeConfig(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Control{cfg: cfg, state: NewState(), events: hub}, nil
}

// normalizeConfig fills zero-valued tuning fields with the swan2 defaults
// before validation runs.
func normalizeConfig(cfg *Config) {
	defaults := DefaultTimeouts()
	if cfg.Timeouts.InitialRTO <= 0 {
		cfg.Timeouts.InitialRTO = defaults.InitialRTO
	}
	if cfg.Timeouts.MaxRTO <= 0 {
		cfg.Timeouts.MaxRTO = defaults.MaxRTO
	}
	if cfg.Timeouts.MaxRetries == 0 {
		cfg.Timeouts.MaxRetries = defaults.MaxRetries
	}
	if cfg.Timeouts.SkfReassemblyTimeout <= 0 {
		cfg.Timeouts.SkfReassemblyTimeout = defaults.SkfReassemblyTimeout
	}
	if cfg.FragmentPlaintextLimit <= 0 {
		cfg.FragmentPlaintextLimit = FragmentPlaintextLimit
	}
}

// Run executes the handshake actor, then — on success — starts the Running
// actor and reports the Established result exactly once. The demux goroutine
// routes packets from `in` to one fixed control mailbox; the handshake and
// running actors read that mailbox in turn, so ownership flips only at the
// established boundary without a channel-switch race. The `in` channel is
// owned by the caller and is never closed here.
func (c *Control) Run(ctx context.Context, in <-chan *transport.Packet, tx chan<- *transport.Frame) (*Established, error) {
	if c == nil {
		return nil, fmt.Errorf("control: nil Control")
	}
	if c.handshake == nil {
		c.handshake = &Handshake{cfg: c.cfg, state: c.state, events: c.events}
	}
	return c.runHandshake(ctx, in, tx, c.handshake)
}

// startDemux runs the router goroutine: it forwards only IKE packets and
// releases non-IKE packets (they never reach the control plane). It exits
// when ctx is canceled or the caller's `in` channel closes. The target
// mailbox is fixed for the whole session; no packet can be stranded by a
// mailbox switch because there is no switch.
func startDemux(ctx context.Context, in <-chan *transport.Packet, ch chan<- *transport.Packet) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case pkt, ok := <-in:
				if !ok {
					return
				}
				if pkt == nil {
					continue
				}
				if pkt.Kind != transport.KindIKE {
					pkt.Release()
					continue
				}
				select {
				case ch <- pkt:
				case <-ctx.Done():
					pkt.Release()
					return
				}
			}
		}
	}()
}

// runHandshake owns the linear initiator flow. The demux always feeds the
// mailbox owned by the current phase, so the handshake never reads the raw
// `in` channel and the running-actor handoff stays race-free.
func (c *Control) runHandshake(ctx context.Context, in <-chan *transport.Packet, tx chan<- *transport.Frame, h *Handshake) (*Established, error) {
	demuxCtx, stopDemux := context.WithCancel(ctx)
	defer func() {
		// Keep the router alive on success for the running actor. On any
		// failure the router must be stopped immediately so a full handshake
		// mailbox cannot block the transport worker.
		if h.state.Phase != PhaseRunning {
			stopDemux()
		}
	}()

	st := h.state
	if st == nil {
		st = NewState()
		h.state = st
	}
	st.Reset()
	st.Phase = PhaseStarting
	st.NextRequestMessageID = 0
	st.ExpectedResponseMessageID = 0
	st.HasExpectedResponse = true

	controlMailbox := make(chan *transport.Packet, 8)
	startDemux(demuxCtx, in, controlMailbox)

	// ---- IKE_SA_INIT -------------------------------------------------
	h.emit(events.Event{Kind: events.EventStageChanged, Stage: events.StageIKEInit})
	var forcedDHGroup uint16
	established := false
	for attempt := 0; attempt < MaxSAInitAttempts; attempt++ {
		st.Phase = PhaseSAInitSent
		frames, err := h.buildSAInitRequest(forcedDHGroup)
		if err != nil {
			return nil, h.fail(tx, err)
		}
		if err := h.sendRequest(demuxCtx, tx, frames); err != nil {
			return nil, h.fail(tx, err)
		}

		msg, err := h.waitSAInitResponse(demuxCtx, controlMailbox, tx)
		if err != nil {
			return nil, h.fail(tx, err)
		}

		// INVALID_KE_PAYLOAD retries carry the requested group as notify
		// data; extract it here because the stage helper reports an enum.
		requestedGroup, _ := invalidKEDHGroup(msg)

		outcome, err := h.applySAInitResponse(msg)
		if err != nil {
			return nil, h.fail(tx, err)
		}
		switch outcome {
		case SAInitEstablished:
			established = true
		case SAInitRetryCookie:
			if attempt+1 >= MaxSAInitAttempts {
				return nil, h.fail(tx, fmt.Errorf("control: peer requested too many COOKIE retries"))
			}
		case SAInitRetryDHGroup:
			if requestedGroup == 0 {
				return nil, h.fail(tx, fmt.Errorf("control: INVALID_KE_PAYLOAD retry without a DH group"))
			}
			if attempt+1 >= MaxSAInitAttempts {
				return nil, h.fail(tx, fmt.Errorf("control: peer requested too many INVALID_KE_PAYLOAD retries"))
			}
			forcedDHGroup = requestedGroup
		}
		if established {
			break
		}
	}
	if !established {
		return nil, h.fail(tx, fmt.Errorf("control: ike_sa_init did not complete after retry handling"))
	}
	if err := h.deriveIKEKeys(); err != nil {
		return nil, h.fail(tx, err)
	}
	h.emitNegotiatedIKE()
	// IKE_SA_INIT used message-id 0; the first IKE_AUTH request is 1.
	st.NextRequestMessageID = 1
	st.HasExpectedResponse = false
	st.ExpectedResponseMessageID = 0
	st.Phase = PhaseSAInitEstablished

	// ---- IKE_AUTH bootstrap + EAP loop -------------------------------
	st.Phase = PhaseAuthBootstrap
	h.emit(events.Event{Kind: events.EventStageChanged, Stage: events.StageIKEAuth})
	bootstrapID := h.beginRequest()
	frames, err := h.buildBootstrapAuthRequest(bootstrapID)
	if err != nil {
		return nil, h.fail(tx, err)
	}
	if err := h.sendRequest(demuxCtx, tx, frames); err != nil {
		return nil, h.fail(tx, err)
	}

	// The EAP peer bridge owns every IKE_AUTH response of this phase,
	// including the bootstrap response (its firstResponse flag runs the
	// one-time AUTH-vs-EAP policy). Do not pre-consume the response here.
	h.emit(events.Event{Kind: events.EventStageChanged, Stage: events.StageEAP})
	if err := h.runEAP(demuxCtx, tx, controlMailbox); err != nil {
		return nil, h.fail(tx, err)
	}

	// ---- final IKE_AUTH / CHILD_SA ------------------------------------
	st.Phase = PhaseChildInstalling
	h.emit(events.Event{Kind: events.EventStageChanged, Stage: events.StageChildSA})
	finalID := h.beginRequest()
	frames, err = h.buildFinalAuthRequest(finalID)
	if err != nil {
		return nil, h.fail(tx, err)
	}
	if err := h.sendRequest(demuxCtx, tx, frames); err != nil {
		return nil, h.fail(tx, err)
	}
	finalMsg, _, err := c.recvProtected(demuxCtx, h, controlMailbox, tx, finalID, wire.ExchangeIkeAuth, "final_auth")
	if err != nil {
		return nil, h.fail(tx, err)
	}
	if _, err := h.processFinalAuth(finalMsg); err != nil {
		// swan2 emits the negotiated ESP algorithm event as soon as the
		// CHILD_SA proposal has been decoded, before CP/TS validation. If
		// processFinalAuth got that far and then failed on CP/traffic
		// selectors, the state already carries the selection; preserve the
		// same failure-path event stream.
		if h.state.SelectedESP != nil {
			h.emitNegotiatedESP()
		}
		return nil, h.fail(tx, err)
	}
	h.emitNegotiatedESP()
	childKeys, err := h.deriveChildKeys()
	if err != nil {
		return nil, h.fail(tx, err)
	}

	// ---- handoff to Running -------------------------------------------
	if st.Assigned == nil {
		return nil, h.fail(tx, fmt.Errorf("control: handshake completed without assigned configuration"))
	}
	if st.SelectedESP == nil {
		return nil, h.fail(tx, fmt.Errorf("control: handshake completed without ESP selection"))
	}
	if st.ActiveChild == nil {
		return nil, h.fail(tx, fmt.Errorf("control: handshake completed without an active CHILD_SA"))
	}
	if len(st.Auth.LocalEAPMSK) == 0 {
		return nil, h.fail(tx, fmt.Errorf("control: handshake completed without EAP MSK"))
	}

	st.Phase = PhaseRunning
	st.HasExpectedResponse = false
	st.ExpectedResponseMessageID = 0
	childClosed := make(chan struct{})
	running := &Running{state: st, events: h.events, cfg: c.cfg, childClosed: childClosed}
	armed := make(chan struct{})
	terminated := make(chan error, 1)
	go func() {
		err := running.Run(demuxCtx, controlMailbox, tx, armed)
		stopDemux()
		terminated <- err
	}()
	h.emit(events.Event{Kind: events.EventStageChanged, Stage: events.StageRunning})

	return &Established{
		Assigned:    *st.Assigned,
		Child:       *st.ActiveChild,
		State:       st,
		IKEKeys:     st.IKEKeys,
		ChildKeys:   childKeys,
		Selection:   st.SelectedESP,
		Arm:         func() { close(armed) },
		Terminated:  terminated,
		ChildClosed: childClosed,
	}, nil
}

// recvProtected receives one complete protected response of an exchange:
// it loops while SKF reassembly reports "more fragments needed" and returns
// the parsed message whose Payloads carry the decrypted inner chain.
func (c *Control) recvProtected(ctx context.Context, h *Handshake, in <-chan *transport.Packet, tx chan<- *transport.Frame, msgID uint32, exchange wire.ExchangeType, step string) (*wire.Message, []wire.Payload, error) {
	return h.recvProtectedPayloads(ctx, in, tx, exchange, msgID, step)
}

// recvProtectedPayloads is the shared protected-response receiver. It keeps
// the raw datagram bytes around until openProtectedRawState has completed
// decryption (or accepted another SKF fragment), so SK and SKF responses use
// exactly the same byte-exact AAD path as swan2 parse_response_protected.
func (h *Handshake) recvProtectedPayloads(ctx context.Context, in <-chan *transport.Packet, tx chan<- *transport.Frame, exchange wire.ExchangeType, msgID uint32, step string) (*wire.Message, []wire.Payload, error) {
	for {
		raw, err := h.waitResponseRaw(ctx, in, tx, step, exchange, msgID)
		if err != nil {
			return nil, nil, err
		}
		payloads, complete, err := openProtectedRawState(h.cfg, h.state, raw)
		if err != nil {
			return nil, nil, err
		}
		if exchange == wire.ExchangeIkeAuth {
			h.state.FirstIKEAuthSeen = true
		}
		if !complete {
			// Incomplete SKF fragment: keep waiting for siblings of the same
			// message-id. The protected helper retained the reassembly state.
			continue
		}
		h.state.LastCompletedResponseMessageID = msgID
		h.state.HasLastCompletedResponse = true
		h.state.HasExpectedResponse = false
		h.state.ExpectedResponseMessageID = 0
		h.state.OutboundRequest = nil
		h.state.InboundFragments = nil

		msg, err := wire.ParseMessage(raw)
		if err != nil {
			return nil, nil, err
		}
		return withPlaintextPayloads(msg, payloads), payloads, nil
	}
}

// waitResponseRaw is the raw-bytes counterpart of exchange.waitResponse. It
// returns the complete datagram for the expected response and leaves
// message-id bookkeeping to the caller, because incomplete SKF fragments
// must not clear the outbound retransmission checkpoint yet.
func (h *Handshake) waitResponseRaw(ctx context.Context, in <-chan *transport.Packet, tx chan<- *transport.Frame, step string, exchange wire.ExchangeType, msgID uint32) ([]byte, error) {
	rto := h.cfg.Timeouts.InitialRTO
	retries := uint8(0)
	timer := time.NewTimer(rto)
	defer timer.Stop()

	for {
		select {
		case pkt, ok := <-in:
			if !ok {
				return nil, fmt.Errorf("control: inbound channel closed while waiting for %s", step)
			}
			if pkt == nil {
				continue
			}
			if pkt.Kind != transport.KindIKE {
				pkt.Release()
				timer.Reset(rto)
				continue
			}
			raw := append([]byte(nil), pkt.Payload...)
			pkt.Release()

			msg, err := wire.ParseMessage(raw)
			if err != nil {
				timer.Reset(rto)
				continue
			}
			dispose, derr := h.classifyResponse(msg.Header, msgID)
			if derr != nil {
				return nil, derr
			}
			if dispose != DispositionExpected {
				timer.Reset(rto)
				continue
			}
			if err := h.validateResponseHeader(msg.Header, exchange, msgID); err != nil {
				return nil, err
			}
			return raw, nil

		case <-timer.C:
			if err := h.retransmit(ctx, tx, &rto, &retries, step); err != nil {
				return nil, err
			}
			timer.Reset(rto)

		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// withPlaintextPayloads presents a parsed (maybe SKF-reassembled) message
// to the stage helpers, which only consume msg.Header and msg.Payloads.
func withPlaintextPayloads(m *wire.Message, payloads []wire.Payload) *wire.Message {
	inner := *m
	inner.Payloads = payloads
	inner.Encrypted = nil
	return &inner
}

// waitSAInitResponse is the SA_INIT-specific receive loop. It exists apart
// from exchange.waitResponse for one reason: the full raw SA_INIT response
// must be check-pointed into State.SAInitResponse before the pooled
// transport buffer is released, because responder AUTH signing hashes those
// exact bytes later.
func (h *Handshake) waitSAInitResponse(ctx context.Context, in <-chan *transport.Packet, tx chan<- *transport.Frame) (*wire.Message, error) {
	rto := h.cfg.Timeouts.InitialRTO
	retries := uint8(0)
	timer := time.NewTimer(rto)
	defer timer.Stop()

	for {
		select {
		case pkt, ok := <-in:
			if !ok {
				return nil, fmt.Errorf("control: inbound channel closed while waiting for ike_sa_init")
			}
			if pkt == nil {
				continue
			}
			if pkt.Kind != transport.KindIKE {
				pkt.Release()
				timer.Reset(rto)
				continue
			}
			raw := append([]byte(nil), pkt.Payload...)
			msg, err := wire.ParseMessage(raw)
			if err != nil {
				pkt.Release()
				timer.Reset(rto)
				continue
			}
			dispose, derr := h.classifyResponse(msg.Header, 0)
			if derr != nil {
				pkt.Release()
				return nil, derr
			}
			if dispose != DispositionExpected {
				pkt.Release()
				timer.Reset(rto)
				continue
			}
			if err := h.validateResponseHeader(msg.Header, wire.ExchangeIkeSAInit, 0); err != nil {
				pkt.Release()
				return nil, err
			}
			// Checkpoint before release: the raw bytes must survive the
			// pooled-buffer return.
			h.recordResponseCheckpoint(pkt)
			pkt.Release()

			h.state.LastCompletedResponseMessageID = 0
			h.state.HasLastCompletedResponse = true
			h.state.OutboundRequest = nil
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return msg, nil

		case <-timer.C:
			if err := h.retransmit(ctx, tx, &rto, &retries, "ike_sa_init"); err != nil {
				return nil, err
			}
			timer.Reset(rto)

		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// fail implements the unified failure path: best-effort protected
// AUTHENTICATION_FAILED notify (when keys are available), deterministic
// Broken -> Stopped events, state teardown, then the original error.
func (h *Handshake) fail(tx chan<- *transport.Frame, err error) error {
	if h == nil || err == nil {
		return err
	}
	if h.state != nil &&
		h.state.ResponderSPI != 0 &&
		h.state.IKEKeys != nil &&
		!h.state.SuppressAuthFailedNotify {
		if frames, buildErr := h.buildAuthFailedNotify(); buildErr == nil {
			for _, frame := range frames {
				select {
				case tx <- frame:
				default:
					// best-effort: never let a failing handshake block on a
					// full writer queue.
				}
			}
		}
	}
	if h.state != nil {
		h.state.FailureReason = err.Error()
		h.state.ClearSession()
		// swan2 finish_failure marks the routine failed and then
		// cleanup_session sets the SA state to Stopped before emitting
		// Broken/Stopped. Keep the same terminal state so later Close calls
		// report AlreadyClosed instead of trying to DELETE a dead SA.
		h.state.Phase = PhaseStopped
	}
	h.emit(events.Event{Kind: events.EventBroken, Reason: err.Error()})
	h.emit(events.Event{Kind: events.EventStopped})
	return err
}

// buildAuthFailedNotify wraps a single protected AUTHENTICATION_FAILED
// NOTIFY using the current IKE keys. The exchange type follows the phase
// exactly like swan2's send_authentication_failed_notify.
func (h *Handshake) buildAuthFailedNotify() ([]*transport.Frame, error) {
	notifyBody := payload.AppendNotify(nil, payload.Notify{
		Type: wire.NotifyAuthenticationFailed,
	})
	exchange := wire.ExchangeInformational
	if h.state.Phase == PhaseAuthBootstrap || h.state.Phase == PhaseAuthEAPInProgress || h.state.Phase == PhaseChildInstalling {
		exchange = wire.ExchangeIkeAuth
	}
	msgID := h.state.NextRequestMessageID
	h.state.NextRequestMessageID++
	return h.buildProtected(exchange, msgID, wire.PayloadTypeNotify, cepSinglePayload(notifyBody))
}

// invalidKEDHGroup extracts the requested group from an INVALID_KE_PAYLOAD
// notify, if present.
func invalidKEDHGroup(m *wire.Message) (uint16, bool) {
	if m == nil {
		return 0, false
	}
	for i := range m.Payloads {
		p := &m.Payloads[i]
		if p.Type != wire.PayloadTypeNotify {
			continue
		}
		n, err := payload.ParseNotify(p.Body)
		if err != nil || n.Type != wire.NotifyInvalidKePayload || len(n.Data) != 2 {
			continue
		}
		return uint16(n.Data[0])<<8 | uint16(n.Data[1]), true
	}
	return 0, false
}

// emitNegotiatedIKE posts the negotiated algorithm event for the IKE SA.
func (h *Handshake) emitNegotiatedIKE() {
	sel := h.state.SelectedIKE
	if sel == nil || sel.Encryption == nil {
		return
	}
	ev := events.Event{Kind: events.EventNegotiatedAlgorithm, Alg: events.NegotiatedAlgorithm{
		Protocol:   "ike",
		Encryption: sel.Encryption.Name,
		PRF:        prfName(sel.PRF),
		DH:         dhName(sel.DH),
	}}
	if !sel.Encryption.AEAD {
		ev.Alg.Integrity = integrityName(sel.Integrity)
	}
	h.emit(ev)
}

// emitNegotiatedESP posts the negotiated algorithm event for the CHILD_SA.
func (h *Handshake) emitNegotiatedESP() {
	sel := h.state.SelectedESP
	if sel == nil || sel.Encryption == nil {
		return
	}
	ev := events.Event{Kind: events.EventNegotiatedAlgorithm, Alg: events.NegotiatedAlgorithm{
		Protocol:   "esp",
		Encryption: sel.Encryption.Name,
	}}
	if !sel.Encryption.AEAD {
		ev.Alg.Integrity = integrityName(sel.Integrity)
	}
	h.emit(ev)
}

func prfName(p *xcrypto.PRF) string {
	if p == nil {
		return ""
	}
	switch p.TransformID {
	case xcrypto.TransformPRFHMACSHA1:
		return "prfsha1"
	case xcrypto.TransformPRFHMACSHA256:
		return "prfsha2_256"
	case xcrypto.TransformPRFHMACSHA512:
		return "prfsha2_512"
	default:
		return fmt.Sprintf("#%d", p.TransformID)
	}
}

func integrityName(i *xcrypto.Integrity) string {
	if i == nil {
		return ""
	}
	switch i.TransformID {
	case xcrypto.TransformIntegrityHMACSHA196:
		return "sha1_96"
	case xcrypto.TransformIntegrityHMACSHA2256128:
		return "sha2_256_128"
	case xcrypto.TransformIntegrityHMACSHA2512256:
		return "sha2_512_256"
	default:
		return fmt.Sprintf("#%d", i.TransformID)
	}
}

func dhName(d *xcrypto.DH) string {
	if d == nil {
		return ""
	}
	if d.Name != "" {
		return d.Name
	}
	return fmt.Sprintf("#%d", d.TransformID)
}
