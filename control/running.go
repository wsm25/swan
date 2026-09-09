package control

import (
	"context"
	"errors"
	"fmt"
	"time"

	"swan/events"
	"swan/transport"
	"swan/wire"
	"swan/wire/payload"
)

// Running owns the SA after the handshake: DPD keepalives, inbound
// INFORMATIONAL/DELETE/CREATE_CHILD_SA processing and duplicate-response
// replay.
//
// Its inbox is the same demux-owned channel the handshake used. The
// handshake stops reading that channel before Running starts, so ownership
// moves without a channel switch and no already-queued packet can be lost.

// KeepaliveInterval drives the empty INFORMATIONAL keepalive (20s).
// Outstanding requests have their own RTO retransmission timer.
const KeepaliveInterval = 20 * time.Second

// MaxInboundResponseHistory bounds cached responses replayed for duplicate
// peer INFORMATIONAL/DELETE requests (swan2: 4).
const MaxInboundResponseHistory = 4

// Running is the post-handshake control actor. It shares the *State with
// the handshake only through the ownership handoff in Control.Run; after
// that no other worker mutates it until the session tears down the context
// and observes Running's exit.
type Running struct {
	state  *State
	events *events.Hub
	cfg    *Config

	// childClosed is closed once when the peer deletes the active
	// CHILD_SA; the facade routes it into the ESP pipeline so the data
	// plane stops encrypting with the deleted SPI.
	childClosed chan<- struct{}
}

// Run serves until ctx ends or the peer requests IKE_SA delete. armed gates
// the loop until the facade has emitted HandshakeCompleted/ConfigAssigned/
// Started, so terminal events from this actor can never reorder before the
// documented success sequence. Return value: nil means the peer deleted the
// IKE SA (clean shutdown, no Broken event); ctx.Err() means normal
// teardown; every other error is fatal and already emitted as Broken.
func (r *Running) Run(ctx context.Context, in <-chan *transport.Packet, tx chan<- *transport.Frame, armed <-chan struct{}) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-armed:
	}

	tick := time.NewTicker(KeepaliveInterval)
	defer tick.Stop()

	// Retransmission timer of the outstanding keepalive request. It is
	// armed on send, disarmed when the authenticated response lands, and
	// doubles up to MaxRTO per retry.
	rto := r.cfg.Timeouts.InitialRTO
	retries := uint8(0)
	var rtoTimer *time.Timer
	var rtoC <-chan time.Time

	armRTO := func() {
		if rtoTimer == nil {
			rtoTimer = time.NewTimer(rto)
		} else {
			stopTimer(rtoTimer)
			rtoTimer.Reset(rto)
		}
		rtoC = rtoTimer.C
	}
	disarmRTO := func() {
		if rtoTimer != nil {
			stopTimer(rtoTimer)
		}
		rtoC = nil
	}
	defer disarmRTO()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-rtoC:
			rtoC = nil
			if !r.state.HasExpectedResponse {
				continue
			}
			if retries >= r.cfg.Timeouts.MaxRetries {
				return r.fail(fmt.Errorf("control: keepalive request %d unanswered after %d retries", r.state.ExpectedResponseMessageID, retries))
			}
			if r.state.OutboundRequest == nil {
				return r.fail(fmt.Errorf("control: outstanding keepalive request has no retransmit checkpoint"))
			}
			if err := r.sendFrames(ctx, tx, r.state.OutboundRequest.Packets); err != nil {
				if errors.Is(err, ctx.Err()) {
					return ctx.Err()
				}
				return r.fail(err)
			}
			retries++
			if rto < r.cfg.Timeouts.MaxRTO {
				rto *= 2
				if rto > r.cfg.Timeouts.MaxRTO {
					rto = r.cfg.Timeouts.MaxRTO
				}
			}
			armRTO()
		case <-tick.C:
			// Expired SKF reassembly is normally dropped lazily when the
			// next fragment arrives; clear it on the idle tick as well so
			// a fragment storm cannot pin it for the rest of the session.
			if frag := r.state.InboundFragments; frag != nil && time.Now().After(frag.ExpiresAt) {
				r.state.InboundFragments = nil
			}
			// A request is already outstanding: retransmission belongs to
			// its RTO timer, not the DPD tick (swan2 send_keepalive).
			if r.state.HasExpectedResponse {
				continue
			}
			if err := r.sendKeepalive(ctx, tx); err != nil {
				if errors.Is(err, ctx.Err()) {
					return ctx.Err()
				}
				return r.fail(err)
			}
			retries = 0
			armRTO()
		case pkt, ok := <-in:
			if !ok {
				return r.fail(errors.New("control: running inbound channel closed"))
			}
			if pkt == nil {
				continue
			}
			shutdown, err := r.processPacket(ctx, pkt, tx)
			pkt.Release()
			if err != nil {
				// Malformed/foreign/cleartext datagrams are dropped; DPD and
				// the peer side recover by retrying, same as swan2 running
				// mode.
				continue
			}
			if !r.state.HasExpectedResponse {
				disarmRTO()
				retries = 0
				// Every accepted response restarts the failure-detection
				// ladder at the configured initial RTO instead of drifting
				// permanently to MaxRTO after lossy periods.
				rto = r.cfg.Timeouts.InitialRTO
			}
			if shutdown {
				return nil
			}
		}
	}
}

// processPacket consumes one packet (ownership transferred; caller releases)
// and dispatches a request or response. The returned shutdown flag means
// the peer asked for IKE_SA deletion and Run should terminate cleanly.
func (r *Running) processPacket(ctx context.Context, pkt *transport.Packet, tx chan<- *transport.Frame) (shutdown bool, err error) {
	if pkt.Kind != transport.KindIKE {
		return false, nil
	}

	msg, err := wire.ParseMessage(pkt.Payload)
	if err != nil {
		return false, err
	}

	// After the handshake every control datagram must be protected. A
	// cleartext INFORMATIONAL could otherwise delete the SA without any
	// cryptographic authentication (spoofable inside the injected stream).
	if msg.Encrypted == nil {
		return false, errors.New("control: cleartext packet rejected in running state")
	}

	if msg.Header.Flags&wire.FlagResponse != 0 {
		return r.processResponse(pkt, msg)
	}

	// Peer request. swan2 parse_inbound_control_request decrypts/parses the
	// protected request before replay/validation: incomplete SKF requests
	// are dropped while their reassembly is retained, and complete when the
	// final fragment arrives.
	inner, complete, err := openRunningPayloads(r.state, pkt.Payload, msg)
	if err != nil {
		return false, err
	}
	if !complete {
		return false, errors.New("control: inbound informational request requires more fragments")
	}
	if msg.Header.MessageID == 0 {
		return false, errors.New("control: inbound IKE informational request missing message-id")
	}
	if frames, ok := r.replayCachedFrames(msg.Header.MessageID); ok {
		return false, r.sendFrames(ctx, tx, frames)
	}
	if len(r.state.InboundHistory) > 0 {
		last := r.state.InboundHistory[len(r.state.InboundHistory)-1].MessageID
		if msg.Header.MessageID <= last {
			return false, fmt.Errorf("control: stale inbound running request %d after %d", msg.Header.MessageID, last)
		}
	}

	switch msg.Header.ExchangeType {
	case wire.ExchangeInformational:
		return r.processInformational(ctx, tx, msg, inner)
	case wire.ExchangeCreateChild:
		// Rekey is out of scope for the MVP: refuse with NO_ADDITIONAL_SAS
		// instead of silently dropping the request (which would make the
		// peer tear the SA down after its retries).
		body := payload.AppendNotify(nil, payload.Notify{Type: wire.NotifyNoAdditionalSAs})
		frames, err := buildProtectedStateAs(nil, r.state, wire.ExchangeCreateChild, msg.Header.MessageID, wire.PayloadTypeNotify, cepSinglePayload(body), wire.FlagResponse)
		if err != nil {
			return false, err
		}
		if err := r.sendFrames(ctx, tx, frames); err != nil {
			return false, err
		}
		r.rememberResponse(msg.Header.MessageID, frames)
		return false, nil
	default:
		// swan2 handle_running_control_packet ignores non-INFORMATIONAL
		// exchanges; CREATE_CHILD_SA above is the one MVP exception.
		return false, nil
	}
}

// processResponse handles the protected response to our outstanding
// keepalive (message-id match, authenticated before the marker clears).
func (r *Running) processResponse(pkt *transport.Packet, msg *wire.Message) (bool, error) {
	// Strict response envelope + message-id match (swan2
	// parse_response_protected / validate_response_header).
	if validateResponseEnvelope(msg.Header) != nil {
		return false, nil
	}
	if msg.Header.InitiatorSPI.Uint64() != r.state.InitiatorSPI {
		return false, nil
	}
	if r.state.ResponderSPI != 0 && msg.Header.ResponderSPI.Uint64() != r.state.ResponderSPI {
		return false, nil
	}
	if !r.state.HasExpectedResponse || msg.Header.MessageID != r.state.ExpectedResponseMessageID {
		return false, nil
	}
	// The response is authenticated/decrypted before the outstanding
	// request marker is cleared. Dropping it on failure keeps the
	// retransmit/keepalive state intact.
	_, complete, err := openRunningPayloads(r.state, pkt.Payload, msg)
	if err != nil {
		return false, err
	}
	if !complete {
		return false, nil
	}
	r.state.HasExpectedResponse = false
	r.state.HasLastCompletedResponse = true
	r.state.LastCompletedResponseMessageID = msg.Header.MessageID
	r.state.OutboundRequest = nil
	r.state.InboundFragments = nil
	return false, nil
}

// processInformational applies the swan2
// process_informational_request_payloads rules to an already-decrypted
// payload list and sends the (empty or DELETE) answer.
func (r *Running) processInformational(ctx context.Context, tx chan<- *transport.Frame, msg *wire.Message, inner []wire.Payload) (bool, error) {
	shutdown, err := r.handleInformationalForPayloads(inner)
	if err != nil {
		return false, err
	}

	frames, err := buildProtectedStateAs(nil, r.state, wire.ExchangeInformational, msg.Header.MessageID, wire.PayloadTypeNone, nil, wire.FlagResponse)
	if err != nil {
		return false, err
	}
	if err := r.sendFrames(ctx, tx, frames); err != nil {
		return false, err
	}
	r.rememberResponse(msg.Header.MessageID, frames)

	if shutdown {
		// Clean peer-initiated IKE delete: Run returns nil, the facade
		// tears the session down. The event stream (Stopped, closed Done /
		// Tunnel) is the facade's job, so exactly one ordered shutdown
		// sequence is produced.
		r.state.ClearSession()
		r.state.Phase = PhaseStopped
	}
	return shutdown, nil
}

// openRunningPayloads returns cleartext inner payloads for inbound running
// packets, plus whether a protected message was complete. Cleartext
// INFORMATIONALs are rejected by processPacket before this helper is used;
// protected packets are decrypted with the raw message (exact AAD bytes).
// Incomplete SKF reassembly returns (nil, false, nil) so the caller can
// keep the outstanding request marker intact exactly like swan2
// parse_response_protected / parse_inbound_control on the NeedMore path.
func openRunningPayloads(state *State, raw []byte, msg *wire.Message) ([]wire.Payload, bool, error) {
	if msg.Encrypted != nil {
		plds, complete, err := openProtectedRawState(nil, state, raw)
		return plds, complete, err
	}
	return msg.Payloads, true, nil
}

// fail returns the original error without emitting: the facade (Session)
// is the single Broken-event owner on the running path and wraps the same
// error; a handful of duplicate Broken events would otherwise leak to
// subscribers.
func (r *Running) fail(err error) error {
	return err
}

// sendKeepalive issues the empty INFORMATIONAL request when no request is
// outstanding.
func (r *Running) sendKeepalive(ctx context.Context, tx chan<- *transport.Frame) error {
	if r.state.HasExpectedResponse {
		return nil
	}
	msgID := r.state.NextRequestMessageID
	r.state.NextRequestMessageID++
	r.state.HasExpectedResponse = true
	r.state.ExpectedResponseMessageID = msgID

	frames, err := buildProtectedState(nil, r.state, wire.ExchangeInformational, msgID, wire.PayloadTypeNone, nil)
	if err != nil {
		return err
	}
	r.state.OutboundRequest = &Checkpoint{MessageID: msgID, Packets: frames}
	return r.sendFrames(ctx, tx, frames)
}

// sendFrames pushes a prepared frame list into the transport queue without
// changing message-id bookkeeping. ctx cancellation unblocks a saturated
// queue so the Running actor can never be wedged by a dead Tx worker.
func (r *Running) sendFrames(ctx context.Context, tx chan<- *transport.Frame, frames []*transport.Frame) error {
	for _, frame := range frames {
		if frame == nil {
			continue
		}
		select {
		case tx <- frame:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// handleInformational parses and dispatches the payload set: empty payloads
// are accepted; DELETE is validated (IKE delete without SPIs, ESP delete
// with the active SPI); everything else is a protocol error.
func (r *Running) handleInformational(m *wire.Message) (peerShutdown bool, err error) {
	return r.handleInformationalForPayloads(m.Payloads)
}

// handleInformationalForPayloads applies the swan2
// process_informational_request_payloads rules to an already-decrypted
// payload list.
func (r *Running) handleInformationalForPayloads(plds []wire.Payload) (peerShutdown bool, err error) {
	if len(plds) == 0 {
		return false, nil
	}
	var deletePayload *payload.Delete
	other := false
	for i, p := range plds {
		if p.Type != wire.PayloadTypeDelete {
			other = true
			break
		}
		d, derr := payload.ParseDelete(p.Body)
		if derr != nil {
			return false, derr
		}
		if deletePayload != nil {
			return false, errors.New("control: multiple delete payloads in one running request")
		}
		deletePayload = &d
		_ = i
	}
	if other {
		return false, errors.New("control: unexpected non-delete payload in running request")
	}
	if deletePayload == nil {
		return false, errors.New("control: running request carries no delete payload")
	}

	switch deletePayload.ProtocolID {
	case wire.DeleteProtocolIKE:
		if len(deletePayload.SPIs) != 0 {
			return false, errors.New("control: ike delete must not carry spis")
		}
		return true, nil
	case wire.DeleteProtocolESP:
		if len(deletePayload.SPIs) != 1 {
			return false, errors.New("control: esp delete must carry exactly one spi")
		}
		if r.state.ActiveChild == nil {
			return false, errors.New("control: received child delete without an active child sa")
		}
		if deletePayload.SPIs[0] != r.state.ActiveChild.OutboundSPI {
			return false, errors.New("control: unexpected child delete spi")
		}
		r.state.ActiveChild = nil
		if r.childClosed != nil {
			close(r.childClosed)
			r.childClosed = nil
		}
		return false, nil
	default:
		return false, fmt.Errorf("control: unsupported delete protocol %d", deletePayload.ProtocolID)
	}
}

// rememberResponse trims the inbound history to MaxInboundResponseHistory.
func (r *Running) rememberResponse(msgID uint32, frames []*transport.Frame) {
	r.state.InboundHistory = append(r.state.InboundHistory, CachedResponse{
		MessageID:       msgID,
		ResponsePackets: frames,
	})
	if len(r.state.InboundHistory) > MaxInboundResponseHistory {
		r.state.InboundHistory = r.state.InboundHistory[len(r.state.InboundHistory)-MaxInboundResponseHistory:]
	}
}

// replayCachedFrames looks up an answered inbound request and returns the
// stored response frames.
func (r *Running) replayCachedFrames(msgID uint32) ([]*transport.Frame, bool) {
	for i := len(r.state.InboundHistory) - 1; i >= 0; i-- {
		entry := &r.state.InboundHistory[i]
		if entry.MessageID == msgID {
			return entry.ResponsePackets, true
		}
	}
	return nil, false
}

// replayCached looks up a previously answered inbound request and returns
// the stored response bytes (first frame payload).
func (r *Running) replayCached(msgID uint32) ([]byte, bool) {
	frames, ok := r.replayCachedFrames(msgID)
	if !ok || len(frames) == 0 || frames[0] == nil {
		return nil, ok
	}
	return frames[0].Payload, true
}

// stopTimer stops a timer and drains its channel when needed. Safe on nil.
func stopTimer(t *time.Timer) {
	if t == nil {
		return
	}
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}
