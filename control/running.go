package control

import (
	"context"
	"fmt"
	"time"

	"swan/events"
	"swan/transport"
	"swan/wire"
	"swan/wire/payload"
)

// Running owns the SA after the handshake: DPD keepalives, inbound
// INFORMATIONAL/DELETE processing and duplicate-response replay.
//
// Its inbox is the same demux-owned channel the handshake used. The
// handshake stops reading that channel before Running starts, so ownership
// moves without a channel switch and no already-queued packet can be lost.

// KeepaliveInterval drives the empty INFORMATIONAL keepalive (20s). While a
// request is outstanding the keepalive is skipped (swan2 resends the
// outstanding checkpoint instead).
const KeepaliveInterval = 20 * time.Second

// MaxInboundResponseHistory bounds cached responses replayed for duplicate
// peer INFORMATIONAL/DELETE requests (swan2: 4).
const MaxInboundResponseHistory = 4

// Running is the post-handshake control actor. It shares the *State with
// the handshake only through the ownership handoff in Control.Run; after
// that no other worker mutates it.
type Running struct {
	state  *State
	events *events.Hub
}

// Run serves until ctx ends or the peer requests IKE_SA delete.
// Inbound requests beyond delete are answered with the empty informational
// response; responses to our keepalives match by message-id.
func (r *Running) Run(ctx context.Context, in <-chan *transport.Packet, tx chan<- *transport.Frame) error {
	tick := time.NewTicker(KeepaliveInterval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			// swan2 send_keepalive: when a request is already outstanding the
			// keepalive is SKIPPED entirely -- retransmission of the outstanding
			// checkpoint belongs to its own retransmit timer, not the DPD tick.
			if r.state.HasExpectedResponse {
				continue
			}
			if err := r.sendKeepalive(ctx, tx); err != nil {
				return r.fail(err)
			}
		case pkt, ok := <-in:
			if !ok {
				return r.fail(fmt.Errorf("control: running inbound channel closed"))
			}
			if pkt == nil {
				continue
			}
			shutdown, err := r.processPacket(pkt, tx)
			if err != nil {
				// Malformed/foreign datagrams are dropped; DPD and the peer
				// side can recover by retrying, same as swan2 running mode.
				continue
			}
			if shutdown {
				return nil
			}
		}
	}
}

// processPacket releases the packet exactly once and dispatches a request or
// response. The returned shutdown flag means the peer asked for IKE_SA
// deletion and Run should terminate cleanly.
func (r *Running) processPacket(pkt *transport.Packet, tx chan<- *transport.Frame) (shutdown bool, err error) {
	defer pkt.Release()
	if pkt.Kind != transport.KindIKE {
		return false, nil
	}

	msg, err := wire.ParseMessage(pkt.Payload)
	if err != nil {
		return false, err
	}

	// swan2 handle_running_control_packet rejects everything but
	// INFORMATIONAL while the SA is in the running state.
	if msg.Header.ExchangeType != wire.ExchangeInformational {
		return false, nil
	}

	if msg.Header.Flags&wire.FlagResponse != 0 {
		// strict response envelope + message-id match (swan2
		// parse_response_protected/validate_response_header).
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
		// swan2 handle_inbound_control_response runs parse_response_protected
		// here: the response is authenticated/decrypted before the outstand-
		// ing request marker is cleared. Dropping it on failure keeps the
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

	// Peer request. swan2 parse_inbound_control_request decrypts/parses the
	// protected request before replay/validation: incomplete SKF requests are
	// dropped while their reassembly is retained, and complete when the final
	// fragment arrives. Do the same here and reject message-id 0 only for
	// complete requests.
	inner, complete, err := openRunningPayloads(r.state, pkt.Payload, msg)
	if err != nil {
		return false, err
	}
	if !complete {
		return false, fmt.Errorf("control: inbound informational request requires more fragments")
	}
	if msg.Header.MessageID == 0 {
		return false, fmt.Errorf("control: inbound IKE informational request missing message-id")
	}
	if frames, ok := r.replayCachedFrames(msg.Header.MessageID); ok {
		return false, r.sendFrames(tx, frames)
	}
	if len(r.state.InboundHistory) > 0 {
		last := r.state.InboundHistory[len(r.state.InboundHistory)-1].MessageID
		if msg.Header.MessageID <= last {
			return false, fmt.Errorf("control: stale inbound running request %d after %d", msg.Header.MessageID, last)
		}
	}

	wasDelete := len(inner) > 0 && inner[0].Type == wire.PayloadTypeDelete
	shutdown, err = r.handleInformationalForPayloads(inner)
	if err != nil {
		return false, err
	}

	frames, err := buildProtectedState(nil, r.state, wire.ExchangeInformational, msg.Header.MessageID, wire.PayloadTypeNone, nil)
	if err != nil {
		return false, err
	}
	if err := r.sendFrames(tx, frames); err != nil {
		return false, err
	}
	r.rememberResponse(msg.Header.MessageID, frames)

	if shutdown {
		r.state.ClearSession()
		r.state.Phase = PhaseStopped
		if r.events != nil {
			r.events.Emit(events.Event{Kind: events.EventStopped})
		}
	}
	_ = wasDelete // swan2 logs delete handling; the debug layer ropes in later
	return shutdown, nil
}

// openRunningPayloads returns cleartext inner payloads for inbound running
// packets, plus whether a protected message was complete. Cleartext
// INFORMATIONALs are unusual but tolerated; protected packets are decrypted
// with the raw message (exact AAD bytes). Incomplete SKF reassembly returns
// (nil, false, nil) so the caller can keep the outstanding request marker
// intact exactly like swan2 parse_response_protected / parse_inbound_control
// on the NeedMore path.
func openRunningPayloads(state *State, raw []byte, msg *wire.Message) ([]wire.Payload, bool, error) {
	if msg.Encrypted != nil {
		plds, complete, err := openProtectedRawState(nil, state, raw)
		return plds, complete, err
	}
	return msg.Payloads, true, nil
}

// fail emits Broken then Stopped and returns the original error, mirroring
// swan2 dataplane report_failure for fatal running-state errors.
func (r *Running) fail(err error) error {
	if r != nil && r.events != nil {
		r.events.Emit(events.Event{Kind: events.EventBroken, Reason: err.Error()})
		r.events.Emit(events.Event{Kind: events.EventStopped})
	}
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
	return r.sendFrames(tx, frames)
}

// sendFrames pushes a prepared frame list into the transport queue without
// changing message-id bookkeeping.
func (r *Running) sendFrames(tx chan<- *transport.Frame, frames []*transport.Frame) error {
	for _, frame := range frames {
		if frame == nil {
			continue
		}
		tx <- frame
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
			return false, fmt.Errorf("control: multiple delete payloads in one running request")
		}
		deletePayload = &d
		_ = i
	}
	if other {
		return false, fmt.Errorf("control: unexpected non-delete payload in running request")
	}
	if deletePayload == nil {
		return false, fmt.Errorf("control: running request carries no delete payload")
	}

	switch deletePayload.ProtocolID {
	case wire.DeleteProtocolIKE:
		if len(deletePayload.SPIs) != 0 {
			return false, fmt.Errorf("control: ike delete must not carry spis")
		}
		return true, nil
	case wire.DeleteProtocolESP:
		if len(deletePayload.SPIs) != 1 {
			return false, fmt.Errorf("control: esp delete must carry exactly one spi")
		}
		if r.state.ActiveChild == nil {
			return false, fmt.Errorf("control: received child delete without an active child sa")
		}
		if deletePayload.SPIs[0] != r.state.ActiveChild.OutboundSPI {
			return false, fmt.Errorf("control: unexpected child delete spi")
		}
		r.state.ActiveChild = nil
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
