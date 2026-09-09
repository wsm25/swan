package control

import (
	"context"
	"fmt"
	"math"
	"time"

	"swan/transport"
	"swan/wire"
)

// Request/response exchange mechanics shared by every stage:
//   - message-id allocation (beginRequest);
//   - outbound checkpoint for retransmission;
//   - inbound loop with retransmission timer, honoring only the expected
//     message-id and filtering duplicate/stale/foreign packets;
//   - response envelope validation (version, flags, SPIs, exchange type,
//     message-id).

// Disposition classifies an inbound packet seen while a request is
// outstanding.
type Disposition uint8

const (
	// DispositionExpected is the awaited response.
	DispositionExpected Disposition = iota
	// DispositionDuplicateOrStale repeats an already completed message-id.
	DispositionDuplicateOrStale
	// DispositionIgnore is unrelated to this SA/request (SPI mismatch etc).
	DispositionIgnore
)

// beginRequest claims the next outbound message-id and marks it expected.
func (h *Handshake) beginRequest() uint32 {
	id := h.state.NextRequestMessageID
	h.state.ExpectedResponseMessageID = id
	h.state.HasExpectedResponse = true
	if h.state.NextRequestMessageID != math.MaxUint32 {
		h.state.NextRequestMessageID++
	}
	return id
}

// sendRequest stores the checkpoint and writes every frame to the transport
// writer channel (owned by tx). The same frame pointers remain in the
// checkpoint: receivers treat Frame payloads as immutable, which is what
// makes identical retransmission possible.
func (h *Handshake) sendRequest(ctx context.Context, tx chan<- *transport.Frame, packets []*transport.Frame) error {
	if !h.state.HasExpectedResponse {
		return fmt.Errorf("control: sendRequest without an expected response message-id")
	}
	h.state.OutboundRequest = &Checkpoint{
		MessageID: h.state.ExpectedResponseMessageID,
		Packets:   packets,
	}
	for _, frame := range packets {
		select {
		case tx <- frame:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// waitResponse drives the receive loop for one request: parses inbound IKE
// packets, drops ESP/keepalives (never delivered by transport anyway),
// classifies headers and on timeout retransmits the checkpoint with
// exponential backoff up to MaxRetries.
func (h *Handshake) waitResponse(ctx context.Context, in <-chan *transport.Packet, tx chan<- *transport.Frame, step string, exchange wire.ExchangeType, msgID uint32) (*wire.Message, error) {
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
			msg, dispose, err := h.handleInboundResponse(pkt, msgID)
			if err != nil {
				return nil, err
			}
			switch dispose {
			case DispositionDuplicateOrStale, DispositionIgnore:
				// swan2 recreates the delay after every received packet, so
				// the RTO always counts from the last event.
				timer.Reset(rto)
				continue
			case DispositionExpected:
			default:
				return nil, fmt.Errorf("control: unexpected disposition %d for %s", dispose, step)
			}

			if err := h.validateResponseHeader(msg.Header, exchange, msgID); err != nil {
				return nil, err
			}
			// Accepted a completed response: absorb bookkeeping exactly once,
			// then fall through to return.
			if exchange == wire.ExchangeIkeAuth {
				h.state.FirstIKEAuthSeen = true
			}
			h.state.LastCompletedResponseMessageID = msgID
			h.state.HasLastCompletedResponse = true
			h.state.OutboundRequest = nil
			h.state.InboundFragments = nil
			// The response has been accepted: the in-flight expectation ends
			// here. ExpectedResponseMessageID is left intact because the EAP
			// bridge labels the just-finished round with it before the next
			// beginRequest overwrites the pair.
			h.state.HasExpectedResponse = false
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return msg, nil

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

// handleInboundResponse parses one classified transport packet, releases it
// (exactly once) and classifies the header. It returns the parsed message
// only for the expected response path.
func (h *Handshake) handleInboundResponse(pkt *transport.Packet, msgID uint32) (*wire.Message, Disposition, error) {
	if pkt == nil {
		return nil, DispositionIgnore, nil
	}
	defer pkt.Release()
	if pkt.Kind != transport.KindIKE {
		return nil, DispositionIgnore, nil
	}
	msg, err := wire.ParseMessage(pkt.Payload)
	if err != nil {
		// Malformed datagrams are dropped without failing the in-flight
		// request; the retransmission timer will make progress if the peer
		// answer was lost.
		return nil, DispositionIgnore, nil
	}
	dispose, err := h.classifyResponse(msg.Header, msgID)
	if err != nil {
		return nil, DispositionIgnore, err
	}
	if dispose != DispositionExpected {
		return nil, dispose, nil
	}

	// The returned Message must outlive the pooled buffer, which Release
	// returns to the pool before this function returns. Clone the raw
	// datagram once and re-parse so the message owns ordinary GC memory.
	owned := append([]byte(nil), pkt.Payload...)
	msg, err = wire.ParseMessage(owned)
	if err != nil {
		return nil, DispositionIgnore, nil
	}
	return msg, dispose, nil
}

// classifyResponse implements the swan2 disposition rules for a parsed
// header: identical SPIs and message-id -> expected; lower/equal already
// completed -> duplicate or stale; anything else in-window is a protocol
// error, out-of-window is ignored.
func (h *Handshake) classifyResponse(hdr wire.Header, msgID uint32) (Disposition, error) {
	if hdr.InitiatorSPI.Uint64() != h.state.InitiatorSPI {
		return DispositionIgnore, nil
	}
	if h.state.ResponderSPI != 0 && hdr.ResponderSPI.Uint64() != h.state.ResponderSPI {
		return DispositionIgnore, nil
	}
	if err := validateResponseEnvelopeForRole(hdr, h.state.IsOriginalInitiator); err != nil {
		return DispositionIgnore, err
	}

	id := hdr.MessageID
	if id == msgID {
		return DispositionExpected, nil
	}
	if id < msgID && h.state.HasLastCompletedResponse && id <= h.state.LastCompletedResponseMessageID {
		return DispositionDuplicateOrStale, nil
	}
	if id < msgID {
		return DispositionIgnore, fmt.Errorf("control: stale response message-id %d while waiting for %d", id, msgID)
	}
	return DispositionIgnore, fmt.Errorf("control: future response message-id %d while waiting for %d", id, msgID)
}

// validateResponseHeader checks version/flags/SPIs/exchange/message-id
// per RFC 7296 and the MVP responder profile.
func (h *Handshake) validateResponseHeader(hdr wire.Header, exchange wire.ExchangeType, msgID uint32) error {
	if err := validateResponseEnvelopeForRole(hdr, h.state.IsOriginalInitiator); err != nil {
		return err
	}
	if hdr.InitiatorSPI.Uint64() != h.state.InitiatorSPI {
		return fmt.Errorf("control: initiator SPI mismatch in response")
	}
	if h.state.ResponderSPI != 0 && hdr.ResponderSPI.Uint64() != h.state.ResponderSPI {
		return fmt.Errorf("control: responder SPI mismatch in response")
	}
	if hdr.ExchangeType != exchange {
		return fmt.Errorf("control: unexpected exchange type %s, want %s", debugExchangeName(hdr.ExchangeType), debugExchangeName(exchange))
	}
	if hdr.MessageID != msgID {
		return fmt.Errorf("control: unexpected message-id %d, want %d", hdr.MessageID, msgID)
	}
	if exchange == wire.ExchangeIkeSAInit {
		if hdr.ResponderSPI.IsZero() {
			if hdr.NextPayload != wire.PayloadTypeNotify {
				return fmt.Errorf("control: IKE_SA_INIT without responder SPI must start with a NOTIFY payload")
			}
		} else {
			// swan2 records a non-zero responder SPI as soon as a valid
			// SA_INIT response arrives, so later SA_INIT retries (e.g. after a
			// COOKIE with a non-zero SPI) are checked against it.
			h.state.ResponderSPI = hdr.ResponderSPI.Uint64()
		}
	}
	return nil
}

// validateResponseEnvelope is validateResponseEnvelopeForRole for the
// initiator-only handshake path (the only path that uses the Handshake
// exchange helpers).
func validateResponseEnvelope(hdr wire.Header) error {
	return validateResponseEnvelopeForRole(hdr, true)
}

// validateResponseEnvelopeForRole checks the response flag/version
// invariant for a given original-initator role. When the peer is the
// original initiator of the current IKE SA, its responses legitimately set
// FlagInitiator as well as FlagResponse (RFC 7296 2.8.2).
func validateResponseEnvelopeForRole(hdr wire.Header, localOriginalInitiator bool) error {
	if hdr.Version != wire.IKEDefaultVersion {
		return fmt.Errorf("control: unexpected IKE version 0x%02x", hdr.Version)
	}
	const mask = wire.FlagResponse | wire.FlagVersion | wire.FlagInitiator
	if hdr.Flags&wire.FlagResponse == 0 {
		return fmt.Errorf("control: expected response flag in inbound message")
	}
	hasInitiator := hdr.Flags&wire.FlagInitiator != 0
	wantInitiator := !localOriginalInitiator
	if hasInitiator != wantInitiator {
		return fmt.Errorf("control: unexpected initiator flag in response (have=%t want=%t)", hasInitiator, wantInitiator)
	}
	if hdr.Flags&^mask != 0 {
		return fmt.Errorf("control: unexpected reserved flag bits 0x%02x", uint8(hdr.Flags)&^mask)
	}
	return nil
}

// retransmit resends the current checkpoint and doubles the RTO (capped).
func (h *Handshake) retransmit(ctx context.Context, tx chan<- *transport.Frame, rto *time.Duration, retries *uint8, step string) error {
	if h.state.OutboundRequest == nil {
		return fmt.Errorf("control: timed out while waiting for %s without an outbound checkpoint", step)
	}
	if h.state.OutboundRequest.MessageID != h.state.ExpectedResponseMessageID {
		return fmt.Errorf("control: outbound request checkpoint mismatch while retransmitting %s", step)
	}
	if *retries >= h.cfg.Timeouts.MaxRetries {
		return fmt.Errorf("control: timed out waiting for %s after %d retransmits", step, h.cfg.Timeouts.MaxRetries)
	}
	*retries++
	h.state.InboundFragments = nil
	for _, frame := range h.state.OutboundRequest.Packets {
		select {
		case tx <- frame:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	*rto *= 2
	if max := h.cfg.Timeouts.MaxRTO; *rto > max {
		*rto = max
	}
	return nil
}

// debugExchangeName is a tiny local fallback so this file does not depend on
// the debug package's name maps.
func debugExchangeName(t wire.ExchangeType) string {
	switch t {
	case wire.ExchangeIkeSAInit:
		return "IKE_SA_INIT"
	case wire.ExchangeIkeAuth:
		return "IKE_AUTH"
	case wire.ExchangeCreateChild:
		return "CREATE_CHILD_SA"
	case wire.ExchangeInformational:
		return "INFORMATIONAL"
	default:
		return fmt.Sprintf("#0x%x", uint8(t))
	}
}
