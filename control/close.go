package control

import (
	"context"
	"fmt"

	"swan/transport"
	"swan/wire"
	"swan/wire/payload"
)

// Graceful close: DELETE exchanges.
//
// Order and scope mirror swan2's routine close:
//   - active CHILD_SA first: INFORMATIONAL with ESP DELETE (our outbound
//     SPI); wait for the protected response with retransmission;
//   - IKE_SA second: INFORMATIONAL with IKE DELETE (no SPIs); same exchange
//     pattern;
//   - then ClearSession and PhaseStopped.
//
// close is best-effort: caller may cancel ctx to abort the sequence.

// CloseOutcome reports whether the close sequence sent anything.
type CloseOutcome uint8

const (
	CloseAlreadyClosed CloseOutcome = iota
	CloseDone
)

// handshakeForClose returns a control-level exchange handle bound to the
// control state. The handshake actor owns more state than the close path
// needs, but its sendRequest/waitResponse helpers are exactly the shared
// retransmission engine.
func (c *Control) handshakeForClose() *Handshake {
	if c.handshake != nil {
		return c.handshake
	}
	return &Handshake{cfg: c.cfg, state: c.state}
}

// buildChildDelete builds one ESP DELETE request for the peer-side SPI.
func (c *Control) buildChildDelete(msgID uint32, spi uint32) ([]*transport.Frame, error) {
	body := payload.AppendDelete(nil, payload.Delete{
		ProtocolID: wire.DeleteProtocolESP,
		SPIs:       []uint32{spi},
	})
	return buildProtectedState(c.cfg, c.state, wire.ExchangeInformational, msgID, wire.PayloadTypeDelete, body)
}

// buildIKEDelete builds the final IKE DELETE request (no SPIs).
func (c *Control) buildIKEDelete(msgID uint32) ([]*transport.Frame, error) {
	body := payload.AppendDelete(nil, payload.Delete{ProtocolID: wire.DeleteProtocolIKE})
	return buildProtectedState(c.cfg, c.state, wire.ExchangeInformational, msgID, wire.PayloadTypeDelete, body)
}

// runDeleteExchange drives one request/reply DELETE round with the shared
// retransmission machinery, without touching handshake-only state.
func (c *Control) runDeleteExchange(ctx context.Context, in <-chan *transport.Packet, tx chan<- *transport.Frame, step string, packets []*transport.Frame) error {
	h := c.handshakeForClose()
	if h == nil || h.state == nil {
		return fmt.Errorf("control: close exchange without state")
	}
	if err := h.sendRequest(ctx, tx, packets); err != nil {
		return err
	}
	// swan2 run_delete_exchange calls parse_response_protected and clears
	// the expected-response marker after the round completes. The shared
	// protected receiver handles both SK and SKF responses with the raw,
	// byte-exact AAD path.
	_, _, err := h.recvProtectedPayloads(ctx, in, tx, wire.ExchangeInformational, h.state.ExpectedResponseMessageID, step)
	if err != nil {
		return err
	}
	h.state.HasExpectedResponse = false
	return nil
}

// Close is the no-inbound-channel convenience wrapper: it sends the delete
// sequence best-effort and immediately clears the session. Callers with the
// demux channel should prefer CloseExchange for the full request/reply
// graceful close.
func (c *Control) Close(ctx context.Context, tx chan<- *transport.Frame) (CloseOutcome, error) {
	if c == nil || c.state == nil {
		return CloseAlreadyClosed, nil
	}
	if c.state.ResponderSPI == 0 || c.state.Phase == PhaseStopped {
		return CloseAlreadyClosed, nil
	}

	if c.state.ActiveChild != nil {
		msgID := c.state.NextRequestMessageID
		c.state.NextRequestMessageID++
		packets, err := c.buildChildDelete(msgID, c.state.ActiveChild.OutboundSPI)
		if err != nil {
			return CloseAlreadyClosed, err
		}
		if err := c.sendCloseFrames(ctx, tx, packets); err != nil {
			return CloseAlreadyClosed, err
		}
	}

	msgID := c.state.NextRequestMessageID
	c.state.NextRequestMessageID++
	packets, err := c.buildIKEDelete(msgID)
	if err != nil {
		return CloseAlreadyClosed, err
	}
	if err := c.sendCloseFrames(ctx, tx, packets); err != nil {
		return CloseAlreadyClosed, err
	}

	c.state.ClearSession()
	c.state.Phase = PhaseStopped
	return CloseDone, nil
}

// CloseExchange performs the full graceful close: CHILD_SA DELETE then
// IKE_SA DELETE, each awaiting the protected response with retries.
func (c *Control) CloseExchange(ctx context.Context, in <-chan *transport.Packet, tx chan<- *transport.Frame) (CloseOutcome, error) {
	if c == nil || c.state == nil {
		return CloseAlreadyClosed, nil
	}
	if c.state.ResponderSPI == 0 || c.state.Phase == PhaseStopped {
		return CloseAlreadyClosed, nil
	}

	h := c.handshakeForClose()

	if c.state.ActiveChild != nil {
		msgID := h.beginRequest()
		packets, err := c.buildChildDelete(msgID, c.state.ActiveChild.OutboundSPI)
		if err != nil {
			return CloseAlreadyClosed, err
		}
		if err := c.runDeleteExchange(ctx, in, tx, "child_sa delete", packets); err != nil {
			return CloseAlreadyClosed, err
		}
	}

	msgID := h.beginRequest()
	packets, err := c.buildIKEDelete(msgID)
	if err != nil {
		return CloseAlreadyClosed, err
	}
	if err := c.runDeleteExchange(ctx, in, tx, "ike_sa delete", packets); err != nil {
		return CloseAlreadyClosed, err
	}

	c.state.ClearSession()
	c.state.Phase = PhaseStopped
	return CloseDone, nil
}

// sendCloseFrames pushes prepared delete frames into the tx queue once.
func (c *Control) sendCloseFrames(ctx context.Context, tx chan<- *transport.Frame, packets []*transport.Frame) error {
	for _, frame := range packets {
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
