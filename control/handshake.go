package control

import (
	"context"
	"fmt"

	"github.com/wsm25/swan/events"
	"github.com/wsm25/swan/transport"
	"github.com/wsm25/swan/wire"
	"github.com/wsm25/swan/xcrypto"
)

// Handshake is the linear initiator state machine worker. It owns the SA
// state from PhaseStarting through PhaseRunning (exclusive), and drives the
// eap worker via the mailbox bridge in EapPeer.
//
// Flow (mirrors swan2 Ikev2Routine::run):
//
//	setup transport bookkeeping
//	IKE_SA_INIT     (message-id 0, COOKIE / INVALID_KE_PAYLOAD retries <= 2)
//	derive IKE keys
//	bootstrap IKE_AUTH (IDi/IDr/CP/child SA/TSi/TSr/notifies, EAP-only)
//	EAP loop        (one IKE_AUTH exchange per EAP round)
//	final IKE_AUTH  (local AUTH from EAP MSK, peer AUTH verify,
//	                 child SA/TS selection, CP reply)
//	handoff to Running
type Handshake struct {
	cfg    *Config
	state  *State
	events *events.Hub

	// localDH is generated together with the KE payload and consumed by
	// deriveIKEKeys (zeroized afterwards).
	localDH *xcrypto.DHKey

	eapPeer *EapPeer
}

// Run performs the full linear flow, then returns the handoff bundle.
// Control.Run is the canonical path (it adds the demux/running handoff);
// this method preserves the standalone entry point by pinning a Control
// value onto the receiver's shared pointers.
func (h *Handshake) Run(ctx context.Context, in <-chan *transport.Packet, tx chan<- *transport.Frame) (*Established, error) {
	if h == nil {
		return nil, fmt.Errorf("control: nil Handshake")
	}
	if h.cfg == nil {
		return nil, fmt.Errorf("control: Handshake missing config")
	}
	if h.state == nil {
		h.state = NewState()
	}
	c := &Control{cfg: h.cfg, state: h.state, events: h.events, handshake: h}
	return c.Run(ctx, in, tx)
}

// emit posts one event onto the hub. The hub's Emit call is non-blocking.
func (h *Handshake) emit(ev events.Event) {
	if h == nil || h.events == nil {
		return
	}
	h.events.Emit(ev)
}

// parseInbound wraps wire.ParseMessage and returns the message plus a
// release hook for the pooled transport packet. Callers must invoke the
// release function exactly once after they finish using the returned
// message. On error the packet is released and the error is returned.
func (h *Handshake) parseInbound(pkt *transport.Packet) (*wire.Message, func(), error) {
	if pkt == nil {
		return nil, func() {}, fmt.Errorf("control: nil inbound packet")
	}
	msg, err := wire.ParseMessage(pkt.Payload)
	if err != nil {
		pkt.Release()
		return nil, func() {}, err
	}
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		pkt.Release()
	}
	return msg, release, nil
}
