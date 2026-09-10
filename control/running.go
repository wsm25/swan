package control

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/wsm25/swan/events"
	"github.com/wsm25/swan/transport"
	"github.com/wsm25/swan/wire"
	"github.com/wsm25/swan/wire/payload"
)

// Running owns the SA after the handshake: DPD keepalives, rekey timers,
// inbound INFORMATIONAL/DELETE/CREATE_CHILD_SA processing and
// duplicate-response replay.
//
// Its inbox is the same demux-owned channel the handshake used. The
// handshake stops reading that channel before Running starts, so ownership
// moves without a channel switch and no already-queued packet can be lost.

// DefaultKeepaliveInterval is the fallback keepalive cadence used by
// DefaultTimeouts (20s). The running cadence comes from cfg.Timeouts.
// Outstanding requests have their own RTO retransmission timer.
const DefaultKeepaliveInterval = 20 * time.Second

// MaxInboundResponseHistory bounds cached responses replayed for duplicate
// peer INFORMATIONAL/DELETE/CREATE_CHILD_SA requests.
const MaxInboundResponseHistory = 4

// Running is the post-handshake control actor. It shares the *State with
// the handshake only through the ownership handoff in Control.Run; after
// that no other worker mutates it until the session tears down the context
// and observes Running's exit.
type Running struct {
	state  *State
	events *events.Hub
	cfg    *Config

	// Timers owned entirely by the single Run goroutine.
	ikeSoft    *time.Timer
	childSoft  *time.Timer
	leaseTimer *time.Timer
	retryTimer *time.Timer

	// leaseDeadline is the absolute hard-expiry time for the current CP
	// lease. Zero means no lease is active.
	leaseDeadline time.Time
	leasePending  bool
	retryKind     RekeyKind
	retryTrigger  RekeyTrigger
}

// Run serves until ctx ends or the peer requests IKE_SA delete. armed
// holds the loop until the public Session has emitted
// HandshakeCompleted/ConfigAssigned/Started, so terminal events from this
// actor can never reorder before the success sequence.
func (r *Running) Run(ctx context.Context, in <-chan *transport.Packet, tx chan<- *transport.Frame, armed <-chan struct{}) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-armed:
	}

	now := time.Now()
	r.ikeSoft = time.NewTimer(rekeyDeadline(now, r.cfg.Rekey.IKE.Time, r.cfg.Rekey.RandTime))
	r.childSoft = time.NewTimer(rekeyDeadline(now, r.cfg.Rekey.Child.Time, r.cfg.Rekey.RandTime))
	r.retryTimer = time.NewTimer(0)
	if !r.retryTimer.Stop() {
		<-r.retryTimer.C
	}
	stopTimer(r.retryTimer)
	r.leaseTimer = time.NewTimer(0)
	if !r.leaseTimer.Stop() {
		<-r.leaseTimer.C
	}
	stopTimer(r.leaseTimer)
	if r.state.Assigned != nil && r.state.Assigned.AddressExpirySeconds > 0 {
		r.armLeaseTimer()
	}
	defer func() {
		stopTimer(r.ikeSoft)
		stopTimer(r.childSoft)
		stopTimer(r.leaseTimer)
		stopTimer(r.retryTimer)
	}()

	tick := time.NewTicker(r.cfg.Timeouts.Keepalive)
	defer tick.Stop()

	// Retransmission timer of the outstanding current-SA request. It is
	// armed on send, disarmed when the authenticated response lands, and
	// doubles up to MaxRTO per retry.
	rto := r.cfg.Timeouts.InitialRTO
	retries := uint8(0)
	var rtoTimer *time.Timer
	var rtoC <-chan time.Time
	rtoArmedID := uint32(0)

	// Retransmission timer of the old IKE SA DELETE (separate numbering).
	oldRto := r.cfg.Timeouts.InitialRTO
	oldRetries := uint8(0)
	var oldRtoTimer *time.Timer
	var oldRtoC <-chan time.Time

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
	armOldRTO := func() {
		if oldRtoTimer == nil {
			oldRtoTimer = time.NewTimer(oldRto)
		} else {
			stopTimer(oldRtoTimer)
			oldRtoTimer.Reset(oldRto)
		}
		oldRtoC = oldRtoTimer.C
	}
	disarmOldRTO := func() {
		if oldRtoTimer != nil {
			stopTimer(oldRtoTimer)
		}
		oldRtoC = nil
	}
	defer disarmRTO()
	defer disarmOldRTO()

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
				if r.state.Rekey != nil {
					// Rekey timeout keeps the old SA alive and retries
					// later; DPD keepalive timeout alone stays fatal.
					r.abandonRekey(true)
					retries = 0
					rto = r.cfg.Timeouts.InitialRTO
					continue
				}
				if r.leasePending {
					if err := r.leaseRetryOrExpire(ctx); err != nil {
						return r.fail(err)
					}
					retries = 0
					rto = r.cfg.Timeouts.InitialRTO
					continue
				}
				return r.fail(fmt.Errorf("control: keepalive request %d unanswered after %d retries", r.state.ExpectedResponseMessageID, retries))
			}
			if r.state.OutboundRequest == nil {
				return r.fail(fmt.Errorf("control: outstanding request has no retransmit checkpoint"))
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

		case <-oldRtoC:
			oldRtoC = nil
			if len(r.state.OldIKE) == 0 || !r.state.OldIKE[0].HasExpectedResponse {
				continue
			}
			if oldRetries >= r.cfg.Timeouts.MaxRetries {
				// Best effort: the new IKE SA is already current and the
				// peer will close the old SA (or we stop trying to).
				old := &r.state.OldIKE[0]
				old.HasExpectedResponse = false
				old.OutboundRequest = nil
				oldRetries = 0
				oldRto = r.cfg.Timeouts.InitialRTO
				continue
			}
			old := &r.state.OldIKE[0]
			if old.OutboundRequest == nil {
				continue
			}
			if err := r.sendFrames(ctx, tx, old.OutboundRequest.Packets); err != nil {
				if errors.Is(err, ctx.Err()) {
					return ctx.Err()
				}
				oldRto = r.cfg.Timeouts.InitialRTO
				continue
			}
			oldRetries++
			if oldRto < r.cfg.Timeouts.MaxRTO {
				oldRto *= 2
				if oldRto > r.cfg.Timeouts.MaxRTO {
					oldRto = r.cfg.Timeouts.MaxRTO
				}
			}
			armOldRTO()

		case <-tick.C:
			// Expired SKF reassembly is normally dropped lazily when the
			// next fragment arrives; clear it on the idle tick as well.
			if frag := r.state.InboundFragments; frag != nil && time.Now().After(frag.ExpiresAt) {
				r.state.InboundFragments = nil
			}
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
			rtoArmedID = r.state.ExpectedResponseMessageID
			armRTO()

		case <-r.ikeSoft.C:
			if r.safeToRekey() {
				if err := r.startIKERekey(ctx, tx, RekeyTriggerTime); err != nil {
					if errors.Is(err, ctx.Err()) {
						return ctx.Err()
					}
					r.abandonRekey(true)
				} else {
					retries = 0
					rto = r.cfg.Timeouts.InitialRTO
					rtoArmedID = r.state.ExpectedResponseMessageID
					armRTO()
				}
			}

		case <-r.childSoft.C:
			if r.safeToRekey() {
				if err := r.startChildRekey(ctx, tx, RekeyTriggerTime); err != nil {
					if errors.Is(err, ctx.Err()) {
						return ctx.Err()
					}
					r.abandonRekey(true)
				} else {

					retries = 0
					rto = r.cfg.Timeouts.InitialRTO
					rtoArmedID = r.state.ExpectedResponseMessageID
					armRTO()
				}
			}

		case <-r.cfg.NearWrap:
			if r.safeToRekey() && r.state.ActiveChild != nil {
				if err := r.startChildRekey(ctx, tx, RekeyTriggerNearWrap); err != nil {
					if errors.Is(err, ctx.Err()) {
						return ctx.Err()
					}
					r.abandonRekey(true)
				} else {
					retries = 0
					rto = r.cfg.Timeouts.InitialRTO
					rtoArmedID = r.state.ExpectedResponseMessageID
					armRTO()
				}
			}

		case <-r.retryTimer.C:
			if r.safeToRekey() {
				switch r.retryKind {
				case RekeyIke:
					if err := r.startIKERekey(ctx, tx, r.retryTrigger); err != nil {
						r.abandonRekey(true)
						continue
					}
				case RekeyChild:
					if r.state.ActiveChild != nil {
						if err := r.startChildRekey(ctx, tx, r.retryTrigger); err != nil {
							r.abandonRekey(true)
							continue
						}
					}
				}
				retries = 0
				rto = r.cfg.Timeouts.InitialRTO
				rtoArmedID = r.state.ExpectedResponseMessageID
				armRTO()
			}

		case <-r.leaseTimer.C:
			if r.safeToRenewLease() {
				if err := r.sendLeaseRenewal(ctx, tx); err != nil {
					if errors.Is(err, ctx.Err()) {
						return ctx.Err()
					}
					if lerr := r.leaseRetryOrExpire(ctx); lerr != nil {
						return r.fail(lerr)
					}
				} else {
					retries = 0
					rto = r.cfg.Timeouts.InitialRTO
					rtoArmedID = r.state.ExpectedResponseMessageID
					armRTO()
				}
			}

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
			if r.state.HasExpectedResponse && rtoArmedID != r.state.ExpectedResponseMessageID {
				disarmRTO()
				retries = 0
				rto = r.cfg.Timeouts.InitialRTO
				rtoArmedID = r.state.ExpectedResponseMessageID
				armRTO()
			} else if !r.state.HasExpectedResponse && !r.hasOldExpectedResponse() {
				disarmRTO()
				retries = 0
				rto = r.cfg.Timeouts.InitialRTO
				if rtoArmedID != 0 {
					rtoArmedID = 0
				}
			}
			if len(r.state.OldIKE) > 0 && r.state.OldIKE[0].HasExpectedResponse {
				armOldRTO()
			} else {
				disarmOldRTO()
			}
			if shutdown {
				return nil
			}
		}
	}
}

func (r *Running) hasOldExpectedResponse() bool {
	return len(r.state.OldIKE) > 0 && r.state.OldIKE[0].HasExpectedResponse
}

func (r *Running) resetChildSoft() {
	if r.childSoft == nil {
		return
	}
	stopTimer(r.childSoft)
	r.childSoft.Reset(rekeyDeadline(time.Now(), r.cfg.Rekey.Child.Time, r.cfg.Rekey.RandTime))
}

func (r *Running) resetIkeSoft() {
	if r.ikeSoft == nil {
		return
	}
	stopTimer(r.ikeSoft)
	r.ikeSoft.Reset(rekeyDeadline(time.Now(), r.cfg.Rekey.IKE.Time, r.cfg.Rekey.RandTime))
}

func (r *Running) armLeaseTimer() {
	if r.state.Assigned == nil || r.state.Assigned.AddressExpirySeconds == 0 {
		return
	}
	delay := leaseRenewDelay(r.state.Assigned.AddressExpirySeconds)
	r.leaseDeadline = time.Now().Add(time.Duration(r.state.Assigned.AddressExpirySeconds) * time.Second)
	if r.leaseTimer == nil {
		r.leaseTimer = time.NewTimer(delay)
	} else {
		stopTimer(r.leaseTimer)
		r.leaseTimer.Reset(delay)
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

	// Retained old IKE SA packets use the old SPIs/keys/MIDs.
	if len(r.state.OldIKE) > 0 {
		old := &r.state.OldIKE[0]
		if msg.Header.InitiatorSPI.Uint64() == old.InitiatorSPI && msg.Header.ResponderSPI.Uint64() == old.ResponderSPI {
			return r.processOldIKEPacket(ctx, pkt, msg, tx)
		}
	}

	if msg.Header.Flags&wire.FlagResponse != 0 {
		return r.processResponse(ctx, tx, pkt, msg)
	}

	// Peer request. Parse/decrypt the protected request before replay
	// validation: incomplete SKF requests are dropped while their
	// reassembly is retained.
	inner, complete, err := openRunningPayloads(r.state, pkt.Payload, msg)
	if err != nil {
		return false, err
	}
	if msg.Header.ExchangeType == wire.ExchangeCreateChild {
	}
	if !complete {
		return false, errors.New("control: inbound rekey/control request requires more fragments")
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
		return false, r.processCreateChild(ctx, tx, msg, inner)
	default:
		return false, nil
	}
}

// processResponse handles the protected response to our outstanding current
// SA request (keepalive, rekey, lease renewal, or post-rekey child DELETE).
func (r *Running) processResponse(ctx context.Context, tx chan<- *transport.Frame, pkt *transport.Packet, msg *wire.Message) (bool, error) {
	if validateResponseEnvelopeForRole(msg.Header, r.state.IsOriginalInitiator) != nil {
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
	inner, complete, err := openRunningPayloads(r.state, pkt.Payload, msg)
	if err != nil {
		return false, err
	}
	if msg.Header.ExchangeType == wire.ExchangeCreateChild {
	}
	if !complete {
		return false, nil
	}

	switch {
	case r.state.Rekey != nil:
		if r.state.Rekey.Kind == RekeyChild {
			if err := r.finishChildRekeyResponse(ctx, tx, inner); err != nil {
				return false, err
			}
			// finishChildRekeyResponse may have already started the
			// old-child DELETE as the next outbound request; leave that
			// request's bookkeeping untouched in that case.
			if r.state.Phase == PhaseRekeyChildDeletingOld {
				break
			}
		} else {
			if err := r.finishIKERekeyResponse(ctx, tx, inner); err != nil {
				return false, err
			}
		}
		r.state.HasExpectedResponse = false
		r.state.OutboundRequest = nil
		r.state.InboundFragments = nil
	case r.leasePending:
		if err := r.finishLeaseResponse(inner); err != nil {
			return false, err
		}
		r.state.HasExpectedResponse = false
		r.state.OutboundRequest = nil
		r.state.InboundFragments = nil
	default:
		r.state.HasExpectedResponse = false
		r.state.HasLastCompletedResponse = true
		r.state.LastCompletedResponseMessageID = msg.Header.MessageID
		r.state.OutboundRequest = nil
		r.state.InboundFragments = nil
		if r.state.Phase == PhaseRekeyChildDeletingOld {
			r.finishDeleteOldChild()
		}
	}
	return false, nil
}

// processInformational applies the swan2
// process_informational_request_payloads rules to an already-decrypted
// payload list and sends the (empty, CFG_ACK or DELETE) answer.
func (r *Running) processInformational(ctx context.Context, tx chan<- *transport.Frame, msg *wire.Message, inner []wire.Payload) (bool, error) {
	shutdown, cfgAck, err := r.handleInformationalForPayloads(inner)
	if err != nil {
		return false, err
	}
	next := wire.PayloadTypeNone
	var responseBody []byte
	if cfgAck {
		next = wire.PayloadTypeCP
		responseBody = cepSinglePayload(payload.AppendConfigPayload(nil, payload.ConfigPayload{Kind: wire.ConfigTypeAck}))
	}
	frames, err := buildProtectedStateAs(nil, r.state, wire.ExchangeInformational, msg.Header.MessageID, next, responseBody, responseFlags(stateIKEEnvelope(r.state)))
	if err != nil {
		return false, err
	}
	if err := r.sendFrames(ctx, tx, frames); err != nil {
		return false, err
	}
	r.rememberResponse(msg.Header.MessageID, frames)

	if shutdown {
		// Clean peer-initiated IKE delete: Run returns nil and the public
		// Session tears the session down. The event stream (Stopped,
		// closed Done / Tunnel) is the Session's job, so exactly one
		// ordered shutdown sequence is produced.
		r.state.ClearSession()
		r.state.Phase = PhaseStopped
	}
	return shutdown, nil
}

// handleInformationalForPayloads applies the swan2
// process_informational_request_payloads rules to an already-decrypted
// payload list. DELETE is accepted for the active child, a retained old
// child, or the active IKE SA; unknown child SPIs are dropped. A running
// request carrying exactly one CFG_SET is applied and the bool result asks
// processInformational to answer CFG_ACK.
func (r *Running) handleInformationalForPayloads(plds []wire.Payload) (peerShutdown bool, cfgAck bool, err error) {
	if len(plds) == 0 {
		return false, false, nil
	}
	if len(plds) == 1 && plds[0].Type == wire.PayloadTypeCP {
		cp, perr := payload.ParseConfigPayload(plds[0].Body)
		if perr != nil {
			return false, false, perr
		}
		if cp.Kind != wire.ConfigTypeSet {
			return false, false, errors.New("control: unexpected non-delete payload in running request")
		}
		assigned, present, aerr := cesDecodeAssignedCP(cp)
		if aerr != nil {
			return false, false, aerr
		}
		r.applyConfigUpdate(assigned, present, configApplyMerge)
		return false, true, nil
	}
	var deletePayload *payload.Delete
	for i := range plds {
		p := &plds[i]
		if p.Type != wire.PayloadTypeDelete {
			return false, false, errors.New("control: unexpected non-delete payload in running request")
		}
		d, derr := payload.ParseDelete(p.Body)
		if derr != nil {
			return false, false, derr
		}
		if deletePayload != nil {
			return false, false, errors.New("control: multiple delete payloads in one running request")
		}
		deletePayload = &d
	}
	if deletePayload == nil {
		return false, false, errors.New("control: running request carries no delete payload")
	}

	switch deletePayload.ProtocolID {
	case wire.DeleteProtocolIKE:
		if len(deletePayload.SPIs) != 0 {
			return false, false, errors.New("control: ike delete must not carry spis")
		}
		return true, false, nil
	case wire.DeleteProtocolESP:
		if len(deletePayload.SPIs) != 1 {
			return false, false, errors.New("control: esp delete must carry exactly one spi")
		}
		spi := deletePayload.SPIs[0]
		// A DELETE for a replaced child only cleans up the retained inbound
		// codec; it does not end the active tunnel.
		if r.state.OldChild != nil && spi == r.state.OldChild.OutboundSPI {
			r.dataplaneChildDeleted(*r.state.OldChild)
			r.state.OldChild = nil
			if r.state.Phase == PhaseRekeyChildDeletingOld {
				r.state.Phase = PhaseRunning
			}
			return false, false, nil
		}
		if r.state.ActiveChild == nil {
			return false, false, nil
		}
		if spi != r.state.ActiveChild.OutboundSPI {
			return false, false, nil
		}
		r.dataplaneChildDeleted(*r.state.ActiveChild)
		r.state.ActiveChild = nil
		return false, false, nil
	default:
		return false, false, fmt.Errorf("control: unsupported delete protocol %d", deletePayload.ProtocolID)
	}
}

// fail returns the original error without emitting: the public Session is
// the single Broken-event owner on the running path and wraps the same
// error; duplicate Broken events would otherwise reach subscribers.
func (r *Running) fail(err error) error {
	return err
}

// sendKeepalive issues the empty INFORMATIONAL request when no request is
// outstanding.
func (r *Running) sendKeepalive(ctx context.Context, tx chan<- *transport.Frame) error {
	if r.state.HasExpectedResponse {
		return nil
	}
	msgID := r.beginRequest()
	frames, err := buildProtectedState(r.cfg, r.state, wire.ExchangeInformational, msgID, wire.PayloadTypeNone, nil)
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

// sendLeaseRenewal issues the CP lease renewal request (INFORMATIONAL +
// CFG_REQUEST), section 8 of the design.
func (r *Running) sendLeaseRenewal(ctx context.Context, tx chan<- *transport.Frame) error {
	st := r.state
	assigned := st.Assigned
	if assigned == nil {
		return nil
	}
	msgID := r.beginRequest()
	body := payload.AppendConfigRenewRequest(nil, payload.ConfigRenewRequest{
		InternalIPv4:       assigned.InternalIPv4,
		InternalIPv6:       assigned.InternalIPv6,
		InternalIPv6Prefix: assigned.InternalIPv6Prefix,
	})
	frames, err := buildProtectedState(r.cfg, st, wire.ExchangeInformational, msgID, wire.PayloadTypeCP, cepSinglePayload(body))
	if err != nil {
		return err
	}
	r.leasePending = true
	st.OutboundRequest = &Checkpoint{MessageID: msgID, Packets: frames}
	return r.sendFrames(ctx, tx, frames)
}

// finishLeaseResponse handles a CFG_REPLY to our renewal request.
func (r *Running) finishLeaseResponse(inner []wire.Payload) error {
	r.leasePending = false
	var cpBody []byte
	for i := range inner {
		if inner[i].Type == wire.PayloadTypeCP {
			cpBody = inner[i].Body
			break
		}
	}
	if len(cpBody) == 0 {
		return r.leaseRetryOrExpire(context.Background())
	}
	assigned, err := cesDecodeAssigned(cpBody)
	if err != nil {
		r.leaseRetryOrExpire(context.Background())
		return err
	}
	r.applyConfigUpdate(assigned, cesAssignedMask{}, configApplyReplace)
	return nil
}

// leaseRetryOrExpire implements renewal failure handling: retry at
// min(remaining/2, 60s) +- 5%, or fail the session after the advertised
// hard expiry passes.
func (r *Running) leaseRetryOrExpire(ctx context.Context) error {
	r.leasePending = false
	r.state.OutboundRequest = nil
	r.state.InboundFragments = nil
	r.state.HasExpectedResponse = false
	if r.state.Assigned == nil || r.state.Assigned.AddressExpirySeconds == 0 {
		return nil
	}
	if !r.leaseDeadline.IsZero() && !time.Now().Before(r.leaseDeadline) {
		_ = ctx
		return fmt.Errorf("control: CP address lease expired at %s", r.leaseDeadline.Format(time.RFC3339))
	}
	remaining := time.Until(r.leaseDeadline)
	if remaining <= 0 {
		return fmt.Errorf("control: CP address lease expired")
	}
	delay := leaseRetryDelay(remaining)
	if r.leaseTimer == nil {
		r.leaseTimer = time.NewTimer(delay)
	} else {
		stopTimer(r.leaseTimer)
		r.leaseTimer.Reset(delay)
	}
	return nil
}

func randInt63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	return time.Now().UnixNano() % n
}

// leaseRenewDelay is the 80% renewal trigger from RFC 7296 3.15 expiry,
// with a 1s floor so a tiny expiry still leaves a live timer.
func leaseRenewDelay(expirySeconds uint32) time.Duration {
	delay := time.Duration(uint64(expirySeconds) * uint64(time.Second) * 8 / 10)
	if delay < time.Second {
		return time.Second
	}
	return delay
}

// leaseRetryDelay schedules the next lease-renewal attempt at
// min(remaining/2, 60s) with +-5% jitter and a 1s floor.
func leaseRetryDelay(remaining time.Duration) time.Duration {
	delay := remaining / 2
	if delay > 60*time.Second {
		delay = 60 * time.Second
	}
	delay += time.Duration(randInt63n(int64(delay/20 + 1)))
	if delay < time.Second {
		return time.Second
	}
	return delay
}

// openRunningPayloads returns cleartext inner payloads for inbound running
// packets, plus whether a protected message was complete.
func openRunningPayloads(state *State, raw []byte, msg *wire.Message) ([]wire.Payload, bool, error) {
	if msg.Encrypted != nil {
		plds, complete, err := openProtectedRawState(nil, state, raw)
		return plds, complete, err
	}
	return msg.Payloads, true, nil
}
