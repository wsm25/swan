package control

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"swan/transport"
	"swan/wire"
	"swan/wire/payload"
	"swan/xcrypto"
)

// Rekey orchestration for the Running actor. The select loop in running.go
// owns all state mutation; these helpers are called only from that single
// goroutine.

func (r *Running) safeToRekey() bool {
	if r == nil || r.state == nil {
		return false
	}
	st := r.state
	if st.Phase != PhaseRunning {
		return false
	}
	if st.HasExpectedResponse || st.Rekey != nil {
		return false
	}
	if len(st.OldIKE) != 0 {
		return false
	}
	return true
}

func (r *Running) safeToRenewLease() bool {
	if !r.safeToRekey() {
		return false
	}
	return r.state.Assigned != nil && r.state.Assigned.AddressExpirySeconds > 0
}

// beginRequest allocates the next message-id on the active IKE SA.
func (r *Running) beginRequest() uint32 {
	st := r.state
	id := st.NextRequestMessageID
	st.NextRequestMessageID++
	st.ExpectedResponseMessageID = id
	st.HasExpectedResponse = true
	return id
}

// startChildRekey builds and sends a CREATE_CHILD_SA CHILD rekey.
func (r *Running) startChildRekey(ctx context.Context, tx chan<- *transport.Frame, trigger RekeyTrigger) error {
	st := r.state
	if !r.safeToRekey() {
		return nil
	}
	if st.ActiveChild == nil {
		return nil
	}
	inboundSPI, err := generateChildSPI()
	if err != nil {
		return err
	}
	rc := &RekeyContext{
		Kind:      RekeyChild,
		Trigger:   trigger,
		StartedAt: time.Now(),
		OldChild:  st.ActiveChild,
		NewChild:  &NegotiatingChildSA{InboundSPI: inboundSPI},
	}
	plain, err := r.buildChildRekeyRequestPayloads(rc)
	if err != nil {
		return err
	}
	msgID := r.beginRequest()
	rc.MessageID = msgID
	frames, err := buildProtectedState(r.cfg, st, wire.ExchangeCreateChild, msgID, wire.PayloadTypeNotify, plain)
	if err != nil {
		return err
	}
	st.Rekey = rc
	st.Phase = PhaseRekeyChildRequesting
	st.OutboundRequest = &Checkpoint{MessageID: msgID, Packets: frames}
	if err := r.sendFrames(ctx, tx, frames); err != nil {
		return err
	}
	return nil
}

// startIKERekey builds and sends a CREATE_CHILD_SA IKE rekey.
func (r *Running) startIKERekey(ctx context.Context, tx chan<- *transport.Frame, trigger RekeyTrigger) error {
	st := r.state
	if !r.safeToRekey() {
		return nil
	}
	rc := &RekeyContext{
		Kind:      RekeyIke,
		Trigger:   trigger,
		StartedAt: time.Now(),
	}
	plain, err := r.buildIKERekeyRequestPayloads(rc)
	if err != nil {
		return err
	}
	msgID := r.beginRequest()
	rc.MessageID = msgID
	frames, err := buildProtectedState(r.cfg, st, wire.ExchangeCreateChild, msgID, wire.PayloadTypeSA, plain)
	if err != nil {
		return err
	}
	st.Rekey = rc
	st.Phase = PhaseRekeyIkeRequesting
	st.OutboundRequest = &Checkpoint{MessageID: msgID, Packets: frames}
	return r.sendFrames(ctx, tx, frames)
}

// abandonRekey clears a failed rekey and schedules a retry. The old SA
// remains installed and serving.
func (r *Running) abandonRekey(retry bool) {
	st := r.state
	if st.Rekey != nil {
		st.Rekey.LocalDH = nil
		st.Rekey.LocalKE = nil
		st.Rekey.Ni = nil
		st.Rekey.PeerPassive = nil
	}
	st.Rekey = nil
	st.OutboundRequest = nil
	st.InboundFragments = nil
	st.HasExpectedResponse = false
	st.Phase = PhaseRunning
	if retry && r.retryTimer != nil {
		armTimer(r.retryTimer, retryBackoff(r.cfg.Rekey.RetryInterval))
	}
}

// installChild asks the public Session data plane to atomically install a
// new child and waits for the ack before returning.
func (r *Running) installChild(ctx context.Context, child *ChildSA, keys *xcrypto.ChildKeys, selection *xcrypto.Selection) error {
	if r.cfg == nil || r.cfg.DataUpdates == nil {
		return errors.New("control: data-plane update channel is not wired")
	}
	ack := make(chan struct{}, 1)
	select {
	case r.cfg.DataUpdates <- DataplaneUpdate{
		Kind:      UpdateChildInstalled,
		Child:     *child,
		Keys:      keys,
		Selection: selection,
		Ack:       ack,
	}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-ack:
		return nil
	case <-time.After(2 * time.Second):
		return errors.New("control: data-plane child install ack timed out")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// dataplaneChildDeleted notifies Session that a child's inbound ESP codec
// may be dropped, or (for the active child) that the tunnel has ended.
func (r *Running) dataplaneChildDeleted(child ChildSA) {
	if r.cfg == nil || r.cfg.DataUpdates == nil {
		return
	}
	select {
	case r.cfg.DataUpdates <- DataplaneUpdate{Kind: UpdateChildDeleted, Child: child}:
	default:
	}
}

// finishChildRekeyResponse validates and installs our initiated child
// rekey, then starts the old-child DELETE.
func (r *Running) finishChildRekeyResponse(ctx context.Context, tx chan<- *transport.Frame, inner []wire.Payload) error {
	st := r.state
	rc := st.Rekey
	if rc == nil || rc.Kind != RekeyChild || rc.OldChild == nil {
		return errors.New("control: child rekey response without rekey context")
	}
	resp, err := r.parseChildRekeyResponse(inner)
	if err != nil {
		r.abandonRekey(true)
		return err
	}
	if !bytesEqual(resp.TSi, rc.OldChild.TSi) || !bytesEqual(resp.TSr, rc.OldChild.TSr) {
		r.abandonRekey(true)
		return errors.New("control: child rekey response changed traffic selectors")
	}
	keys, err := r.deriveChildRekeyKeys(rc, resp.Nr, resp.KEr, resp.Selection)
	if err != nil {
		r.abandonRekey(true)
		return err
	}
	child := &ChildSA{
		InboundSPI:          rc.NewChild.InboundSPI,
		OutboundSPI:         resp.PeerSPI,
		TSi:                 append([]byte(nil), resp.TSi...),
		TSr:                 append([]byte(nil), resp.TSr...),
		LocalChildInitiator: true,
	}
	old := st.ActiveChild
	if old == nil || old != rc.OldChild {
		r.abandonRekey(true)
		return errors.New("control: active child changed during child rekey")
	}
	if err := r.installChild(ctx, child, keys, resp.Selection); err != nil {
		// The failed install did not touch the old child; retry later.
		r.abandonRekey(true)
		return err
	}
	st.SelectedESP = resp.Selection
	st.ActiveChild = child
	st.OldChild = old
	st.Rekey = nil
	st.HasExpectedResponse = false
	st.OutboundRequest = nil
	st.InboundFragments = nil
	r.resetChildSoft()

	// The new child is installed: now DELETE the old child. This must never
	// happen before the data-plane ack above.
	return r.sendDeleteOldChild(ctx, tx)
}

// sendDeleteOldChild starts the post-rekey DELETE for the replaced child.
// RFC 7296 DELETE semantics send our INBOUND SPI (design arbiter decision).
func (r *Running) sendDeleteOldChild(ctx context.Context, tx chan<- *transport.Frame) error {
	st := r.state
	if st.OldChild == nil {
		st.Phase = PhaseRunning
		return nil
	}
	msgID := r.beginRequest()
	body := payload.AppendDelete(nil, payload.Delete{
		ProtocolID: wire.DeleteProtocolESP,
		SPIs:       []uint32{st.OldChild.InboundSPI},
	})
	frames, err := buildProtectedState(r.cfg, st, wire.ExchangeInformational, msgID, wire.PayloadTypeDelete, cepSinglePayload(body))
	if err != nil {
		return err
	}
	st.Phase = PhaseRekeyChildDeletingOld
	st.OutboundRequest = &Checkpoint{MessageID: msgID, Packets: frames}
	return r.sendFrames(ctx, tx, frames)
}

// finishDeleteOldChild completes a child rekey once the old-child DELETE
// response has arrived.
func (r *Running) finishDeleteOldChild() {
	st := r.state
	if st.OldChild != nil {
		r.dataplaneChildDeleted(*st.OldChild)
	}
	st.OldChild = nil
	st.Phase = PhaseRunning
	st.HasExpectedResponse = false
	st.OutboundRequest = nil
}

// finishIKERekeyResponse validates and installs our initiated IKE rekey,
// then starts the old IKE SA DELETE.
func (r *Running) finishIKERekeyResponse(ctx context.Context, tx chan<- *transport.Frame, inner []wire.Payload) error {
	st := r.state
	rc := st.Rekey
	if rc == nil || rc.Kind != RekeyIke {
		return errors.New("control: IKE rekey response without rekey context")
	}
	selection, responderSPI, nr, ker, err := r.parseIKERekeyResponse(inner)
	if err != nil {
		r.abandonRekey(true)
		return err
	}
	rc.NewResponderSPI = responderSPI
	rc.NewNonceN = append([]byte(nil), nr...)
	newSPIi := rc.NewInitiatorSPI
	newKeys, _, err := r.deriveIKERekeyKeys(rc, nr, ker, newSPIi, responderSPI, selection)
	if err != nil {
		r.abandonRekey(true)
		return err
	}

	// Preserve the old IKE SA context for the old-SA DELETE and keep it
	// decryptable until that exchange completes.
	oldCtx := OldIKEContext{
		InitiatorSPI:              st.InitiatorSPI,
		ResponderSPI:              st.ResponderSPI,
		IsOriginalInitiator:       st.IsOriginalInitiator,
		SelectedIKE:               st.SelectedIKE,
		IKEKeys:                   st.IKEKeys,
		NextRequestMessageID:      st.NextRequestMessageID,
		ExpectedResponseMessageID: st.ExpectedResponseMessageID,
		HasExpectedResponse:       false,
		OutboundRequest:           nil,
		InboundHistory:            append([]CachedResponse(nil), st.InboundHistory...),
		InboundFragments:          nil,
	}

	// Install the new IKE SA: fresh SPIs, nonces, keys and MID counters.
	st.InitiatorSPI = newSPIi
	st.ResponderSPI = responderSPI
	st.IsOriginalInitiator = true
	st.InitiatorNonce = append([]byte(nil), rc.Ni...)
	st.ResponderNonce = append([]byte(nil), nr...)
	st.IKEKeys = newKeys
	st.SelectedIKE = selection
	st.NextRequestMessageID = 0
	st.ExpectedResponseMessageID = 0
	st.HasExpectedResponse = false
	st.LastCompletedResponseMessageID = 0
	st.HasLastCompletedResponse = false
	st.OutboundRequest = nil
	st.InboundHistory = st.InboundHistory[:0]
	st.InboundFragments = nil
	st.SAInitRequest = nil
	st.SAInitResponse = nil
	st.OldIKE = append(st.OldIKE, oldCtx)
	st.Rekey = nil
	st.Phase = PhaseRekeyIkeDeletingOld
	r.resetIkeSoft()

	return r.sendOldIKEDelete(ctx, tx)
}

// sendOldIKEDelete starts the old IKE SA DELETE using the retained old
// context (old SPIs, old keys, old role, old message-id numbering).
func (r *Running) sendOldIKEDelete(ctx context.Context, tx chan<- *transport.Frame) error {
	st := r.state
	if len(st.OldIKE) == 0 {
		st.Phase = PhaseRunning
		return nil
	}
	old := &st.OldIKE[0]
	env := oldIKEEnvelope(old)
	msgID := old.NextRequestMessageID
	old.NextRequestMessageID++
	body := payload.AppendDelete(nil, payload.Delete{ProtocolID: wire.DeleteProtocolIKE})
	frames, err := buildProtectedEnvelopeAs(r.cfg, env, wire.ExchangeInformational, msgID, wire.PayloadTypeDelete, cepSinglePayload(body), requestFlags(env))
	if err != nil {
		return err
	}
	old.OutboundRequest = &Checkpoint{MessageID: msgID, Packets: frames}
	old.ExpectedResponseMessageID = msgID
	old.HasExpectedResponse = true
	return r.sendFrames(ctx, tx, frames)
}

// finishOldIKEDelete drops the retained old IKE context and returns to
// normal running state.
func (r *Running) finishOldIKEDelete() {
	if len(r.state.OldIKE) == 0 {
		r.state.Phase = PhaseRunning
		return
	}
	r.state.OldIKE = r.state.OldIKE[:0]
	r.state.Phase = PhaseRunning
}

// processOldIKEPacket handles packets addressed to the retained old IKE SA
// while its DELETE is outstanding. It uses the old context's own keys and
// MID numbering (RFC 7296 2.8.2).
func (r *Running) processOldIKEPacket(ctx context.Context, pkt *transport.Packet, msg *wire.Message, tx chan<- *transport.Frame) (shutdown bool, err error) {
	if len(r.state.OldIKE) == 0 {
		return false, nil
	}
	old := &r.state.OldIKE[0]
	if msg.Header.InitiatorSPI.Uint64() != old.InitiatorSPI || msg.Header.ResponderSPI.Uint64() != old.ResponderSPI {
		return false, nil
	}
	env := oldIKEEnvelope(old)

	if msg.Header.Flags&wire.FlagResponse != 0 {
		if err := validateResponseEnvelopeForRole(msg.Header, old.IsOriginalInitiator); err != nil {
			return false, nil
		}
		if !old.HasExpectedResponse || msg.Header.MessageID != old.ExpectedResponseMessageID {
			return false, nil
		}
		_, derr := openProtectedMessageEnvelope(env, pkt.Payload)
		if derr != nil {
			return false, derr
		}
		old.HasExpectedResponse = false
		old.OutboundRequest = nil
		r.finishOldIKEDelete()
		return false, nil
	}

	// Peer request on the old SA. The only request we expect in this
	// retained window is the peer's IKE DELETE for the old SA (peer as new
	// original initiator owns old-SA deletion in path 5.4).
	plds, derr := openProtectedMessageEnvelope(env, pkt.Payload)
	if derr != nil {
		return false, derr
	}
	if msg.Header.MessageID == 0 {
		return false, errors.New("control: old IKE SA request missing message-id")
	}
	if len(old.InboundHistory) > 0 {
		for i := range old.InboundHistory {
			if old.InboundHistory[i].MessageID == msg.Header.MessageID {
				return false, r.sendFrames(ctx, tx, old.InboundHistory[i].ResponsePackets)
			}
		}
	}
	if msg.Header.ExchangeType == wire.ExchangeInformational {
		ikeDelete := false
		for i := range plds {
			p := &plds[i]
			if p.Type != wire.PayloadTypeDelete {
				continue
			}
			d, parseErr := payload.ParseDelete(p.Body)
			if parseErr != nil {
				return false, parseErr
			}
			if d.ProtocolID == wire.DeleteProtocolIKE && len(d.SPIs) == 0 {
				ikeDelete = true
			}
		}
		frames, berr := buildProtectedEnvelopeAs(r.cfg, env, wire.ExchangeInformational, msg.Header.MessageID, wire.PayloadTypeNone, nil, responseFlags(env))
		if berr != nil {
			return false, berr
		}
		if err := r.sendFrames(ctx, tx, frames); err != nil {
			return false, err
		}
		old.InboundHistory = append(old.InboundHistory, CachedResponse{MessageID: msg.Header.MessageID, ResponsePackets: frames})
		if ikeDelete {
			r.finishOldIKEDelete()
		}
		return false, nil
	}
	return false, nil
}

// processCreateChild is the peer-request CREATE_CHILD_SA dispatcher. TSi or
// TSr presence means child rekey; SA protocol IKE and no TS means IKE
// rekey.
func (r *Running) processCreateChild(ctx context.Context, tx chan<- *transport.Frame, msg *wire.Message, inner []wire.Payload) error {
	hasTS := false
	for i := range inner {
		if inner[i].Type == wire.PayloadTypeTSi || inner[i].Type == wire.PayloadTypeTSr {
			hasTS = true
			break
		}
	}
	if !hasTS {
		return r.processPeerIKERekey(ctx, tx, msg, inner)
	}
	return r.processPeerChildRekey(ctx, tx, msg, inner)
}

// processPeerChildRekey accepts a peer-initiated CHILD_SA rekey and
// installs the responder-side child (make-before-break).
func (r *Running) processPeerChildRekey(ctx context.Context, tx chan<- *transport.Frame, msg *wire.Message, inner []wire.Payload) error {
	st := r.state
	old := st.ActiveChild

	// Locate and validate N(REKEY_SA).
	var rekeyNotify *payload.Notify
	for i := range inner {
		p := &inner[i]
		if p.Type != wire.PayloadTypeNotify {
			continue
		}
		n, err := payload.ParseNotify(p.Body)
		if err != nil {
			return err
		}
		if n.Type == wire.NotifyRekeySA {
			rekeyNotify = &n
			break
		}
	}
	if rekeyNotify == nil {
		return errors.New("control: peer child rekey missing REKEY_SA notify")
	}
	if rekeyNotify.ProtocolID != wire.DeleteProtocolESP || len(rekeyNotify.SPI) != 4 {
		return errors.New("control: malformed REKEY_SA notify in peer child rekey")
	}
	targetSPI := binary.BigEndian.Uint32(rekeyNotify.SPI)
	notFound := func(ctx context.Context, tx chan<- *transport.Frame, spi uint32) error {
		body := payload.AppendNotify(nil, payload.Notify{ProtocolID: wire.DeleteProtocolESP, SPI: appendU32(nil, spi), Type: wire.NotifyChildSANotFound})
		frames, err := buildProtectedStateAs(r.cfg, st, wire.ExchangeCreateChild, msg.Header.MessageID, wire.PayloadTypeNotify, cepSinglePayload(body), responseFlags(stateIKEEnvelope(st)))
		if err != nil {
			return err
		}
		if err := r.sendFrames(ctx, tx, frames); err != nil {
			return err
		}
		r.rememberResponse(msg.Header.MessageID, frames)
		return nil
	}
	// RFC 7296 2.8.1: the REKEY_SA SPI is the sender's inbound ESP SPI,
	// which is the receiver's outbound SPI for the existing child. Accept
	// both spellings so strongSwan-style and design-documented peers work.
	if old == nil || (targetSPI != old.OutboundSPI && targetSPI != old.InboundSPI) {
		return notFound(ctx, tx, targetSPI)
	}

	var saPayload *payload.SA
	var peerTSi, peerTSr []byte
	var peerNi []byte
	var peerKE []byte
	for i := range inner {
		p := &inner[i]
		switch p.Type {
		case wire.PayloadTypeSA:
			sa, err := payload.ParseSA(p.Body)
			if err != nil {
				return err
			}
			saPayload = &sa
		case wire.PayloadTypeNonce:
			n, err := payload.ParseNonce(p.Body)
			if err != nil {
				return err
			}
			peerNi = append([]byte(nil), n...)
		case wire.PayloadTypeKE:
			k, err := payload.ParseKE(p.Body)
			if err != nil {
				return err
			}
			if k.DHGroup != xcrypto.TransformDHCurve25519 {
				return fmt.Errorf("control: unsupported peer child rekey DH group %d", k.DHGroup)
			}
			peerKE = append([]byte(nil), k.Data...)
		case wire.PayloadTypeTSi:
			peerTSi = append([]byte(nil), p.Body...)
		case wire.PayloadTypeTSr:
			peerTSr = append([]byte(nil), p.Body...)
		}
	}
	if saPayload == nil || len(peerTSi) == 0 || len(peerTSr) == 0 || len(peerNi) == 0 {
		return errors.New("control: peer child rekey missing SA/TS/NONCE payload")
	}
	if !bytesEqual(peerTSi, old.TSr) || !bytesEqual(peerTSr, old.TSi) {
		return errors.New("control: peer child rekey selectors do not match the existing child")
	}

	if st.Rekey != nil && st.Rekey.Kind == RekeyChild {
		// Collision window: keep the old child installed and refuse with a
		// temporary failure so the peer retries after our own rekey settles.
		body := payload.AppendNotify(nil, payload.Notify{ProtocolID: wire.NotifyProtocolNone, Type: wire.NotifyTemporaryFailure})
		frames, err := buildProtectedStateAs(r.cfg, st, wire.ExchangeCreateChild, msg.Header.MessageID, wire.PayloadTypeNotify, cepSinglePayload(body), responseFlags(stateIKEEnvelope(st)))
		if err != nil {
			return err
		}
		if err := r.sendFrames(ctx, tx, frames); err != nil {
			return err
		}
		r.rememberResponse(msg.Header.MessageID, frames)
		return nil
	}

	responseSPI, err := generateChildSPI()
	if err != nil {
		return err
	}
	selected, selection, err := selectPeerESPProposal(r.cfg, *saPayload, responseSPI, len(peerKE) > 0)
	if err != nil {
		body := payload.AppendNotify(nil, payload.Notify{ProtocolID: wire.DeleteProtocolESP, SPI: appendU32(nil, targetSPI), Type: wire.NotifyNoProposalChosen})
		frames, ferr := buildProtectedStateAs(r.cfg, st, wire.ExchangeCreateChild, msg.Header.MessageID, wire.PayloadTypeNotify, cepSinglePayload(body), responseFlags(stateIKEEnvelope(st)))
		if ferr != nil {
			return ferr
		}
		if ferr := r.sendFrames(ctx, tx, frames); ferr != nil {
			return ferr
		}
		r.rememberResponse(msg.Header.MessageID, frames)
		return nil
	}

	ourNr, err := xcrypto.GenerateNonce(32)
	if err != nil {
		return err
	}
	var localDH *xcrypto.DHKey
	var kerPayload payload.KeyExchange
	var shared []byte
	if len(peerKE) > 0 {
		gen, err := generateRekeyDH()
		if err != nil {
			return err
		}
		localDH = gen.dh
		kerPayload = gen.ke
		shared, err = localDH.ECDH(peerKE)
		if err != nil {
			return err
		}
	}

	parts := []cesPayloadPart{{typ: wire.PayloadTypeSA, body: payload.AppendSA(nil, selected)}}
	parts = append(parts, cesPayloadPart{typ: wire.PayloadTypeNonce, body: payload.AppendNonce(nil, ourNr)})
	if len(peerKE) > 0 {
		parts = append(parts, cesPayloadPart{typ: wire.PayloadTypeKE, body: payload.AppendKE(nil, kerPayload)})
	}
	parts = append(parts,
		cesPayloadPart{typ: wire.PayloadTypeTSi, body: peerTSi},
		cesPayloadPart{typ: wire.PayloadTypeTSr, body: peerTSr},
	)
	plain := cesBuildChain(parts)
	frames, err := buildProtectedStateAs(r.cfg, st, wire.ExchangeCreateChild, msg.Header.MessageID, wire.PayloadTypeSA, plain, responseFlags(stateIKEEnvelope(st)))
	if err != nil {
		return err
	}

	keys, err := xcrypto.DeriveChildKeys(selection.PRF, r.state.IKEKeys.SKd, peerNi, ourNr, shared, selection.Encryption, selection.Integrity)
	if err != nil {
		return err
	}
	child := &ChildSA{
		InboundSPI:          responseSPI,
		OutboundSPI:         selectedPeerOutboundSPI(*saPayload),
		TSi:                 append([]byte(nil), peerTSr...),
		TSr:                 append([]byte(nil), peerTSi...),
		LocalChildInitiator: false,
	}
	if err := r.installChild(ctx, child, keys, selection); err != nil {
		return err
	}
	st.SelectedESP = selection
	st.OldChild = old
	st.ActiveChild = child
	r.resetChildSoft()

	if err := r.sendFrames(ctx, tx, frames); err != nil {
		return err
	}
	r.rememberResponse(msg.Header.MessageID, frames)
	return nil
}

// selectedPeerOutboundSPI returns the ESP SPI the peer proposed in its
// selected SA proposal (our new outbound SPI).
func selectedPeerOutboundSPI(sa payload.SA) uint32 {
	if len(sa.Proposals) == 0 || len(sa.Proposals[0].SPI) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(sa.Proposals[0].SPI)
}

// processPeerIKERekey accepts a peer-initiated IKE_SA rekey. After success
// the peer becomes the original initiator of the new IKE SA (RFC 7296
// 2.8.2), so our future requests omit FlagInitiator and use SKer/SKar.
func (r *Running) processPeerIKERekey(ctx context.Context, tx chan<- *transport.Frame, msg *wire.Message, inner []wire.Payload) error {
	st := r.state
	if st.Rekey != nil || len(st.OldIKE) > 0 {
		body := payload.AppendNotify(nil, payload.Notify{ProtocolID: wire.NotifyProtocolNone, Type: wire.NotifyTemporaryFailure})
		frames, err := buildProtectedStateAs(r.cfg, st, wire.ExchangeCreateChild, msg.Header.MessageID, wire.PayloadTypeNotify, cepSinglePayload(body), responseFlags(stateIKEEnvelope(st)))
		if err != nil {
			return err
		}
		if err := r.sendFrames(ctx, tx, frames); err != nil {
			return err
		}
		r.rememberResponse(msg.Header.MessageID, frames)
		return nil
	}

	var saPayload *payload.SA
	var peerNi, peerKE []byte
	for i := range inner {
		p := &inner[i]
		switch p.Type {
		case wire.PayloadTypeSA:
			sa, err := payload.ParseSA(p.Body)
			if err != nil {
				return err
			}
			saPayload = &sa
		case wire.PayloadTypeNonce:
			n, err := payload.ParseNonce(p.Body)
			if err != nil {
				return err
			}
			peerNi = append([]byte(nil), n...)
		case wire.PayloadTypeKE:
			k, err := payload.ParseKE(p.Body)
			if err != nil {
				return err
			}
			if k.DHGroup != xcrypto.TransformDHCurve25519 {
				return fmt.Errorf("control: unsupported peer IKE rekey DH group %d", k.DHGroup)
			}
			peerKE = append([]byte(nil), k.Data...)
		case wire.PayloadTypeTSi, wire.PayloadTypeTSr:
			return errors.New("control: unexpected TS payload in peer IKE rekey")
		}
	}
	if saPayload == nil || len(peerNi) == 0 || len(peerKE) == 0 {
		return errors.New("control: peer IKE rekey missing SA/NONCE/KE payload")
	}

	newResponderSPI, err := xcrypto.GenerateSPI()
	if err != nil {
		return err
	}
	selected, selection, peerInitiatorSPI, err := selectPeerIKEProposal(r.cfg, *saPayload, newResponderSPI)
	if err != nil {
		body := payload.AppendNotify(nil, payload.Notify{ProtocolID: wire.NotifyProtocolNone, Type: wire.NotifyNoProposalChosen})
		frames, ferr := buildProtectedStateAs(r.cfg, st, wire.ExchangeCreateChild, msg.Header.MessageID, wire.PayloadTypeNotify, cepSinglePayload(body), responseFlags(stateIKEEnvelope(st)))
		if ferr != nil {
			return ferr
		}
		if ferr := r.sendFrames(ctx, tx, frames); ferr != nil {
			return ferr
		}
		r.rememberResponse(msg.Header.MessageID, frames)
		return nil
	}

	ourNr, err := xcrypto.GenerateNonce(32)
	if err != nil {
		return err
	}
	gen, err := generateRekeyDH()
	if err != nil {
		return err
	}
	shared, err := gen.dh.ECDH(peerKE)
	if err != nil {
		return err
	}
	parts := []cesPayloadPart{
		{typ: wire.PayloadTypeSA, body: payload.AppendSA(nil, selected)},
		{typ: wire.PayloadTypeNonce, body: payload.AppendNonce(nil, ourNr)},
		{typ: wire.PayloadTypeKE, body: payload.AppendKE(nil, gen.ke)},
	}
	frames, err := buildProtectedStateAs(r.cfg, st, wire.ExchangeCreateChild, msg.Header.MessageID, wire.PayloadTypeSA, cesBuildChain(parts), responseFlags(stateIKEEnvelope(st)))
	if err != nil {
		return err
	}

	skeyseed, err := xcrypto.RekeySKEYSEED(st.SelectedIKE.PRF, st.IKEKeys.SKd, shared, peerNi, ourNr)
	if err != nil {
		return err
	}
	newKeys, err := xcrypto.DeriveIKEKeys(selection.PRF, skeyseed, peerNi, ourNr, peerInitiatorSPI, newResponderSPI, selection.Encryption, selection.Integrity)
	if err != nil {
		return err
	}

	oldCtx := OldIKEContext{
		InitiatorSPI:              st.InitiatorSPI,
		ResponderSPI:              st.ResponderSPI,
		IsOriginalInitiator:       st.IsOriginalInitiator,
		SelectedIKE:               st.SelectedIKE,
		IKEKeys:                   st.IKEKeys,
		NextRequestMessageID:      st.NextRequestMessageID,
		ExpectedResponseMessageID: st.ExpectedResponseMessageID,
		HasExpectedResponse:       false,
		OutboundRequest:           nil,
		InboundHistory:            append([]CachedResponse(nil), st.InboundHistory...),
	}

	// Send the response before installing so the frames use the current
	// (soon to be old) IKE SA keys; `rememberResponse` is deliberately on
	// the old context after install so retransmits on the old SPIs replay
	// this exact response.
	if err := r.sendFrames(ctx, tx, frames); err != nil {
		return err
	}

	st.InitiatorSPI = peerInitiatorSPI
	st.ResponderSPI = newResponderSPI
	st.IsOriginalInitiator = false
	st.InitiatorNonce = append([]byte(nil), peerNi...)
	st.ResponderNonce = append([]byte(nil), ourNr...)
	st.IKEKeys = newKeys
	st.SelectedIKE = selection
	st.NextRequestMessageID = 0
	st.ExpectedResponseMessageID = 0
	st.HasExpectedResponse = false
	st.LastCompletedResponseMessageID = 0
	st.HasLastCompletedResponse = false
	st.OutboundRequest = nil
	st.InboundHistory = st.InboundHistory[:0]
	st.InboundFragments = nil
	st.SAInitRequest = nil
	st.SAInitResponse = nil
	st.OldIKE = append(st.OldIKE, oldCtx)
	st.Rekey = nil
	st.Phase = PhaseRekeyIkeDeletingOld
	r.resetIkeSoft()

	old := &st.OldIKE[0]
	old.InboundHistory = append(old.InboundHistory, CachedResponse{MessageID: msg.Header.MessageID, ResponsePackets: frames})
	return nil
}

// selectPeerESPProposal picks the first peer ESP proposal compatible with
// cfg.ESP and builds the responder-selected SA with our new inbound SPI.
// wantsDH reports whether the peer included a KE payload; a no-KE request
// selects the same cipher without a DH transform and derives non-PFS keys.
func selectPeerESPProposal(cfg *Config, sa payload.SA, responseSPI uint32, wantsDH bool) (payload.SA, *xcrypto.Selection, error) {
	if cfg == nil || len(cfg.ESP) == 0 {
		return payload.SA{}, nil, errors.New("control: ESP proposals are required")
	}
	for pi := range sa.Proposals {
		prop := &sa.Proposals[pi]
		if prop.ProtocolID != wire.DeleteProtocolESP || len(prop.SPI) != 4 {
			continue
		}
		remote, ok := proposalFromWire(prop, false)
		if !ok {
			continue
		}
		for li := range cfg.ESP {
			// ESP proposals do not carry PRF on the wire; the PRF family is
			// inherited from the IKE SA. Supply the local suite's PRF before
			// reusing the standard Select machinery.
			remote.PRF = append(remote.PRF[:0], cfg.ESP[li].PRF...)
			// A no-KE child rekey has no DH transform on the wire. Match
			// the local cipher/PFS profile without requiring a DH group and
			// then strip the placeholder so the response omits DH as well.
			remoteHadDH := len(remote.DH) > 0
			if !remoteHadDH && len(cfg.ESP[li].DH) > 0 {
				remote.DH = append(remote.DH[:0], cfg.ESP[li].DH...)
			}
			sel, err := cfg.ESP[li].Select(remote)
			if err != nil {
				continue
			}
			if !wantsDH {
				sel.DH = nil
			}
			selected := responderSelectedESP(prop, responseSPI, sel)
			return selected, sel, nil
		}
	}
	return payload.SA{}, nil, errors.New("control: no compatible peer ESP proposal")
}

// selectPeerIKEProposal picks the first peer IKE proposal compatible with
// cfg.IKE and returns the selected SA, algorithms and peer's new initiator
// SPI.
func selectPeerIKEProposal(cfg *Config, sa payload.SA, responseSPI uint64) (payload.SA, *xcrypto.Selection, uint64, error) {
	if cfg == nil || len(cfg.IKE) == 0 {
		return payload.SA{}, nil, 0, errors.New("control: IKE proposals are required")
	}
	for pi := range sa.Proposals {
		prop := &sa.Proposals[pi]
		if prop.ProtocolID != wire.DeleteProtocolIKE || len(prop.SPI) != 8 {
			continue
		}
		peerSPI := binary.BigEndian.Uint64(prop.SPI)
		remote, ok := proposalFromWire(prop, true)
		if !ok {
			continue
		}
		for li := range cfg.IKE {
			sel, err := cfg.IKE[li].Select(remote)
			if err != nil {
				continue
			}
			selected := responderSelectedIKE(prop, responseSPI, sel)
			return selected, sel, peerSPI, nil
		}
	}
	return payload.SA{}, nil, 0, errors.New("control: no compatible peer IKE proposal")
}

// proposalFromWire converts a wire proposal body into xcrypto.Proposal for
// server-side selection. isIKE requires a DH transform and forbids ESN.
func proposalFromWire(prop *payload.Proposal, isIKE bool) (*xcrypto.Proposal, bool) {
	remote := &xcrypto.Proposal{}
	for _, t := range prop.Transforms {
		switch t.Type {
		case wire.TransformENC:
			bits, err := payload.ParseKeyLengthAttr(t.Attrs)
			if err != nil || bits == 0 || bits%8 != 0 {
				return nil, false
			}
			remote.Encryption = append(remote.Encryption, xcrypto.EncryptionID{TransformID: t.ID, KeyLen: bits / 8})
		case wire.TransformINTEG:
			if len(t.Attrs) != 0 {
				return nil, false
			}
			remote.Integrity = append(remote.Integrity, t.ID)
		case wire.TransformPRF:
			if !isIKE || len(t.Attrs) != 0 {
				return nil, false
			}
			remote.PRF = append(remote.PRF, t.ID)
		case wire.TransformDH:
			if len(t.Attrs) != 0 {
				return nil, false
			}
			remote.DH = append(remote.DH, t.ID)
		case wire.TransformESN:
			if isIKE || t.ID != wire.ESNNoExtendedSequenceNumbers {
				return nil, false
			}
		default:
			return nil, false
		}
	}
	if len(remote.Encryption) == 0 || (isIKE && len(remote.DH) == 0) {
		return nil, false
	}
	if isIKE && len(remote.PRF) == 0 {
		// Mirror ParseProposal's default: AEAD proposals default PRF from
		// the (absent) integrity family when possible. The MVP peer always
		// sends explicit PRF; fail rather than guess.
		return nil, false
	}
	return remote, true
}

// responderSelectedESP builds the responder's SA payload echoing the chosen
// peer transforms with our new inbound SPI.
func responderSelectedESP(peer *payload.Proposal, responseSPI uint32, sel *xcrypto.Selection) payload.SA {
	spi := make([]byte, 4)
	binary.BigEndian.PutUint32(spi, responseSPI)
	transforms := []payload.Transform{
		{Type: wire.TransformENC, ID: sel.Encryption.TransformID, Attrs: payload.KeyLengthAttr(uint16(sel.Encryption.TransformKeyLen * 8))},
	}
	if !sel.Encryption.AEAD {
		transforms = append(transforms, payload.Transform{Type: wire.TransformINTEG, ID: sel.Integrity.TransformID})
	}
	// The MVP peer offers NO_EXT_SEQ; echo it when the selected peer
	// proposal carried an ESN transform.
	for _, t := range peer.Transforms {
		if t.Type == wire.TransformESN && t.ID == wire.ESNNoExtendedSequenceNumbers {
			transforms = append(transforms, payload.Transform{Type: wire.TransformESN, ID: wire.ESNNoExtendedSequenceNumbers})
			break
		}
	}
	if sel.DH != nil {
		transforms = append(transforms, payload.Transform{Type: wire.TransformDH, ID: sel.DH.TransformID})
	}
	return payload.SA{Proposals: []payload.Proposal{{
		Num:        peer.Num,
		ProtocolID: wire.DeleteProtocolESP,
		SPI:        spi,
		Transforms: transforms,
	}}}
}

// responderSelectedIKE builds the responder's IKE SA payload echoing the
// chosen peer transforms with the new responder SPI.
func responderSelectedIKE(peer *payload.Proposal, responseSPI uint64, sel *xcrypto.Selection) payload.SA {
	spi := make([]byte, 8)
	binary.BigEndian.PutUint64(spi, responseSPI)
	transforms := []payload.Transform{
		{Type: wire.TransformENC, ID: sel.Encryption.TransformID, Attrs: payload.KeyLengthAttr(uint16(sel.Encryption.TransformKeyLen * 8))},
	}
	if !sel.Encryption.AEAD {
		transforms = append(transforms, payload.Transform{Type: wire.TransformINTEG, ID: sel.Integrity.TransformID})
	}
	transforms = append(transforms, payload.Transform{Type: wire.TransformPRF, ID: sel.PRF.TransformID})
	transforms = append(transforms, payload.Transform{Type: wire.TransformDH, ID: sel.DH.TransformID})
	return payload.SA{Proposals: []payload.Proposal{{
		Num:        peer.Num,
		ProtocolID: wire.DeleteProtocolIKE,
		SPI:        spi,
		Transforms: transforms,
	}}}
}

// armTimer safely resets a timer and returns its channel; it is kept here
// so the Running select loop only ever observes reset timer channels.
func armTimer(t *time.Timer, d time.Duration) {
	if t == nil {
		return
	}
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

var _ = transport.KindIKE
