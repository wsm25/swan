package control

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"

	"swan/transport"
	"swan/wire"
	"swan/wire/payload"
	"swan/xcrypto"
)

// Rekey helpers: wire builders, response parsers, key derivation and the
// pure trigger/timer arithmetic. The Running actor owns all state mutation;
// the builders here only construct frames and derived material.

// generateChildSPI returns a random non-zero 32-bit inbound ESP SPI.
func generateChildSPI() (uint32, error) {
	raw, err := xcrypto.GenerateNonce(4)
	if err != nil {
		return 0, fmt.Errorf("control: generate child SPI: %w", err)
	}
	spi := binary.BigEndian.Uint32(raw)
	if spi == 0 {
		spi = 1
	}
	return spi, nil
}

// rekeyDeadline returns now + lifetime - random jitter in [0, jitterCap].
// jitterCap <= 0 derives 10% of the lifetime (the accepted default).
func rekeyDeadline(now time.Time, lifetime, jitterCap time.Duration) time.Duration {
	jitter := jitterCap
	if jitter <= 0 {
		jitter = lifetime / 10
	}
	if jitter < 0 || jitter > lifetime {
		jitter = lifetime / 10
	}
	d := lifetime - jitter
	if d < 0 {
		d = lifetime
	}
	if jitter > 0 {
		d += time.Duration(rand.Int63n(int64(jitter)))
	}
	if d < lifetime/2 {
		d = lifetime / 2
	}
	return time.Until(now.Add(d))
}

// retryBackoff returns RetryInterval with +-20% jitter.
func retryBackoff(base time.Duration) time.Duration {
	if base <= 0 {
		base = 30 * time.Second
	}
	jitter := base / 5
	if jitter <= 0 {
		jitter = time.Second
	}
	return base - jitter + time.Duration(rand.Int63n(2*int64(jitter)+1))
}

// appendESPProposalsForRekey serializes the local ESP offers for a
// CREATE_CHILD_SA child rekey. includeDH appends each proposal's DH
// transforms (RFC 7296 2.17 PFS).
func (r *Running) appendESPProposalsForRekey(dst []byte, spi uint32, includeDH bool) ([]byte, error) {
	offers, err := childOffers(r.cfg)
	if err != nil {
		return nil, err
	}
	spiBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(spiBytes, spi)

	var sa payload.SA
	for i := range offers {
		transforms, err := childProposalTransforms(offers[i], includeDH)
		if err != nil {
			return nil, err
		}
		sa.Proposals = append(sa.Proposals, payload.Proposal{
			Num:        uint8(i + 1),
			ProtocolID: wire.DeleteProtocolESP,
			SPI:        append([]byte(nil), spiBytes...),
			Transforms: transforms,
		})
	}
	return payload.AppendSA(dst, sa), nil
}

// appendIKEProposalsWithSPI serializes cfg.IKE as SA payload body with a
// proposal SPI field (RFC 7296 2.18 for IKE rekey).
func (r *Running) appendIKEProposalsWithSPI(dst []byte, spi uint64) ([]byte, error) {
	if r.cfg == nil || len(r.cfg.IKE) == 0 {
		return nil, fmt.Errorf("control: IKE proposals are required")
	}
	var spiBytes [8]byte
	binary.BigEndian.PutUint64(spiBytes[:], spi)
	var sa payload.SA
	for num, suite := range r.cfg.IKE {
		var transforms []payload.Transform
		aead := false
		for _, enc := range suite.Encryption {
			alg, err := xcrypto.NewEncryption(enc.TransformID, enc.KeyLen)
			if err != nil {
				return nil, err
			}
			aead = aead || alg.AEAD
			attrs := payload.KeyLengthAttr(uint16(alg.TransformKeyLen * 8))
			transforms = append(transforms, payload.Transform{Type: wire.TransformENC, ID: enc.TransformID, Attrs: attrs})
		}
		for _, prf := range suite.PRF {
			transforms = append(transforms, payload.Transform{Type: wire.TransformPRF, ID: prf})
		}
		if !aead {
			for _, integ := range suite.Integrity {
				transforms = append(transforms, payload.Transform{Type: wire.TransformINTEG, ID: integ})
			}
		}
		for _, dh := range suite.DH {
			transforms = append(transforms, payload.Transform{Type: wire.TransformDH, ID: dh})
		}
		sa.Proposals = append(sa.Proposals, payload.Proposal{
			Num:        uint8(num + 1),
			ProtocolID: wire.DeleteProtocolIKE,
			SPI:        append([]byte(nil), spiBytes[:]...),
			Transforms: transforms,
		})
	}
	return payload.AppendSA(dst, sa), nil
}

// buildChildRekeyRequestPayloads renders the initiator child-rekey
// plaintext chain and fills the RekeyContext with the fresh nonce/KE state.
func (r *Running) buildChildRekeyRequestPayloads(rc *RekeyContext) ([]byte, error) {
	if r.state.ActiveChild == nil {
		return nil, fmt.Errorf("control: child rekey without an active child SA")
	}
	ni, err := xcrypto.GenerateNonce(32)
	if err != nil {
		return nil, fmt.Errorf("control: generate child rekey nonce: %w", err)
	}
	rc.Ni = ni

	parts := []cesPayloadPart{
		{
			typ: wire.PayloadTypeNotify,
			body: payload.AppendNotify(nil, payload.Notify{
				ProtocolID: wire.DeleteProtocolESP,
				SPI:        appendU32(nil, r.state.ActiveChild.InboundSPI),
				Type:       wire.NotifyRekeySA,
			}),
		},
	}

	sa, err := r.appendESPProposalsForRekey(nil, rc.NewChild.InboundSPI, r.cfg.Rekey.ChildPFS)
	if err != nil {
		return nil, err
	}
	parts = append(parts,
		cesPayloadPart{typ: wire.PayloadTypeSA, body: sa},
		cesPayloadPart{typ: wire.PayloadTypeNonce, body: payload.AppendNonce(nil, ni)},
	)

	if r.cfg.Rekey.ChildPFS {
		ke, err := generateRekeyDH()
		if err != nil {
			return nil, err
		}
		rc.LocalDH = ke.dh
		rc.LocalKE = &ke.ke
		parts = append(parts, cesPayloadPart{typ: wire.PayloadTypeKE, body: payload.AppendKE(nil, ke.ke)})
	}

	parts = append(parts,
		cesPayloadPart{typ: wire.PayloadTypeTSi, body: append([]byte(nil), r.state.ActiveChild.TSi...)},
		cesPayloadPart{typ: wire.PayloadTypeTSr, body: append([]byte(nil), r.state.ActiveChild.TSr...)},
	)
	return cesBuildChain(parts), nil
}

// buildIKERekeyRequestPayloads renders the initiator IKE-rekey plaintext
// chain and fills the RekeyContext with the fresh nonce/KE/SPIi state.
func (r *Running) buildIKERekeyRequestPayloads(rc *RekeyContext) ([]byte, error) {
	ni, err := xcrypto.GenerateNonce(32)
	if err != nil {
		return nil, fmt.Errorf("control: generate IKE rekey nonce: %w", err)
	}
	spiI, err := xcrypto.GenerateSPI()
	if err != nil {
		return nil, fmt.Errorf("control: generate new initiator SPI: %w", err)
	}
	ke, err := generateRekeyDH()
	if err != nil {
		return nil, err
	}

	rc.Ni = ni
	rc.NewInitiatorSPI = spiI
	rc.LocalDH = ke.dh
	rc.LocalKE = &ke.ke

	sa, err := r.appendIKEProposalsWithSPI(nil, spiI)
	if err != nil {
		return nil, err
	}
	return cesBuildChain([]cesPayloadPart{
		{typ: wire.PayloadTypeSA, body: sa},
		{typ: wire.PayloadTypeNonce, body: payload.AppendNonce(nil, ni)},
		{typ: wire.PayloadTypeKE, body: payload.AppendKE(nil, ke.ke)},
	}), nil
}

type generatedRekeyDH struct {
	dh *xcrypto.DHKey
	ke payload.KeyExchange
}

func generateRekeyDH() (generatedRekeyDH, error) {
	dh, err := xcrypto.GenerateDH(xcrypto.TransformDHCurve25519)
	if err != nil {
		return generatedRekeyDH{}, fmt.Errorf("control: generate rekey DH: %w", err)
	}
	pub, err := dh.PublicBytes()
	if err != nil {
		return generatedRekeyDH{}, fmt.Errorf("control: encode rekey KE: %w", err)
	}
	return generatedRekeyDH{dh: dh, ke: payload.KeyExchange{DHGroup: xcrypto.TransformDHCurve25519, Data: pub}}, nil
}

// childRekeyResponse is the validated CREATE_CHILD_SA child-rekey
// response content.
type childRekeyResponse struct {
	PeerSPI   uint32
	Nr        []byte
	KEr       []byte
	TSi       []byte
	TSr       []byte
	SA        payload.SA
	Selection *xcrypto.Selection
}

// parseChildRekeyResponse parses a CREATE_CHILD_SA child-rekey response.
// It returns peer SPI, nonce, optional DH public bytes, TSi/TSr bodies and
// the selected algorithms.
func (r *Running) parseChildRekeyResponse(inner []wire.Payload) (childRekeyResponse, error) {
	var out childRekeyResponse
	var sa *payload.SA
	seenSA := false
	seenNonce := false
	seenKE := false
	for i := range inner {
		p := &inner[i]
		switch p.Type {
		case wire.PayloadTypeSA:
			if seenSA {
				return out, fmt.Errorf("control: duplicate SA payload in child rekey response")
			}
			parsed, parseErr := payload.ParseSA(p.Body)
			if parseErr != nil {
				return out, parseErr
			}
			sa = &parsed
			seenSA = true
		case wire.PayloadTypeNonce:
			if seenNonce {
				return out, fmt.Errorf("control: duplicate NONCE payload in child rekey response")
			}
			parsed, parseErr := payload.ParseNonce(p.Body)
			if parseErr != nil {
				return out, parseErr
			}
			out.Nr = append([]byte(nil), parsed...)
			seenNonce = true
		case wire.PayloadTypeKE:
			if seenKE {
				return out, fmt.Errorf("control: duplicate KE payload in child rekey response")
			}
			parsed, parseErr := payload.ParseKE(p.Body)
			if parseErr != nil {
				return out, parseErr
			}
			if parsed.DHGroup != xcrypto.TransformDHCurve25519 {
				return out, fmt.Errorf("control: unsupported child rekey DH group %d", parsed.DHGroup)
			}
			out.KEr = append([]byte(nil), parsed.Data...)
			seenKE = true
		case wire.PayloadTypeTSi:
			out.TSi = append([]byte(nil), p.Body...)
		case wire.PayloadTypeTSr:
			out.TSr = append([]byte(nil), p.Body...)
		case wire.PayloadTypeAuth, wire.PayloadTypeEAP:
			return out, fmt.Errorf("control: AUTH/EAP is forbidden in a rekey response")
		default:
			// Notifies are handled by the caller before this parser when
			// they carry error conditions; ignore other payloads.
		}
	}
	if sa == nil {
		return out, fmt.Errorf("control: child rekey response missing SA payload")
	}
	if !seenNonce {
		return out, fmt.Errorf("control: child rekey response missing NONCE payload")
	}
	if len(out.TSi) == 0 || len(out.TSr) == 0 {
		return out, fmt.Errorf("control: child rekey response missing TSi/TSr payload")
	}
	if !r.cfg.Rekey.ChildPFS && seenKE {
		return out, fmt.Errorf("control: unexpected KE payload in non-PFS child rekey response")
	}
	if r.cfg.Rekey.ChildPFS && !seenKE {
		return out, fmt.Errorf("control: PFS child rekey response missing KE payload")
	}
	peerSPI, selection, err := (&Handshake{cfg: r.cfg, state: r.state}).decodeChildSelection(*sa)
	if err != nil {
		return out, err
	}
	out.PeerSPI = peerSPI
	out.SA = *sa
	out.Selection = selection
	return out, nil
}

// parseIKERekeyResponse parses a CREATE_CHILD_SA IKE-rekey response:
// exactly one selected IKE proposal carrying the responder's new SPI, Nr
// and KEr. No TSi/TSr/AUTH/EAP is allowed.
func (r *Running) parseIKERekeyResponse(inner []wire.Payload) (selection *xcrypto.Selection, responderSPI uint64, nr, ker []byte, err error) {
	var sa *payload.SA
	var nonce []byte
	for i := range inner {
		p := &inner[i]
		switch p.Type {
		case wire.PayloadTypeSA:
			if sa != nil {
				return nil, 0, nil, nil, fmt.Errorf("control: duplicate SA payload in IKE rekey response")
			}
			parsed, parseErr := payload.ParseSA(p.Body)
			if parseErr != nil {
				return nil, 0, nil, nil, parseErr
			}
			sa = &parsed
		case wire.PayloadTypeNonce:
			if nonce != nil {
				return nil, 0, nil, nil, fmt.Errorf("control: duplicate NONCE payload in IKE rekey response")
			}
			parsed, parseErr := payload.ParseNonce(p.Body)
			if parseErr != nil {
				return nil, 0, nil, nil, parseErr
			}
			nonce = append([]byte(nil), parsed...)
		case wire.PayloadTypeKE:
			if ker != nil {
				return nil, 0, nil, nil, fmt.Errorf("control: duplicate KE payload in IKE rekey response")
			}
			parsed, parseErr := payload.ParseKE(p.Body)
			if parseErr != nil {
				return nil, 0, nil, nil, parseErr
			}
			if parsed.DHGroup != xcrypto.TransformDHCurve25519 {
				return nil, 0, nil, nil, fmt.Errorf("control: unsupported IKE rekey DH group %d", parsed.DHGroup)
			}
			ker = append([]byte(nil), parsed.Data...)
		case wire.PayloadTypeTSi, wire.PayloadTypeTSr, wire.PayloadTypeAuth, wire.PayloadTypeEAP:
			return nil, 0, nil, nil, fmt.Errorf("control: unexpected payload type %d in IKE rekey response", uint8(p.Type))
		}
	}
	if sa == nil {
		return nil, 0, nil, nil, fmt.Errorf("control: IKE rekey response missing SA payload")
	}
	if nonce == nil {
		return nil, 0, nil, nil, fmt.Errorf("control: IKE rekey response missing NONCE payload")
	}
	if ker == nil {
		return nil, 0, nil, nil, fmt.Errorf("control: IKE rekey response missing KE payload")
	}
	if len(sa.Proposals) != 1 {
		return nil, 0, nil, nil, fmt.Errorf("control: IKE rekey response must contain exactly one selected proposal")
	}
	if len(sa.Proposals) != 1 {
		return nil, 0, nil, nil, fmt.Errorf("control: IKE rekey response must contain exactly one selected proposal")
	}
	// decodeIKESelectionWithSPI both validates the echoed proposal against
	// the local offer list and extracts the responder's new SPI.
	h := &Handshake{cfg: r.cfg, state: r.state}
	spi, sel, err := h.decodeIKESelectionWithSPI(*sa)
	if err != nil {
		return nil, 0, nil, nil, err
	}
	return sel, spi, nonce, ker, nil
}

// deriveChildRekeyKeys derives the new CHILD_SA keys after the response.
func (r *Running) deriveChildRekeyKeys(rc *RekeyContext, peerNr, peerKE []byte, selection *xcrypto.Selection) (*xcrypto.ChildKeys, error) {
	if r.state.IKEKeys == nil {
		return nil, fmt.Errorf("control: IKE key material is missing")
	}
	var shared []byte
	if r.cfg.Rekey.ChildPFS {
		if rc.LocalDH == nil || len(peerKE) == 0 {
			return nil, fmt.Errorf("control: missing DH material for PFS child rekey")
		}
		secret, err := rc.LocalDH.ECDH(peerKE)
		rc.LocalDH = nil
		if err != nil {
			return nil, fmt.Errorf("control: derive child rekey DH secret: %w", err)
		}
		shared = secret
	}
	return xcrypto.DeriveChildKeys(
		r.state.SelectedIKE.PRF,
		r.state.IKEKeys.SKd,
		rc.Ni,
		peerNr,
		shared,
		selection.Encryption,
		selection.Integrity,
	)
}

// deriveIKERekeyKeys derives new IKE key material per RFC 7296 2.18.
func (r *Running) deriveIKERekeyKeys(rc *RekeyContext, peerNr, peerKE []byte, newSPIi, newSPIr uint64, newSelection *xcrypto.Selection) (*xcrypto.IKEKeys, []byte, error) {
	if rc.LocalDH == nil {
		return nil, nil, fmt.Errorf("control: missing IKE rekey DH keypair")
	}
	shared, err := rc.LocalDH.ECDH(peerKE)
	rc.LocalDH = nil
	if err != nil {
		return nil, nil, fmt.Errorf("control: derive IKE rekey DH secret: %w", err)
	}
	skeyseed, err := xcrypto.RekeySKEYSEED(r.state.SelectedIKE.PRF, r.state.IKEKeys.SKd, shared, rc.Ni, peerNr)
	if err != nil {
		return nil, nil, fmt.Errorf("control: derive IKE rekey SKEYSEED: %w", err)
	}
	keys, err := xcrypto.DeriveIKEKeys(newSelection.PRF, skeyseed, rc.Ni, peerNr, newSPIi, newSPIr, newSelection.Encryption, newSelection.Integrity)
	if err != nil {
		return nil, nil, fmt.Errorf("control: derive IKE rekey keys: %w", err)
	}
	return keys, skeyseed, nil
}

// appendU32 writes a 4-byte big-endian integer.
func appendU32(dst []byte, v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return append(dst, b[:]...)
}

var _ = transport.KindIKE
