package control

import (
	"encoding/binary"
	"fmt"
	"net"

	"swan/transport"
	"swan/wire"
	"swan/wire/payload"
	"swan/xcrypto"
)

// SA_INIT stage (RFC 7296 1.2 / 2.x):
//   - build request: SA proposals, KE, Ni nonce, NAT-D SRC/DST, and the
//     FRAGMENTATION_SUPPORTED + SIGNATURE_HASH_ALGORITHMS notifies;
//   - apply response: validate SPI/nonce/KE, decode selected proposal,
//     track NAT-D verdict and peer capabilities;
//   - retry on COOKIE (repeat with cookie notify) and INVALID_KE_PAYLOAD
//     (repeat with the requested DH group), at most MaxSAInitAttempts.

// MaxSAInitAttempts bounds total SA_INIT exchanges: initial attempt plus
// two retries (swan2 behavior).
const MaxSAInitAttempts = 3

// SAInitOutcome reports how the response was applied.
type SAInitOutcome uint8

const (
	SAInitEstablished SAInitOutcome = iota
	SAInitRetryCookie
	SAInitRetryDHGroup
)

// signatureHashAlgorithmsNotify advertises SHA2-256/384/512 (ids 2/3/4).
var signatureHashAlgorithmsNotify = []byte{0x00, 0x02, 0x00, 0x03, 0x00, 0x04}

// buildSAInitRequest renders one complete IKE_SA_INIT request for the given
// forced DH group (0 = none); it also records SPIi, Ni, KE and the chosen
// proposal suite in the state for later AUTH octets.
func (h *Handshake) buildSAInitRequest(forcedDHGroup uint16) ([]*transport.Frame, error) {
	suite, selection, err := h.selectIKESuite(forcedDHGroup)
	if err != nil {
		return nil, err
	}
	h.state.SelectedIKE = selection

	if h.state.InitiatorSPI == 0 {
		v, err := xcrypto.GenerateSPI()
		if err != nil {
			return nil, fmt.Errorf("control: generate initiator SPI: %w", err)
		}
		h.state.InitiatorSPI = v
	}
	if len(h.state.InitiatorNonce) == 0 {
		ni, err := xcrypto.GenerateNonce(32)
		if err != nil {
			return nil, fmt.Errorf("control: generate initiator nonce: %w", err)
		}
		h.state.InitiatorNonce = ni
	}

	// KE is generated fresh for every SA_INIT build (including COOKIE
	// retries), exactly like swan2 build_ike_sa_init_request.
	dh, err := xcrypto.GenerateDH(selection.DH.TransformID)
	if err != nil {
		return nil, fmt.Errorf("control: generate local KE: %w", err)
	}
	pub, err := dh.PublicBytes()
	if err != nil {
		return nil, fmt.Errorf("control: encode local KE: %w", err)
	}
	h.state.LocalDH = dh
	h.state.InitiatorKE = payload.KeyExchange{DHGroup: selection.DH.TransformID, Data: pub}

	// NAT-D hashes: logical NAT-T port 4500, never a real socket port.
	// The request is sent before the responder SPI exists, so it is zero in
	// the NAT-D computation (RFC 3947/7383).
	srcHash, dstHash, err := h.localNATHashes(0)
	if err != nil {
		return nil, err
	}
	h.state.NAT.SourceHashLocal = srcHash
	h.state.NAT.DestinationHashLocal = dstHash

	pkt, err := h.buildSAInitPacket(suite)
	if err != nil {
		return nil, err
	}
	h.state.SAInitRequest = append([]byte(nil), pkt...)
	return []*transport.Frame{{Kind: transport.KindIKE, Payload: pkt}}, nil
}

// selectIKESuite picks the local IKE proposal for this attempt. A forced
// non-zero DH group (INVALID_KE_PAYLOAD retry) must be present in the
// chosen suite. Returned suite is used to re-derive transform shapes.
func (h *Handshake) selectIKESuite(forcedDHGroup uint16) (*xcrypto.Proposal, *xcrypto.Selection, error) {
	if h.cfg == nil || len(h.cfg.IKE) == 0 {
		return nil, nil, fmt.Errorf("control: IKE proposals are required")
	}
	var suite *xcrypto.Proposal
	if forcedDHGroup != 0 {
		for i := range h.cfg.IKE {
			for _, dh := range h.cfg.IKE[i].DH {
				if dh == forcedDHGroup {
					suite = &h.cfg.IKE[i]
					break
				}
			}
			if suite != nil {
				break
			}
		}
		if suite == nil {
			return nil, nil, fmt.Errorf("control: peer requested unsupported DH group %d", forcedDHGroup)
		}
	} else {
		suite = &h.cfg.IKE[0]
	}

	selection, err := suite.Select(suite)
	if err != nil {
		return nil, nil, fmt.Errorf("control: select IKE proposal: %w", err)
	}
	return suite, selection, nil
}

// buildSAInitPacket lays out the payload chain and returns the wire bytes.
func (h *Handshake) buildSAInitPacket(suite *xcrypto.Proposal) ([]byte, error) {
	b := wire.NewBuilder(wire.Header{
		InitiatorSPI: wire.Uint64SPI(h.state.InitiatorSPI),
		ResponderSPI: wire.SPI{},
		NextPayload:  wire.PayloadTypeNone,
		Version:      wire.IKEDefaultVersion,
		ExchangeType: wire.ExchangeIkeSAInit,
		Flags:        wire.FlagInitiator,
		MessageID:    0,
	})

	if len(h.state.Cookie) > 0 {
		if err := b.Push(wire.PayloadTypeNotify, false, payload.AppendNotify(nil, payload.Notify{
			ProtocolID: wire.NotifyProtocolNone,
			Type:       wire.NotifyCookie,
			Data:       h.state.Cookie,
		})); err != nil {
			return nil, err
		}
	}

	saBody, err := h.appendIKEProposals(nil)
	if err != nil {
		return nil, err
	}
	if err := b.Push(wire.PayloadTypeSA, false, saBody); err != nil {
		return nil, err
	}
	if err := b.Push(wire.PayloadTypeKE, false, payload.AppendKE(nil, h.state.InitiatorKE)); err != nil {
		return nil, err
	}
	if err := b.Push(wire.PayloadTypeNonce, false, payload.AppendNonce(nil, h.state.InitiatorNonce)); err != nil {
		return nil, err
	}

	appends := []struct {
		t    wire.NotifyType
		data []byte
	}{
		{wire.NotifyNATDetectionSourceIP, h.state.NAT.SourceHashLocal},
		{wire.NotifyNATDetectionDestinationIP, h.state.NAT.DestinationHashLocal},
		{wire.NotifyFragmentationSupported, nil},
		{wire.NotifySignatureHashAlgorithms, signatureHashAlgorithmsNotify},
	}
	for _, n := range appends {
		body := payload.AppendNotify(nil, payload.Notify{ProtocolID: wire.NotifyProtocolNone, Type: n.t, Data: n.data})
		if err := b.Push(wire.PayloadTypeNotify, false, body); err != nil {
			return nil, err
		}
	}
	return b.Finish(), nil
}

// appendIKEProposals serializes cfg.IKE as SA payload body. AEAD suites omit
// integrity transforms; CBC suites include them. The DH transform closes the
// chain, which AppendProposal marks Last.
func (h *Handshake) appendIKEProposals(dst []byte) ([]byte, error) {
	if h.cfg == nil || len(h.cfg.IKE) == 0 {
		return nil, fmt.Errorf("control: IKE proposals are required")
	}
	var sa payload.SA
	for num, suite := range h.cfg.IKE {
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
			Transforms: transforms,
		})
	}
	return payload.AppendSA(dst, sa), nil
}

// applySAInitResponse validates and absorbs one IKE_SA_INIT response:
// COOKIE/INVALID_KE_PAYLOAD produce the matching retry outcome, everything
// else must constitute a complete response (SA + Nr + KE + NAT-D verdict).
func (h *Handshake) applySAInitResponse(m *wire.Message) (SAInitOutcome, error) {
	responderSPI := m.Header.ResponderSPI.Uint64()
	if responderSPI == 0 {
		if len(m.Payloads) == 0 || m.Payloads[0].Type != wire.PayloadTypeNotify {
			return 0, fmt.Errorf("control: IKE_SA_INIT without responder SPI must start with a NOTIFY")
		}
	}

	// swan2 discards the previous attempt's NAT-D hashes and peer capability
	// flags before absorbing a new SA_INIT response.
	h.state.NAT.SourceHashRemote = nil
	h.state.NAT.DestinationHashRemote = nil
	h.state.Peer = PeerCapabilities{}

	var (
		sawSA        bool
		sawKE        bool
		sawNonce     bool
		cookie       []byte
		hasInvalidKE bool
		saPayload    payload.SA
		nonce        []byte
		ke           payload.KeyExchange
	)

	for i := range m.Payloads {
		p := &m.Payloads[i]
		switch p.Type {
		case wire.PayloadTypeSA:
			if sawSA {
				return 0, fmt.Errorf("control: duplicate SA payload in IKE_SA_INIT response")
			}
			sa, err := payload.ParseSA(p.Body)
			if err != nil {
				return 0, fmt.Errorf("control: parse IKE_SA_INIT SA: %w", err)
			}
			if len(sa.Proposals) != 1 {
				return 0, fmt.Errorf("control: IKE_SA_INIT response must contain exactly one selected proposal")
			}
			saPayload = sa
			sawSA = true
		case wire.PayloadTypeNonce:
			if sawNonce {
				return 0, fmt.Errorf("control: duplicate NONCE payload in IKE_SA_INIT response")
			}
			n, err := payload.ParseNonce(p.Body)
			if err != nil {
				return 0, fmt.Errorf("control: parse IKE_SA_INIT nonce: %w", err)
			}
			nonce = append([]byte(nil), n...)
			sawNonce = true
		case wire.PayloadTypeKE:
			if sawKE {
				return 0, fmt.Errorf("control: duplicate KEE payload in IKE_SA_INIT response")
			}
			k, err := payload.ParseKE(p.Body)
			if err != nil {
				return 0, fmt.Errorf("control: parse IKE_SA_INIT KE: %w", err)
			}
			k.Data = append([]byte(nil), k.Data...)
			ke = k
			sawKE = true
		case wire.PayloadTypeNotify:
			n, err := payload.ParseNotify(p.Body)
			if err != nil {
				return 0, fmt.Errorf("control: parse IKE_SA_INIT notify: %w", err)
			}
			switch n.Type {
			case wire.NotifyCookie:
				if len(n.SPI) != 0 || len(n.Data) == 0 {
					return 0, fmt.Errorf("control: COOKIE notify must not carry SPI and must carry data")
				}
				if len(cookie) > 0 {
					return 0, fmt.Errorf("control: duplicate COOKIE notify")
				}
				cookie = append([]byte(nil), n.Data...)
			case wire.NotifyInvalidKePayload:
				if n.ProtocolID != wire.NotifyProtocolNone || len(n.SPI) != 0 || len(n.Data) != 2 {
					return 0, fmt.Errorf("control: INVALID_KE_PAYLOAD notify must use protocol 0 and carry exactly one DH group")
				}
				if hasInvalidKE {
					return 0, fmt.Errorf("control: duplicate INVALID_KE_PAYLOAD notify")
				}
				hasInvalidKE = true
			case wire.NotifyNATDetectionSourceIP:
				if n.ProtocolID != wire.NotifyProtocolNone || len(n.SPI) != 0 {
					return 0, fmt.Errorf("control: NAT_DETECTION_SOURCE_IP must use protocol 0 and must not carry SPI")
				}
				h.state.NAT.SourceHashRemote = append([]byte(nil), n.Data...)
			case wire.NotifyNATDetectionDestinationIP:
				if n.ProtocolID != wire.NotifyProtocolNone || len(n.SPI) != 0 {
					return 0, fmt.Errorf("control: NAT_DETECTION_DESTINATION_IP must use protocol 0 and must not carry SPI")
				}
				h.state.NAT.DestinationHashRemote = append([]byte(nil), n.Data...)
			case wire.NotifyFragmentationSupported:
				if n.ProtocolID != wire.NotifyProtocolNone || len(n.SPI) != 0 {
					return 0, fmt.Errorf("control: FRAGMENTATION_SUPPORTED must use protocol 0 and must not carry SPI")
				}
				h.state.Peer.SupportsFragmentation = true
			case wire.NotifySignatureHashAlgorithms:
				if n.ProtocolID != wire.NotifyProtocolNone || len(n.SPI) != 0 {
					return 0, fmt.Errorf("control: SIGNATURE_HASH_ALGORITHMS must use protocol 0 and must not carry SPI")
				}
				hashes, err := parseSignatureHashAlgorithms(n.Data)
				if err != nil {
					return 0, err
				}
				h.state.Auth.PeerSignatureHashAlgorithms = hashes
			case wire.NotifyNoProposalChosen:
				return 0, fmt.Errorf("control: peer rejected IKE proposal (NO_PROPOSAL_CHOSEN)")
			default:
				if n.Type < 16384 {
					return 0, fmt.Errorf("control: received IKE_SA_INIT error notify %d", uint16(n.Type))
				}
			}
		}
	}

	if len(cookie) > 0 || hasInvalidKE {
		if len(cookie) > 0 && hasInvalidKE {
			return 0, fmt.Errorf("control: COOKIE and INVALID_KE_PAYLOAD cannot both require a retry")
		}
		if sawSA || sawKE || sawNonce {
			return 0, fmt.Errorf("control: retry IKE_SA_INIT response must not include SA/KE/NONCE")
		}
		if len(cookie) > 0 {
			h.state.Cookie = cookie
			return SAInitRetryCookie, nil
		}
		h.state.Cookie = nil
		return SAInitRetryDHGroup, nil
	}

	if !sawSA {
		return 0, fmt.Errorf("control: IKE_SA_INIT response missing SA payload")
	}
	if responderSPI == 0 {
		return 0, fmt.Errorf("control: IKE_SA_INIT response without responder SPI did not request COOKIE/INVALID_KE_PAYLOAD")
	}

	if !sawNonce {
		return 0, fmt.Errorf("control: IKE_SA_INIT response missing Nr")
	}
	if !sawKE {
		return 0, fmt.Errorf("control: IKE_SA_INIT response missing KE")
	}

	selection, err := h.decodeIKESelection(saPayload)
	if err != nil {
		return 0, err
	}
	h.state.Cookie = nil
	h.state.SelectedIKE = selection
	h.state.ResponderSPI = responderSPI
	h.state.ResponderNonce = nonce
	h.state.ResponderKE = ke

	detected, err := h.natDetected()
	if err != nil {
		return 0, err
	}
	h.state.NAT.Detected = detected
	return SAInitEstablished, nil
}

// decodeIKESelection maps the responder's selected proposal (with the
// proposal number it references) back onto the exact local IKE proposal and
// verifies transform IDs, key lengths and the AEAD-or-CBC integrity rules.
func (h *Handshake) decodeIKESelection(sa payload.SA) (*xcrypto.Selection, error) {
	sp := sa.Proposals[0]
	if sp.ProtocolID != wire.DeleteProtocolIKE || len(sp.SPI) != 0 {
		return nil, fmt.Errorf("control: invalid selected IKE proposal header")
	}
	idx := int(sp.Num) - 1
	if idx < 0 || idx >= len(h.cfg.IKE) {
		return nil, fmt.Errorf("control: peer selected unoffered IKE proposal number %d", sp.Num)
	}

	var remote xcrypto.Proposal
	for _, t := range sp.Transforms {
		switch t.Type {
		case wire.TransformENC:
			bits, err := payload.ParseKeyLengthAttr(t.Attrs)
			if err != nil {
				return nil, fmt.Errorf("control: selected encryption transform: %w", err)
			}
			if bits == 0 || bits%8 != 0 {
				return nil, fmt.Errorf("control: invalid selected encryption key length %d", bits)
			}
			remote.Encryption = append(remote.Encryption, xcrypto.EncryptionID{TransformID: t.ID, KeyLen: bits / 8})
		case wire.TransformINTEG:
			if len(t.Attrs) != 0 {
				return nil, fmt.Errorf("control: unexpected integrity attributes in selected IKE proposal")
			}
			remote.Integrity = append(remote.Integrity, t.ID)
		case wire.TransformPRF:
			if len(t.Attrs) != 0 {
				return nil, fmt.Errorf("control: unexpected PRF attributes in selected IKE proposal")
			}
			remote.PRF = append(remote.PRF, t.ID)
		case wire.TransformDH:
			if len(t.Attrs) != 0 {
				return nil, fmt.Errorf("control: unexpected DH attributes in selected IKE proposal")
			}
			remote.DH = append(remote.DH, t.ID)
		case wire.TransformESN:
			return nil, fmt.Errorf("control: unexpected ESN transform in selected IKE proposal")
		default:
			return nil, fmt.Errorf("control: unexpected transform type %d in selected IKE proposal", uint8(t.Type))
		}
	}

	selection, err := h.cfg.IKE[idx].Select(&remote)
	if err != nil {
		return nil, fmt.Errorf("control: peer selected unsupported IKE proposal: %w", err)
	}
	if len(remote.Encryption) != 1 || len(remote.PRF) != 1 || len(remote.DH) != 1 {
		return nil, fmt.Errorf("control: selected IKE proposal missing unique transforms")
	}
	if !selectionMatchesIKE(selection, remote) {
		return nil, fmt.Errorf("control: peer selected transforms do not match the offered IKE proposal")
	}
	return selection, nil
}

// decodeIKESelectionWithSPI maps an IKE-rekey selected proposal back onto
// the local IKE proposal list. The proposal SPI field carries the peer's
// new IKE SPI (RFC 7296 2.18); it is returned alongside the selection.
func (h *Handshake) decodeIKESelectionWithSPI(sa payload.SA) (uint64, *xcrypto.Selection, error) {
	sp := sa.Proposals[0]
	if sp.ProtocolID != wire.DeleteProtocolIKE || len(sp.SPI) != 8 {
		return 0, nil, fmt.Errorf("control: invalid selected IKE rekey proposal header")
	}
	spi := uint64(sp.SPI[0])<<56 | uint64(sp.SPI[1])<<48 | uint64(sp.SPI[2])<<40 | uint64(sp.SPI[3])<<32 |
		uint64(sp.SPI[4])<<24 | uint64(sp.SPI[5])<<16 | uint64(sp.SPI[6])<<8 | uint64(sp.SPI[7])
	idx := int(sp.Num) - 1
	if idx < 0 || idx >= len(h.cfg.IKE) {
		return 0, nil, fmt.Errorf("control: peer selected unoffered IKE proposal number %d", sp.Num)
	}

	var remote xcrypto.Proposal
	for _, t := range sp.Transforms {
		switch t.Type {
		case wire.TransformENC:
			bits, err := payload.ParseKeyLengthAttr(t.Attrs)
			if err != nil {
				return 0, nil, fmt.Errorf("control: selected encryption transform: %w", err)
			}
			if bits == 0 || bits%8 != 0 {
				return 0, nil, fmt.Errorf("control: invalid selected encryption key length %d", bits)
			}
			remote.Encryption = append(remote.Encryption, xcrypto.EncryptionID{TransformID: t.ID, KeyLen: bits / 8})
		case wire.TransformINTEG:
			if len(t.Attrs) != 0 {
				return 0, nil, fmt.Errorf("control: unexpected integrity attributes in selected IKE proposal")
			}
			remote.Integrity = append(remote.Integrity, t.ID)
		case wire.TransformPRF:
			if len(t.Attrs) != 0 {
				return 0, nil, fmt.Errorf("control: unexpected PRF attributes in selected IKE proposal")
			}
			remote.PRF = append(remote.PRF, t.ID)
		case wire.TransformDH:
			if len(t.Attrs) != 0 {
				return 0, nil, fmt.Errorf("control: unexpected DH attributes in selected IKE proposal")
			}
			remote.DH = append(remote.DH, t.ID)
		case wire.TransformESN:
			return 0, nil, fmt.Errorf("control: unexpected ESN transform in selected IKE proposal")
		default:
			return 0, nil, fmt.Errorf("control: unexpected transform type %d in selected IKE proposal", uint8(t.Type))
		}
	}

	selection, err := h.cfg.IKE[idx].Select(&remote)
	if err != nil {
		return 0, nil, fmt.Errorf("control: peer selected unsupported IKE proposal: %w", err)
	}
	if len(remote.Encryption) != 1 || len(remote.PRF) != 1 || len(remote.DH) != 1 {
		return 0, nil, fmt.Errorf("control: selected IKE proposal missing unique transforms")
	}
	if !selectionMatchesIKE(selection, remote) {
		return 0, nil, fmt.Errorf("control: peer selected transforms do not match the offered IKE proposal")
	}
	return spi, selection, nil
}

// selectionMatchesIKE verifies the negotiated Selection against the exact
// transform IDs and key length the responder echoed.
func selectionMatchesIKE(sel *xcrypto.Selection, remote xcrypto.Proposal) bool {
	enc := remote.Encryption[0]
	if sel.Encryption.TransformID != enc.TransformID || sel.Encryption.TransformKeyLen != int(enc.KeyLen) {
		return false
	}
	if sel.Encryption.AEAD {
		if len(remote.Integrity) != 0 {
			return false
		}
	} else {
		if len(remote.Integrity) != 1 || sel.Integrity.TransformID != remote.Integrity[0] {
			return false
		}
	}
	return sel.PRF.TransformID == remote.PRF[0] && sel.DH.TransformID == remote.DH[0]
}

// parseSignatureHashAlgorithms decodes 16-bit big-endian algorithm ids.
func parseSignatureHashAlgorithms(data []byte) ([]uint16, error) {
	if len(data) == 0 || len(data)%2 != 0 {
		return nil, fmt.Errorf("control: invalid SIGNATURE_HASH_ALGORITHMS notify data")
	}
	out := make([]uint16, 0, len(data)/2)
	for i := 0; i < len(data); i += 2 {
		out = append(out, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return out, nil
}

// localNATHashes computes both initiator NAT-D hashes for the supplied
// responder SPI: 0 while building the request, the negotiated responder SPI
// when comparing against the responder's NAT-D payloads later.
func (h *Handshake) localNATHashes(responderSPI uint64) ([]byte, []byte, error) {
	localIP := h.cfg.LocalIP
	if localIP == nil {
		localIP = net.IPv4zero
	}
	src, err := xcrypto.NatDetectionHash(h.state.InitiatorSPI, responderSPI, localIP, transport.LogicalNatTPort)
	if err != nil {
		return nil, nil, fmt.Errorf("control: compute NAT-D source hash: %w", err)
	}
	dst, err := xcrypto.NatDetectionHash(h.state.InitiatorSPI, responderSPI, h.cfg.PeerIP, transport.LogicalNatTPort)
	if err != nil {
		return nil, nil, fmt.Errorf("control: compute NAT-D destination hash: %w", err)
	}
	return src, dst, nil
}

// deriveIKEKeys consumes the DH private key (zeroized), computes SKEYSEED
// and splits the IKE key material, then stores it on the state.
func (h *Handshake) deriveIKEKeys() error {
	if h.state.LocalDH == nil {
		return fmt.Errorf("control: missing local DH keypair")
	}
	if h.state.SelectedIKE == nil || h.state.IKEKeys != nil {
		return fmt.Errorf("control: missing IKE selection")
	}
	if len(h.state.InitiatorNonce) == 0 || len(h.state.ResponderNonce) == 0 || len(h.state.ResponderKE.Data) == 0 {
		return fmt.Errorf("control: IKE_SA_INIT is incomplete")
	}

	shared, err := h.state.LocalDH.ECDH(h.state.ResponderKE.Data)
	h.state.LocalDH = nil // zeroize the private side
	if err != nil {
		return fmt.Errorf("control: derive DH shared secret: %w", err)
	}
	sel := h.state.SelectedIKE
	skeyseed, err := xcrypto.SKEYSEED(sel.PRF, h.state.InitiatorNonce, h.state.ResponderNonce, shared)
	if err != nil {
		return fmt.Errorf("control: derive SKEYSEED: %w", err)
	}
	keys, err := xcrypto.DeriveIKEKeys(sel.PRF, skeyseed,
		h.state.InitiatorNonce, h.state.ResponderNonce,
		h.state.InitiatorSPI, h.state.ResponderSPI,
		sel.Encryption, sel.Integrity)
	if err != nil {
		return fmt.Errorf("control: derive IKE keys: %w", err)
	}
	h.state.IKEKeys = keys
	return nil
}

// natDetected compares local and remote NAT-D hashes; differing source or
// destination hash indicates NAT. The MVP profile intentionally makes the
// local source port non-4500 so a correctly-reported remote source hash
// normally mismatches.
func (h *Handshake) natDetected() (bool, error) {
	src, dst, err := h.localNATHashes(h.state.ResponderSPI)
	if err != nil {
		return false, err
	}
	// swan2 nat_detected only compares a remote hash when the peer actually
	// sent one; a missing remote hash is treated as "not detected on that
	// side", never as a mismatch against the local 20-byte hash.
	srcMismatch := len(h.state.NAT.SourceHashRemote) > 0 && !bytesEqual(src, h.state.NAT.SourceHashRemote)
	dstMismatch := len(h.state.NAT.DestinationHashRemote) > 0 && !bytesEqual(dst, h.state.NAT.DestinationHashRemote)
	return srcMismatch || dstMismatch, nil
}

// recordResponseCheckpoint retains the full SA_INIT response bytes (the
// AUTH signed octets must hash the exact raw packet). The caller keeps
// ownership of pkt and must Release it exactly once.
func (h *Handshake) recordResponseCheckpoint(pkt *transport.Packet) {
	if pkt != nil {
		h.state.SAInitResponse = append([]byte(nil), pkt.Payload...)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
