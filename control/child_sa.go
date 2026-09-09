package control

import (
	"fmt"
	"net"

	"swan/transport"
	"swan/wire"
	"swan/wire/payload"
	"swan/xcrypto"
)

// Final IKE_AUTH / CHILD_SA stage:
//   - build the final AUTH request (IDr request when rightid is set, IDi,
//     local AUTH);
//   - parse the response: AUTH required, EAP forbidden, SA/TSi/TSr/CP
//     required (unless a child-failure notify explains the rejection);
//   - validate SPIs, traffic selectors (TSr must narrow to the assigned
//     internal address) and decode the assigned CP configuration;
//   - derive the CHILD_SA key material from SK_d.

// buildFinalAuthRequest renders the last IKE_AUTH request of the handshake.
func (h *Handshake) buildFinalAuthRequest(msgID uint32) ([]*transport.Frame, error) {
	if len(h.cfg.IDI.Data) == 0 {
		return nil, fmt.Errorf("control: local identity missing before final AUTH")
	}
	localAuth, err := h.buildLocalAuth(h.cfg.IDI)
	if err != nil {
		return nil, err
	}

	var parts []cesPayloadPart
	first := wire.PayloadTypeIDi
	if h.cfg.RightID.Type != 0 {
		first = wire.PayloadTypeIDr
		parts = append(parts, cesPayloadPart{
			typ:  wire.PayloadTypeIDr,
			body: payload.AppendID(nil, h.cfg.RightID),
		})
	}
	idBody := payload.AppendID(nil, h.cfg.IDI)
	if len(h.state.Auth.FirstIDiPayload) > 0 {
		idBody = append([]byte(nil), h.state.Auth.FirstIDiPayload...)
	}
	parts = append(parts, cesPayloadPart{
		typ:  wire.PayloadTypeIDi,
		body: idBody,
	})
	parts = append(parts, cesPayloadPart{
		typ:  wire.PayloadTypeAuth,
		body: payload.AppendAuth(nil, localAuth),
	})

	return h.buildProtected(wire.ExchangeIkeAuth, msgID, first, cesBuildChain(parts))
}

// processFinalAuth absorbs the final response and produces the active
// ChildSA plus AssignedConfig (stored on state).
func (h *Handshake) processFinalAuth(m *wire.Message) (*ChildSA, error) {
	if h.state.NegotiatingChild == nil {
		return nil, fmt.Errorf("control: missing negotiating CHILD_SA state")
	}

	var auth *payload.Auth
	var idr []byte
	var eapBody []byte
	var childSA *payload.SA
	var tsiBody []byte
	var tsrBody []byte
	var cpBody []byte
	var certs [][]byte
	var notifies []payload.Notify
	var spiNotifies []cesSpiNotify

	for i := range m.Payloads {
		p := &m.Payloads[i]
		switch p.Type {
		case wire.PayloadTypeAuth:
			a, err := payload.ParseAuth(p.Body)
			if err != nil {
				return nil, err
			}
			auth = &a
		case wire.PayloadTypeIDr:
			idr = append([]byte(nil), p.Body...)
		case wire.PayloadTypeEAP:
			eapBody = append([]byte(nil), p.Body...)
		case wire.PayloadTypeCert:
			cert, err := payload.ParseCert(p.Body)
			if err != nil {
				return nil, err
			}
			if cert.Encoding != wire.CertEncodingX509Signature {
				return nil, fmt.Errorf("control: unsupported CERT encoding %d", cert.Encoding)
			}
			certs = append(certs, append([]byte(nil), cert.DER...))
		case wire.PayloadTypeSA:
			sa, err := payload.ParseSA(p.Body)
			if err != nil {
				return nil, err
			}
			childSA = &sa
		case wire.PayloadTypeTSi:
			tsiBody = append([]byte(nil), p.Body...)
		case wire.PayloadTypeTSr:
			tsrBody = append([]byte(nil), p.Body...)
		case wire.PayloadTypeCP:
			cpBody = append([]byte(nil), p.Body...)
		case wire.PayloadTypeNotify:
			n, err := payload.ParseNotify(p.Body)
			if err != nil {
				return nil, err
			}
			notifies = append(notifies, n)
			if len(n.SPI) > 0 {
				if len(n.SPI) != 4 {
					return nil, fmt.Errorf("control: unexpected SPI size in final IKE_AUTH notify")
				}
				if !isChildFailureNotify(n.Type) {
					return nil, fmt.Errorf("control: unexpected SPI-scoped notify %d in final IKE_AUTH", uint16(n.Type))
				}
				spiNotifies = append(spiNotifies, cesSpiNotify{
					typ:      n.Type,
					protocol: n.ProtocolID,
					spi:      cesU32(n.SPI),
				})
			}
		default:
			// Other payload types are ignored in the final AUTH response,
			// matching swan2's permissive final-response scan.
		}
	}

	if len(eapBody) != 0 {
		return nil, fmt.Errorf("control: final IKE_AUTH response must not include EAP payload")
	}
	if err := h.validateAuthNotifies(notifies); err != nil {
		return nil, err
	}
	if auth == nil {
		return nil, fmt.Errorf("control: final IKE_AUTH response missing AUTH payload")
	}
	peerIDr := idr
	if len(peerIDr) == 0 {
		peerIDr = append([]byte(nil), h.state.Auth.PeerIDr...)
	}
	if len(peerIDr) < 4 {
		return nil, fmt.Errorf("control: final IKE_AUTH response missing IDr payload")
	}
	if err := h.recordPeerIdentity(peerIDr); err != nil {
		return nil, err
	}
	if len(certs) > 0 {
		h.state.Auth.PeerCerts = certs
	}
	if err := h.verifyPeerAuth(peerIDr, *auth); err != nil {
		return nil, err
	}

	if childSA == nil {
		if reason := cesChildFailureReason(notifies); reason != "" {
			return nil, fmt.Errorf("control: CHILD_SA negotiation failed: %s", reason)
		}
		return nil, fmt.Errorf("control: final IKE_AUTH response missing CHILD_SA proposal")
	}

	peerSPI, selection, err := h.decodeChildSelection(*childSA)
	if err != nil {
		return nil, err
	}
	localInbound := h.state.NegotiatingChild.InboundSPI
	if err := cesValidateSpiNotifies(spiNotifies, peerSPI, localInbound); err != nil {
		return nil, err
	}
	h.state.SelectedESP = selection

	if len(cpBody) == 0 {
		return nil, fmt.Errorf("control: final IKE_AUTH response missing CP payload")
	}
	assigned, err := cesDecodeAssigned(cpBody)
	if err != nil {
		return nil, err
	}
	if assigned.InternalIPv4 == nil && assigned.InternalIPv6 == nil {
		return nil, fmt.Errorf("control: final IKE_AUTH CP reply missing INTERNAL_IP4/6_ADDRESS")
	}

	if len(tsiBody) == 0 || len(tsrBody) == 0 {
		return nil, fmt.Errorf("control: final IKE_AUTH response missing TSi/TSr payload")
	}
	tsi, err := payload.ParseTS(tsiBody)
	if err != nil {
		return nil, err
	}
	tsr, err := payload.ParseTS(tsrBody)
	if err != nil {
		return nil, err
	}
	if err := h.validateTrafficSelectors(tsi, tsr, assigned); err != nil {
		return nil, err
	}

	h.state.Assigned = assigned
	child := &ChildSA{
		InboundSPI:  localInbound,
		OutboundSPI: peerSPI,
		TSi:         append([]byte(nil), tsiBody...),
		TSr:         append([]byte(nil), tsrBody...),
	}
	h.state.NegotiatingChild = nil
	h.state.ActiveChild = child
	return child, nil
}

// decodeChildSelection maps the responder's chosen ESP proposal number and
// transforms back onto the exact proposal variant we offered (including the
// strongswan-compat NO_EXT_SEQ omission variant), returning peer SPI and
// selected algorithms.
func (h *Handshake) decodeChildSelection(sa payload.SA) (uint32, *xcrypto.Selection, error) {
	if len(sa.Proposals) != 1 {
		return 0, nil, fmt.Errorf("control: unexpected CHILD_SA proposal count %d", len(sa.Proposals))
	}
	prop := sa.Proposals[0]
	if prop.ProtocolID != wire.DeleteProtocolESP {
		return 0, nil, fmt.Errorf("control: unexpected CHILD_SA proposal protocol %d", prop.ProtocolID)
	}
	if len(prop.SPI) != 4 {
		return 0, nil, fmt.Errorf("control: CHILD_SA proposal SPI size mismatch")
	}
	peerSPI := cesU32(prop.SPI)

	offers, err := h.cesChildOffers()
	if err != nil {
		return 0, nil, err
	}
	idx := int(prop.Num) - 1
	if idx < 0 || idx >= len(offers) {
		return 0, nil, fmt.Errorf("control: peer selected an unoffered CHILD_SA proposal number %d", prop.Num)
	}
	offer := offers[idx]

	var encID uint16
	var encKeyLen uint16
	var integID uint16
	var hasInteg bool
	esn := -1
	var chosenTR *payload.Transform

	for i := range prop.Transforms {
		tr := &prop.Transforms[i]
		switch tr.Type {
		case wire.TransformENC:
			if chosenTR != nil {
				return 0, nil, fmt.Errorf("control: multiple ENCR transforms in CHILD_SA selection")
			}
			chosenTR = tr
			keyBits, err := payload.ParseKeyLengthAttr(tr.Attrs)
			if err != nil {
				return 0, nil, err
			}
			if keyBits == 0 || keyBits%8 != 0 {
				return 0, nil, fmt.Errorf("control: invalid CHILD_SA encryption key length")
			}
			encID = tr.ID
			encKeyLen = keyBits / 8
		case wire.TransformINTEG:
			if hasInteg {
				return 0, nil, fmt.Errorf("control: multiple INTEG transforms in CHILD_SA selection")
			}
			integID = tr.ID
			hasInteg = true
		case wire.TransformESN:
			if esn != -1 {
				return 0, nil, fmt.Errorf("control: multiple ESN transforms in CHILD_SA selection")
			}
			esn = int(tr.ID)
		default:
			return 0, nil, fmt.Errorf("control: unexpected transform type %d in CHILD_SA selection", tr.Type)
		}
	}

	if chosenTR == nil {
		return 0, nil, fmt.Errorf("control: CHILD_SA selection missing ENCR transform")
	}
	variantOK := false
	for _, e := range offer.enc {
		if e.TransformID == encID && e.KeyLen == encKeyLen {
			variantOK = true
			break
		}
	}
	if !variantOK {
		return 0, nil, fmt.Errorf("control: CHILD_SA selected an unoffered encryption transform %d/%d", encID, encKeyLen)
	}

	enc, err := xcrypto.NewEncryption(encID, encKeyLen)
	if err != nil {
		return 0, nil, fmt.Errorf("control: CHILD_SA encryption %d/%d: %w", encID, encKeyLen, err)
	}
	var integ *xcrypto.Integrity
	if enc.AEAD {
		if hasInteg {
			return 0, nil, fmt.Errorf("control: AEAD CHILD_SA selection must not include integrity")
		}
		integ, err = xcrypto.NewIntegrity(xcrypto.TransformIntegrityNone)
		if err != nil {
			return 0, nil, err
		}
	} else {
		if !hasInteg {
			return 0, nil, fmt.Errorf("control: CHILD_SA selection missing integrity transform")
		}
		ok := false
		for _, id := range offer.integrity {
			if id == integID {
				ok = true
				break
			}
		}
		if !ok {
			return 0, nil, fmt.Errorf("control: CHILD_SA selected an unoffered integrity transform %d", integID)
		}
		integ, err = xcrypto.NewIntegrity(integID)
		if err != nil {
			return 0, nil, err
		}
	}
	// swan2 treats an absent ESN transform as NO_EXT_SEQ and also accepts a
	// present NO_EXT_SEQ (0) transform, regardless of which offer variant
	// the responder selected.
	if esn != -1 && esn != wire.ESNNoExtendedSequenceNumbers {
		return 0, nil, fmt.Errorf("control: unsupported CHILD_SA ESN mode %d", esn)
	}

	if h.state.SelectedIKE == nil {
		return 0, nil, fmt.Errorf("control: IKE proposal missing before CHILD_SA selection")
	}
	return peerSPI, &xcrypto.Selection{
		Encryption: enc,
		Integrity:  integ,
		PRF:        h.state.SelectedIKE.PRF,
		DH:         h.state.SelectedIKE.DH,
	}, nil
}

// validateTrafficSelectors enforces the MVP remote-access rules: TSi must
// narrow to the assigned INTERNAL_IP4/IP6_ADDRESS, both sides IPv4+IPv6
// ranges with sane ordering and all ports (0..65535).
func (h *Handshake) validateTrafficSelectors(tsi, tsr payload.TrafficSelectors, assigned *AssignedConfig) error {
	if len(tsi.Selectors) == 0 || len(tsr.Selectors) == 0 {
		return fmt.Errorf("control: final IKE_AUTH TS payload has empty selectors")
	}
	for i := range tsi.Selectors {
		sel := &tsi.Selectors[i]
		if err := cesCheckSelector(sel); err != nil {
			return fmt.Errorf("control: invalid TSi selector: %w", err)
		}
		switch sel.Type {
		case wire.TSTypeIPv4AddrRange:
			if assigned.InternalIPv4 == nil {
				return fmt.Errorf("control: TSi is IPv4 but CP has no INTERNAL_IP4_ADDRESS")
			}
			if !sel.StartAddr.Equal(assigned.InternalIPv4) || !sel.EndAddr.Equal(assigned.InternalIPv4) {
				return fmt.Errorf("control: TSi must narrow to the assigned INTERNAL_IP4_ADDRESS")
			}
		case wire.TSTypeIPv6AddrRange:
			if assigned.InternalIPv6 == nil {
				return fmt.Errorf("control: TSi is IPv6 but CP has no INTERNAL_IP6_ADDRESS")
			}
			if !sel.StartAddr.Equal(assigned.InternalIPv6) || !sel.EndAddr.Equal(assigned.InternalIPv6) {
				return fmt.Errorf("control: TSi must narrow to the assigned INTERNAL_IP6_ADDRESS")
			}
		default:
			return fmt.Errorf("control: unsupported TSi traffic selector type %d", sel.Type)
		}
	}
	for i := range tsr.Selectors {
		sel := &tsr.Selectors[i]
		if err := cesCheckSelector(sel); err != nil {
			return fmt.Errorf("control: invalid TSr selector: %w", err)
		}
		if sel.Type != wire.TSTypeIPv4AddrRange && sel.Type != wire.TSTypeIPv6AddrRange {
			return fmt.Errorf("control: unsupported TSr traffic selector type %d", sel.Type)
		}
	}
	return nil
}

// deriveChildKeys expands SK_d into the four CHILD_SA keys.
func (h *Handshake) deriveChildKeys() (*xcrypto.ChildKeys, error) {
	if h.state.IKEKeys == nil {
		return nil, fmt.Errorf("control: IKE key material is missing")
	}
	if len(h.state.InitiatorNonce) == 0 || len(h.state.ResponderNonce) == 0 {
		return nil, fmt.Errorf("control: missing nonce material")
	}
	if h.state.SelectedIKE == nil || h.state.SelectedESP == nil {
		return nil, fmt.Errorf("control: missing selected algorithms")
	}
	return xcrypto.DeriveChildKeys(
		h.state.SelectedIKE.PRF,
		h.state.IKEKeys.SKd,
		h.state.InitiatorNonce,
		h.state.ResponderNonce,
		h.state.SelectedESP.Encryption,
		h.state.SelectedESP.Integrity,
	)
}

// cesPayloadPart is one inner payload chain segment of the final AUTH
// request plaintext.
type cesPayloadPart struct {
	typ  wire.PayloadType
	body []byte
}

// cesBuildChain concatenates payload parts with correct generic headers.
func cesBuildChain(parts []cesPayloadPart) []byte {
	var out []byte
	for i := range parts {
		next := wire.PayloadTypeNone
		if i+1 < len(parts) {
			next = parts[i+1].typ
		}
		total := 4 + len(parts[i].body)
		out = append(out, byte(next), 0, byte(total>>8), byte(total))
		out = append(out, parts[i].body...)
	}
	return out
}

// cesSpiNotify is an SPI-scoped notify collected from the final AUTH
// response.
type cesSpiNotify struct {
	typ      wire.NotifyType
	protocol uint8
	spi      uint32
}

type cesOffer struct {
	enc       []xcrypto.EncryptionID
	integrity []uint16
	omitESN   bool
}

// cesChildOffers recreates swan2's child_sa_offer_variants list: the local
// ESP proposals in order, then (for strongswan-compat) AEAD duplicates that
// omit the NO_EXT_SEQ transform.
func (h *Handshake) cesChildOffers() ([]cesOffer, error) {
	var offers []cesOffer
	seen := map[string]bool{}
	for si := range h.cfg.ESP {
		suite := &h.cfg.ESP[si]
		mk := func(omit bool) (string, cesOffer) {
			key := cesOfferKey(suite, omit)
			return key, cesOffer{enc: suite.Encryption, integrity: suite.Integrity, omitESN: omit}
		}
		key, off := mk(false)
		if !seen[key] {
			seen[key] = true
			offers = append(offers, off)
		}
		if h.cfg.StrongswanCompatible {
			if cesSuiteIsAEAD(suite) {
				key2, off2 := mk(true)
				if !seen[key2] {
					seen[key2] = true
					offers = append(offers, off2)
				}
			}
		}
	}
	if len(offers) == 0 {
		return nil, fmt.Errorf("control: esp_suite is required")
	}
	return offers, nil
}

func cesSuiteIsAEAD(suite *xcrypto.Proposal) bool {
	return cesEncryptionListIsAEAD(suite.Encryption)
}

func cesEncryptionListIsAEAD(encs []xcrypto.EncryptionID) bool {
	for i := range encs {
		enc, err := xcrypto.NewEncryption(encs[i].TransformID, encs[i].KeyLen)
		if err == nil && enc.AEAD {
			return true
		}
	}
	return false
}

// espOfferTransforms builds one ESP proposal's transform list from the
// offer-variant decoded earlier. CBC suites include integrity transforms and
// a closing NO_EXT_SEQ ESN transform; AEAD suites include no integrity and
// may omit the ESN transform for the strongswan-compatible variant.
func espOfferTransforms(offer cesOffer) ([]payload.Transform, error) {
	var transforms []payload.Transform
	for _, enc := range offer.enc {
		alg, err := xcrypto.NewEncryption(enc.TransformID, enc.KeyLen)
		if err != nil {
			return nil, err
		}
		transforms = append(transforms, payload.Transform{
			Type:  wire.TransformENC,
			ID:    enc.TransformID,
			Attrs: payload.KeyLengthAttr(uint16(alg.TransformKeyLen * 8)),
		})
	}
	if !cesEncryptionListIsAEAD(offer.enc) {
		for _, integ := range offer.integrity {
			transforms = append(transforms, payload.Transform{Type: wire.TransformINTEG, ID: integ})
		}
	}
	if !offer.omitESN {
		transforms = append(transforms, payload.Transform{Type: wire.TransformESN, ID: wire.ESNNoExtendedSequenceNumbers})
	}
	return transforms, nil
}

func cesOfferKey(suite *xcrypto.Proposal, omit bool) string {
	s := "omit="
	if omit {
		s = "with-ESN=false "
	}
	for i := range suite.Encryption {
		s += fmt.Sprintf("%d/%d,", suite.Encryption[i].TransformID, suite.Encryption[i].KeyLen)
	}
	for _, id := range suite.Integrity {
		s += fmt.Sprintf("i%d,", id)
	}
	return s
}

func cesValidateSpiNotifies(notifies []cesSpiNotify, expectedOutbound, inbound uint32) error {
	for _, n := range notifies {
		if n.protocol != wire.DeleteProtocolESP {
			return fmt.Errorf("control: unexpected SPI-scoped notify protocol %d", n.protocol)
		}
		if n.spi != expectedOutbound && n.spi != inbound {
			return fmt.Errorf("control: SPI-scoped notify %d unexpected SPI 0x%08x", n.typ, n.spi)
		}
	}
	return nil
}

func cesChildFailureReason(notifies []payload.Notify) string {
	for _, n := range notifies {
		switch n.Type {
		case wire.NotifyNoProposalChosen:
			return "NO_PROPOSAL_CHOSEN"
		case wire.NotifySinglePairRequired:
			return "SINGLE_PAIR_REQUIRED"
		case wire.NotifyNoAdditionalSAs:
			return "NO_ADDITIONAL_SAS"
		case wire.NotifyInternalAddressFailure:
			return "INTERNAL_ADDRESS_FAILURE"
		case wire.NotifyFailedCPRequired:
			return "FAILED_CP_REQUIRED"
		case wire.NotifyTSUnacceptable:
			return "TS_UNACCEPTABLE"
		}
	}
	return ""
}

// cesDecodeAssigned parses a CFG_REPLY body into AssignedConfig.
func cesDecodeAssigned(b []byte) (*AssignedConfig, error) {
	cp, err := payload.ParseConfigPayload(b)
	if err != nil {
		return nil, err
	}
	if !cp.IsReply {
		return nil, fmt.Errorf("control: expected CFG_REPLY in final IKE_AUTH")
	}
	out := &AssignedConfig{}
	for i := range cp.Attributes {
		attr := &cp.Attributes[i]
		switch attr.Type {
		case wire.ConfigAttrInternalIPv4Address:
			if len(attr.Value) == 0 {
				continue
			}
			if len(attr.Value) != 4 {
				return nil, fmt.Errorf("control: invalid INTERNAL_IP4_ADDRESS length %d", len(attr.Value))
			}
			out.InternalIPv4 = net.IPv4(attr.Value[0], attr.Value[1], attr.Value[2], attr.Value[3])
		case wire.ConfigAttrInternalIPv4DNS:
			if len(attr.Value) != 4 {
				return nil, fmt.Errorf("control: invalid INTERNAL_IP4_DNS length %d", len(attr.Value))
			}
			out.DNS4 = append(out.DNS4, net.IPv4(attr.Value[0], attr.Value[1], attr.Value[2], attr.Value[3]))
		case wire.ConfigAttrInternalIPv6Address:
			if len(attr.Value) == 0 {
				continue
			}
			if len(attr.Value) != 17 {
				return nil, fmt.Errorf("control: invalid INTERNAL_IP6_ADDRESS length %d", len(attr.Value))
			}
			if attr.Value[16] > 128 {
				return nil, fmt.Errorf("control: invalid INTERNAL_IP6_ADDRESS prefix length %d", attr.Value[16])
			}
			out.InternalIPv6 = append(net.IP(nil), attr.Value[:16]...)
			out.InternalIPv6Prefix = attr.Value[16]
		case wire.ConfigAttrInternalIPv6DNS:
			if len(attr.Value) != 16 {
				return nil, fmt.Errorf("control: invalid INTERNAL_IP6_DNS length %d", len(attr.Value))
			}
			out.DNS6 = append(out.DNS6, append(net.IP(nil), attr.Value...))
		case wire.ConfigAttrInternalAddressExpiry:
			if len(attr.Value) == 4 {
				out.AddressExpirySeconds = uint32(attr.Value[0])<<24 | uint32(attr.Value[1])<<16 | uint32(attr.Value[2])<<8 | uint32(attr.Value[3])
			}
		}
	}
	return out, nil
}

// cesCheckSelector enforces the shared MVP selector rules: protocol 0 and
// full port range.
func cesCheckSelector(sel *payload.Selector) error {
	if sel.ProtocolID != 0 {
		return fmt.Errorf("selector must use protocol 0, got %d", sel.ProtocolID)
	}
	if sel.StartPort != 0 || sel.EndPort != 0xffff {
		return fmt.Errorf("selector must allow all ports")
	}
	return nil
}

// cesU32 decodes a 4-byte big-endian SPI.
func cesU32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

var _ = wire.PayloadTypeSA
