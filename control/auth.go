package control

import (
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"

	"swan/transport"
	"swan/wire"
	"swan/wire/payload"
	"swan/xcrypto"
)

// IKE_AUTH stage: bootstrap request, response processing shared with the
// EAP loop, local AUTH construction and peer AUTH verification.
//
// The bootstrap request carries IDi, INITIAL_CONTACT, (IDr when rightid is
// set), CP request, the child SA proposals (with SPI), TSi (0.0.0.0-...),
// TSr (strongswan default 2000::/3-shaped), MOBIKE_SUPPORTED,
// NO_ADDITIONAL_ADDRESSES, MULTIPLE_AUTH_SUPPORTED, EAP_ONLY_AUTHENTICATION
// and IKEV2_MESSAGE_ID_SYNC_SUPPORTED — the exact MVP shape of swan2.

// buildBootstrapAuthRequest renders the first IKE_AUTH request for a fresh
// child-SA negotiation and records the negotiating state.
func (h *Handshake) buildBootstrapAuthRequest(msgID uint32) ([]*transport.Frame, error) {
	inboundSPI, err := h.generateChildSPI()
	if err != nil {
		return nil, err
	}
	h.state.NegotiatingChild = &NegotiatingChildSA{InboundSPI: inboundSPI}

	idiBody := payload.AppendID(nil, h.cfg.IDI)
	h.state.Auth.FirstIDiPayload = append([]byte(nil), idiBody...)

	esp, err := h.appendESPProposals(nil, inboundSPI)
	if err != nil {
		return nil, err
	}

	parts := []cesPayloadPart{
		{typ: wire.PayloadTypeIDi, body: idiBody},
		{typ: wire.PayloadTypeNotify, body: payload.AppendNotify(nil, payload.Notify{ProtocolID: wire.NotifyProtocolNone, Type: wire.NotifyInitialContact})},
	}
	if h.cfg.RightID.Type != 0 {
		parts = append(parts, cesPayloadPart{typ: wire.PayloadTypeIDr, body: payload.AppendID(nil, h.cfg.RightID)})
	}
	parts = append(parts,
		cesPayloadPart{typ: wire.PayloadTypeCP, body: payload.AppendConfigRequest(nil)},
		cesPayloadPart{typ: wire.PayloadTypeSA, body: esp},
		cesPayloadPart{typ: wire.PayloadTypeTSi, body: payload.AppendTS(nil, tsiAnyDualStack())},
		cesPayloadPart{typ: wire.PayloadTypeTSr, body: payload.AppendTS(nil, tsrStrongswanDefault())},
	)
	for _, t := range []wire.NotifyType{
		wire.NotifyMobikeSupported,
		wire.NotifyNoAdditionalAddresses,
		wire.NotifyMultipleAuthSupported,
		wire.NotifyEapOnlyAuthentication,
		wire.NotifyIKEv2MessageIDSyncSupported,
	} {
		parts = append(parts, cesPayloadPart{
			typ:  wire.PayloadTypeNotify,
			body: payload.AppendNotify(nil, payload.Notify{ProtocolID: wire.NotifyProtocolNone, Type: t}),
		})
	}

	return h.buildProtected(wire.ExchangeIkeAuth, msgID, wire.PayloadTypeIDi, cesBuildChain(parts))
}

// generateChildSPI returns a random non-zero 32-bit SPI for the initiator
// inbound CHILD_SA direction.
func (h *Handshake) generateChildSPI() (uint32, error) {
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

// appendESPProposals serializes cfg.ESP as an SA body for the bootstrap
// IKE_AUTH child proposal. The proposal list comes from the same
// child_sa_offer_variants reconstruction used to decode the responder's
// selection, so wire proposal numbering stays identical when the config
// contains duplicate suites or strongswan-compat AEAD variants that omit
// the final NO_EXT_SEQ (ESN) transform.
func (h *Handshake) appendESPProposals(dst []byte, spi uint32) ([]byte, error) {
	offers, err := h.cesChildOffers()
	if err != nil {
		return nil, err
	}
	spiBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(spiBytes, spi)

	var sa payload.SA
	for i := range offers {
		transforms, err := espOfferTransforms(offers[i])
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

// handleAuthResponse classifies one IKE_AUTH response payload set:
// IDr/CERT/notify bookkeeping, peer capability updates, optional early AUTH
// verification, and extraction of the EAP payload (empty when none).
// firstResponse distinguishes the bootstrap response from EAP rounds.
func (h *Handshake) handleAuthResponse(m *wire.Message, firstResponse bool) ([]byte, error) {
	var (
		eapPayload  []byte
		inboundAuth *payload.Auth
		inboundIDr  []byte
		certs       [][]byte
		notifies    []payload.Notify
	)

	for i := range m.Payloads {
		p := &m.Payloads[i]
		switch p.Type {
		case wire.PayloadTypeEAP:
			eapPayload = append([]byte(nil), p.Body...)
		case wire.PayloadTypeAuth:
			a, err := payload.ParseAuth(p.Body)
			if err != nil {
				return nil, fmt.Errorf("control: parse IKE_AUTH AUTH payload: %w", err)
			}
			inboundAuth = &a
		case wire.PayloadTypeIDr:
			inboundIDr = append([]byte(nil), p.Body...)
		case wire.PayloadTypeCert:
			c, err := payload.ParseCert(p.Body)
			if err != nil {
				return nil, fmt.Errorf("control: parse IKE_AUTH CERT payload: %w", err)
			}
			if c.Encoding != wire.CertEncodingX509Signature {
				return nil, fmt.Errorf("control: unsupported CERT encoding %d", uint8(c.Encoding))
			}
			certs = append(certs, append([]byte(nil), c.DER...))
		case wire.PayloadTypeNotify:
			n, err := payload.ParseNotify(p.Body)
			if err != nil {
				return nil, fmt.Errorf("control: parse IKE_AUTH notify: %w", err)
			}
			if len(n.SPI) != 0 {
				return nil, fmt.Errorf("control: unexpected SPI-scoped notify during EAP progression")
			}
			notifies = append(notifies, n)
		}
	}

	if err := h.validateAuthNotifies(notifies); err != nil {
		return nil, err
	}

	// Peer capability updates from notifies.
	notifyTypes := make([]notifyTableType, 0, len(notifies))
	for _, n := range notifies {
		notifyTypes = append(notifyTypes, notifyTableType(n.Type))
	}
	h.state.Peer.SupportsEAPOnlyAuthentication = containsNotify(notifyTypes, wire.NotifyEapOnlyAuthentication)
	h.state.Peer.SupportsMessageIDSync = containsNotify(notifyTypes, wire.NotifyIKEv2MessageIDSyncSupported)
	h.state.Peer.SupportsFragmentation = h.state.Peer.SupportsFragmentation || containsNotify(notifyTypes, wire.NotifyFragmentationSupported)

	peerIDr := inboundIDr
	if len(peerIDr) == 0 {
		peerIDr = append([]byte(nil), h.state.Auth.PeerIDr...)
	}
	if len(peerIDr) == 0 {
		return nil, fmt.Errorf("control: IKE_AUTH response missing IDr payload")
	}
	if err := h.recordPeerIdentity(peerIDr); err != nil {
		return nil, err
	}
	if len(certs) > 0 {
		h.state.Auth.PeerCerts = certs
	}

	if firstResponse {
		if inboundAuth != nil {
			if err := h.verifyPeerAuth(peerIDr, *inboundAuth); err != nil {
				return nil, err
			}
		} else {
			if len(eapPayload) == 0 {
				return nil, fmt.Errorf("control: first IKE_AUTH response missing AUTH payload")
			}
			if !h.state.Peer.SupportsEAPOnlyAuthentication {
				return nil, fmt.Errorf("control: configured EAP-only authentication, but the peer does not support it")
			}
		}
	} else if inboundAuth != nil {
		if err := h.verifyPeerAuth(peerIDr, *inboundAuth); err != nil {
			return nil, err
		}
	}

	if len(eapPayload) == 0 {
		return nil, fmt.Errorf("control: IKE_AUTH response missing EAP payload")
	}
	return eapPayload, nil
}

// notifyTableType is a local alias so the notify-capability helpers read
// naturally without leaking a second numeric spelling.
type notifyTableType = wire.NotifyType

func containsNotify(list []notifyTableType, want wire.NotifyType) bool {
	for _, have := range list {
		if have == want {
			return true
		}
	}
	return false
}

// recordPeerIdentity validates an IDr payload against the configured
// rightid (type-aware wildcard matching for FQDN/RFC822) and stores it.
func (h *Handshake) recordPeerIdentity(idr []byte) error {
	id, err := payload.ParseID(idr)
	if err != nil {
		return fmt.Errorf("control: invalid IDr payload: %w", err)
	}
	if len(id.Data) == 0 {
		return fmt.Errorf("control: empty IDr value")
	}
	if h.cfg.RightID.Type != 0 && !RightIDMatches(h.cfg.RightID, id) {
		return fmt.Errorf("control: rightid mismatch: expected %s, received %s", string(h.cfg.RightID.Data), string(id.Data))
	}
	h.state.Auth.PeerIDr = append([]byte(nil), idr...)
	return nil
}

// buildLocalAuth renders the initiator AUTH payload. MVP local auth is
// method 2 (Shared Key MIC) computed over the EAP MSK when available,
// falling back to sk_pi exactly like swan2.
func (h *Handshake) buildLocalAuth(localID payload.ID) (payload.Auth, error) {
	sel, keys := h.authMaterial()
	if sel == nil || keys == nil {
		return payload.Auth{}, fmt.Errorf("control: IKE key material is missing")
	}
	idBody := h.state.Auth.FirstIDiPayload
	if len(idBody) == 0 {
		idBody = payload.AppendID(nil, localID)
	}
	macedID, err := xcrypto.MACedID(sel.PRF, keys.SKpi, idBody)
	if err != nil {
		return payload.Auth{}, fmt.Errorf("control: compute local MACedID: %w", err)
	}
	octets, err := h.computeSignedOctets(macedID, false)
	if err != nil {
		return payload.Auth{}, err
	}
	secret := h.localAuthSecret()
	mac, err := xcrypto.AuthMAC(sel.PRF, secret, octets)
	if err != nil {
		return payload.Auth{}, fmt.Errorf("control: compute local AUTH: %w", err)
	}
	return payload.Auth{Method: wire.AuthSharedKeyMIC, Data: mac}, nil
}

// verifyPeerAuth dispatches AUTH methods 1/2/3/14:
//   - method 2: recompute shared-key MIC from the EAP MSK/sk_pr;
//   - methods 1/3/14: parse the AlgorithmIdentifier and delegate signature
//     verification, certificate identity and chain checks to swan/xcrypto.
func (h *Handshake) verifyPeerAuth(idr []byte, auth payload.Auth) error {
	sel, keys := h.authMaterial()
	if sel == nil || keys == nil {
		return fmt.Errorf("control: IKE key material is missing")
	}

	switch auth.Method {
	case wire.AuthSharedKeyMIC:
		macedID, err := xcrypto.MACedID(sel.PRF, keys.SKpr, idr)
		if err != nil {
			return fmt.Errorf("control: compute peer MACedID: %w", err)
		}
		octets, err := h.computeSignedOctets(macedID, true)
		if err != nil {
			return err
		}
		expected, err := xcrypto.AuthMAC(sel.PRF, h.peerAuthSecret(), octets)
		if err != nil {
			return fmt.Errorf("control: compute peer AUTH MAC: %w", err)
		}
		if len(expected) != len(auth.Data) || subtle.ConstantTimeCompare(expected, auth.Data) != 1 {
			return fmt.Errorf("control: AUTH verification failed")
		}
		h.state.Auth.PeerAuthMethod = uint8(auth.Method)
		return nil

	case wire.AuthRsaDigitalSignature, wire.AuthDssDigitalSignature, wire.AuthDigitalSignature:
		var (
			alg       xcrypto.SignatureAlgorithm
			signature []byte
			keyKinds  []xcrypto.PublicKeyType
		)
		if auth.Method == wire.AuthDigitalSignature {
			parsed, sig, err := xcrypto.ParseSignatureAuthData(auth.Data)
			if err != nil {
				return err
			}
			if len(h.state.Auth.PeerSignatureHashAlgorithms) == 0 {
				return fmt.Errorf("control: responder used AUTH method 14 without SIGNATURE_HASH_ALGORITHMS negotiation")
			}
			if !containsUint16(h.state.Auth.PeerSignatureHashAlgorithms, parsed.HashID) {
				return fmt.Errorf("control: AUTH method 14 used unadvertised signature hash algorithm %d", parsed.HashID)
			}
			alg, signature = parsed, sig
			keyKinds = []xcrypto.PublicKeyType{parsed.KeyType}
		} else {
			alg = xcrypto.SignatureAlgorithm{Hash: xcrypto.SHA1()}
			signature = auth.Data
			// Legacy methods carry no AlgorithmIdentifier: try the key
			// types the MVP accepts.
			keyKinds = []xcrypto.PublicKeyType{xcrypto.PublicKeyRSA, xcrypto.PublicKeyECDSA}
		}

		macedID, err := xcrypto.MACedID(sel.PRF, keys.SKpr, idr)
		if err != nil {
			return err
		}
		octets, err := h.computeSignedOctets(macedID, true)
		if err != nil {
			return err
		}
		id, err := payload.ParseID(idr)
		if err != nil {
			return fmt.Errorf("control: parse IDr for certificate identity: %w", err)
		}
		certs, roots, err := h.peerCertificates()
		if err != nil {
			return err
		}

		var lastErr error
		for _, kt := range keyKinds {
			alg.KeyType = kt
			err := xcrypto.VerifyPeerAuthSignature(certs, uint8(id.Type), id.Data, octets, signature, alg, roots, h.cfg.InsecureSkipPeerCertVerify)
			if err == nil {
				h.state.Auth.PeerAuthMethod = uint8(auth.Method)
				return nil
			}
			lastErr = err
		}
		return fmt.Errorf("control: AUTH signature verification failed: %w", lastErr)

	default:
		return fmt.Errorf("control: unsupported AUTH method %d", uint8(auth.Method))
	}
}

// peerCertificates parses the responder certificate chain and loads the
// system trust roots.
func (h *Handshake) peerCertificates() ([]*x509.Certificate, *x509.CertPool, error) {
	if len(h.state.Auth.PeerCerts) == 0 {
		return nil, nil, fmt.Errorf("control: responder AUTH used certificate signature without CERT payload")
	}
	certs := make([]*x509.Certificate, 0, len(h.state.Auth.PeerCerts))
	for _, der := range h.state.Auth.PeerCerts {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, fmt.Errorf("control: parse responder certificate: %w", err)
		}
		certs = append(certs, c)
	}
	if h.cfg.InsecureSkipPeerCertVerify {
		return certs, nil, nil
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return nil, nil, fmt.Errorf("control: load system trust roots: %w", err)
	}
	return certs, roots, nil
}

// computeSignedOctets builds the RFC 7296 authenticator octets:
//
//	local (isResponder=false): SA_INIT request  | Nr      | MACedID
//	peer  (isResponder=true):  SA_INIT response | Ni      | MACedID
func (h *Handshake) computeSignedOctets(macedID []byte, isResponder bool) ([]byte, error) {
	sel, keys := h.authMaterial()
	if sel == nil || keys == nil {
		return nil, fmt.Errorf("control: IKE key material is missing")
	}
	if isResponder {
		if len(h.state.SAInitResponse) == 0 || len(h.state.InitiatorNonce) == 0 {
			return nil, fmt.Errorf("control: missing SA_INIT response checkpoint or initiator nonce")
		}
		out := make([]byte, 0, len(h.state.SAInitResponse)+len(h.state.InitiatorNonce)+len(macedID))
		out = append(out, h.state.SAInitResponse...)
		out = append(out, h.state.InitiatorNonce...)
		out = append(out, macedID...)
		return out, nil
	}
	if len(h.state.SAInitRequest) == 0 || len(h.state.ResponderNonce) == 0 {
		return nil, fmt.Errorf("control: missing SA_INIT request checkpoint or responder nonce")
	}
	out := make([]byte, 0, len(h.state.SAInitRequest)+len(h.state.ResponderNonce)+len(macedID))
	out = append(out, h.state.SAInitRequest...)
	out = append(out, h.state.ResponderNonce...)
	out = append(out, macedID...)
	return out, nil
}

// authMaterial returns the negotiated selection and IKE keys, or nils.
func (h *Handshake) authMaterial() (*xcrypto.Selection, *xcrypto.IKEKeys) {
	if h.state == nil || h.state.SelectedIKE == nil || h.state.IKEKeys == nil {
		return nil, nil
	}
	return h.state.SelectedIKE, h.state.IKEKeys
}

// localAuthSecret is the initiator AUTH secret: EAP MSK when present, else
// sk_pi (swan2 compute_local_auth_mac).
func (h *Handshake) localAuthSecret() []byte {
	if len(h.state.Auth.LocalEAPMSK) > 0 {
		return h.state.Auth.LocalEAPMSK
	}
	return h.state.IKEKeys.SKpi
}

// peerAuthSecret is the responder AUTH secret: EAP MSK when present, else
// sk_pr (swan2 compute_peer_auth_mac).
func (h *Handshake) peerAuthSecret() []byte {
	if len(h.state.Auth.LocalEAPMSK) > 0 {
		return h.state.Auth.LocalEAPMSK
	}
	return h.state.IKEKeys.SKpr
}

func containsUint16(list []uint16, want uint16) bool {
	for _, have := range list {
		if have == want {
			return true
		}
	}
	return false
}

// validateAuthNotifies enforces the MVP notify policy on IKE_AUTH responses
// (capability notifies accepted, child failure notifies tolerated for final
// AUTH, AUTHENTICATION_FAILED and error codes hard-fail).
func (h *Handshake) validateAuthNotifies(notifies []payload.Notify) error {
	for _, n := range notifies {
		switch {
		case isAllowedAuthNotify(n.Type):
			continue
		case isChildFailureNotify(n.Type):
			continue
		case n.Type == wire.NotifyIKEv2MessageIDSync:
			return fmt.Errorf("control: received unsupported IKEV2_MESSAGE_ID_SYNC notify")
		case n.Type == wire.NotifyAuthenticationFailed:
			h.state.SuppressAuthFailedNotify = true
			h.state.Phase = PhaseFailed
			h.state.FailureReason = "received AUTHENTICATION_FAILED notify"
			return fmt.Errorf("control: received AUTHENTICATION_FAILED notify")
		case n.Type < 16384:
			return fmt.Errorf("control: received IKE_AUTH notify error type %d", uint16(n.Type))
		}
	}
	return nil
}

func isAllowedAuthNotify(t wire.NotifyType) bool {
	switch t {
	case wire.NotifyAdditionalTSPossible,
		wire.NotifyEapOnlyAuthentication,
		wire.NotifyEspTFCPaddingNotSupported,
		wire.NotifyFragmentationSupported,
		wire.NotifyIPCompSupported,
		wire.NotifyIKEv2MessageIDSyncSupported,
		wire.NotifyNonFirstFragmentsAlso,
		wire.NotifyUseTransportMode:
		return true
	}
	return false
}

func isChildFailureNotify(t wire.NotifyType) bool {
	switch t {
	case wire.NotifyNoProposalChosen,
		wire.NotifySinglePairRequired,
		wire.NotifyNoAdditionalSAs,
		wire.NotifyInternalAddressFailure,
		wire.NotifyFailedCPRequired,
		wire.NotifyTSUnacceptable:
		return true
	}
	return false
}

// tsiAnyDualStack builds the TSi payload swan2 offers in bootstrap AUTH:
// IPv4 0.0.0.0-255.255.255.255 plus IPv6 ::-ffff:ffff:....
func tsiAnyDualStack() payload.TrafficSelectors {
	return payload.TrafficSelectors{Selectors: []payload.Selector{
		{Type: wire.TSTypeIPv4AddrRange, StartPort: 0, EndPort: 65535, StartAddr: net.IPv4zero, EndAddr: net.IPv4(255, 255, 255, 255)},
		{Type: wire.TSTypeIPv6AddrRange, StartPort: 0, EndPort: 65535, StartAddr: net.IPv6zero, EndAddr: allOnesIPv6()},
	}}
}

// tsrStrongswanDefault builds the default TSr payload (swan2
// append_tsr_strongswan_default): IPv4 full range, IPv6 2000::/3.
func tsrStrongswanDefault() payload.TrafficSelectors {
	return payload.TrafficSelectors{Selectors: []payload.Selector{
		{Type: wire.TSTypeIPv4AddrRange, StartPort: 0, EndPort: 65535, StartAddr: net.IPv4zero, EndAddr: net.IPv4(255, 255, 255, 255)},
		{Type: wire.TSTypeIPv6AddrRange, StartPort: 0, EndPort: 65535, StartAddr: net.ParseIP("2000::"), EndAddr: net.ParseIP("3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
	}}
}

func allOnesIPv6() net.IP {
	return net.IP{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
}
