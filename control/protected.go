package control

import (
	"encoding/binary"
	"fmt"
	"time"

	"swan/transport"
	"swan/wire"
	"swan/xcrypto"
)

// Protected-message helpers: SK/SKF encryption and decryption plus inbound
// fragment reassembly.
//
// Layout follows RFC 7296 3.14 / RFC 7383:
//
//	SK body:  IV (enc.iv_len) | ciphertext | ICV
//	SKF body: fragment-number | total-fragments | IV | ciphertext | ICV
//
// AEAD ciphers authenticate the whole packet prefix (IKE header +
// cleartext payloads) as AAD; non-AEAD ciphers compute the ICV over the
// whole packet up to the ICV bytes, exactly like swan2.

// FragmentPlaintextLimit is the default plaintext size above which
// outbound protected requests split into SKF fragments (only when the peer
// supports fragmentation).
const FragmentPlaintextLimit = 1024

// SkfReassemblyTimeout bounds incomplete inbound SKF reassembly.
const SkfReassemblyTimeout = 15 * time.Second

// skfFirstPayloadUnset is the sentinel stored in
// FragmentReassembly.FirstInnerPayload before fragment 1 arrives. wire
// defines PayloadTypeNone as zero, so zero cannot distinguish "not yet
// seen" from "first fragment declared an empty inner chain".
const skfFirstPayloadUnset wire.PayloadType = 0xff

// buildProtected renders one protected request: plaintext payloads are
// padded (pad len byte, 1..n pattern), encrypted under the IKE keys and
// fragmented into SKFs when required. Returns ready-to-send frames.
func (h *Handshake) buildProtected(exchange wire.ExchangeType, msgID uint32, nextPayload wire.PayloadType, plaintext []byte) ([]*transport.Frame, error) {
	var cfg *Config
	if h != nil {
		cfg = h.cfg
	}
	var state *State
	if h != nil {
		state = h.state
	}
	return buildProtectedStateAs(cfg, state, exchange, msgID, nextPayload, plaintext, wire.FlagInitiator)
}

// buildProtectedState is the package-level protected-message builder for
// initiator-flagged requests, shared by Handshake, Running and the close
// sequence. cfg may be nil (defaults).
func buildProtectedState(cfg *Config, state *State, exchange wire.ExchangeType, msgID uint32, nextPayload wire.PayloadType, plaintext []byte) ([]*transport.Frame, error) {
	return buildProtectedStateAs(cfg, state, exchange, msgID, nextPayload, plaintext, wire.FlagInitiator)
}

// buildProtectedStateAs is buildProtectedState with an explicit header flag
// set: FlagInitiator for requests, FlagResponse for replies to peer
// requests.
func buildProtectedStateAs(cfg *Config, state *State, exchange wire.ExchangeType, msgID uint32, nextPayload wire.PayloadType, plaintext []byte, flags wire.Flags) ([]*transport.Frame, error) {
	if state == nil {
		return nil, fmt.Errorf("control: missing SA state for protected build")
	}
	if state.SelectedIKE == nil || state.IKEKeys == nil {
		return nil, fmt.Errorf("control: IKE cipher state missing for protected build")
	}
	if state.InitiatorSPI == 0 {
		return nil, fmt.Errorf("control: initiator SPI missing for protected build")
	}

	chunk := FragmentPlaintextLimit
	if cfg != nil && cfg.FragmentPlaintextLimit > 0 {
		chunk = cfg.FragmentPlaintextLimit
	}
	total := 1
	if state.Peer.SupportsFragmentation && len(plaintext) > chunk {
		total = (len(plaintext) + chunk - 1) / chunk
	}
	if total > 0xffff {
		return nil, fmt.Errorf("control: too many protected fragments: %d", total)
	}

	frames := make([]*transport.Frame, 0, total)
	for i := 0; i < total; i++ {
		part := plaintext
		if total > 1 {
			start := i * chunk
			end := start + chunk
			if end > len(plaintext) {
				end = len(plaintext)
			}
			part = plaintext[start:end]
		}

		encType := wire.PayloadTypeSK
		var frag *wire.SkfHeader
		innerNext := wire.PayloadTypeNone
		if i == 0 {
			innerNext = nextPayload
		}
		if total > 1 {
			encType = wire.PayloadTypeSKF
			frag = &wire.SkfHeader{
				FragmentNumber: uint16(i + 1),
				TotalFragments: uint16(total),
			}
		}

		frame, err := sealProtectedPacket(state, exchange, msgID, innerNext, encType, frag, part, flags)
		if err != nil {
			return nil, err
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

// sealProtectedPacket builds one complete SK or SKF packet. The caller
// passes one unpadded plaintext chunk; padding is applied here because each
// SKF fragment is padded independently (swan2 push_encrypt semantics).
func sealProtectedPacket(state *State, exchange wire.ExchangeType, msgID uint32, innerNext wire.PayloadType, encType wire.PayloadType, frag *wire.SkfHeader, plaintext []byte, flags wire.Flags) (*transport.Frame, error) {
	sel := state.SelectedIKE
	keys := state.IKEKeys
	enc := sel.Encryption
	integ := sel.Integrity

	if frag != nil && (frag.FragmentNumber == 0 || frag.TotalFragments == 0 || frag.FragmentNumber > frag.TotalFragments) {
		return nil, fmt.Errorf("control: invalid SKF fragment numbers %d/%d", frag.FragmentNumber, frag.TotalFragments)
	}

	ivLen := enc.IVLen
	if ivLen <= 0 {
		return nil, fmt.Errorf("control: invalid IKE cipher IV length %d", ivLen)
	}
	var outerICVLen int
	if enc.AEAD {
		outerICVLen = 0
	} else {
		if integ == nil || integ.KeyLen == 0 {
			return nil, fmt.Errorf("control: non-AEAD IKE cipher has no integrity transform")
		}
		outerICVLen = integ.OutputLen
	}

	hdr := wire.Header{
		InitiatorSPI: wire.Uint64SPI(state.InitiatorSPI),
		ResponderSPI: wire.Uint64SPI(state.ResponderSPI),
		NextPayload:  encType,
		Version:      wire.IKEDefaultVersion,
		ExchangeType: exchange,
		Flags:        flags,
		MessageID:    msgID,
	}
	pkt := hdr.MarshalTo(nil)

	// SK/SKF payload header: next-payload field carries the inner first
	// payload (None for non-first fragments), critical bit clear, length
	// patched below. The SKF fragment header sits before the IV, is not
	// encrypted, and does not participate in plaintext padding.
	payloadHeaderOffset := len(pkt)
	pkt = append(pkt, byte(innerNext), 0, 0, 0)

	fragHeaderLen := 0
	if frag != nil {
		fragHeaderLen = wire.SkfHeaderLen
		fragStart := len(pkt)
		pkt = append(pkt, 0, 0, 0, 0)
		binary.BigEndian.PutUint16(pkt[fragStart:fragStart+2], frag.FragmentNumber)
		binary.BigEndian.PutUint16(pkt[fragStart+2:fragStart+4], frag.TotalFragments)
	}

	padded := padIKEPlaintext(enc, plaintext)

	// sealedLen is the number of bytes appended after the IV. For AEAD this
	// already includes the tag (ciphertext||ICV); for CBC the outer ICV is
	// a separate trailing field. Lengths are patched BEFORE sealing so AEAD
	// auth data and the CBC ICV both cover the final length fields.
	sealedLen := len(padded)
	if enc.AEAD {
		sealedLen += enc.ICVLen
	}
	payloadLen := wire.PayloadHeaderLen + fragHeaderLen + ivLen + sealedLen + outerICVLen
	if payloadLen > 0xffff {
		return nil, fmt.Errorf("control: protected payload too long: %d", payloadLen)
	}
	packetLen := len(pkt) + ivLen + sealedLen + outerICVLen
	if uint64(packetLen) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("control: protected packet too long: %d", packetLen)
	}
	binary.BigEndian.PutUint16(pkt[payloadHeaderOffset+2:payloadHeaderOffset+4], uint16(payloadLen))
	binary.BigEndian.PutUint32(pkt[24:28], uint32(packetLen))

	var aad []byte
	if enc.AEAD {
		aad = append([]byte(nil), pkt...)
	}

	iv := make([]byte, ivLen)
	if err := xcrypto.Fill(iv); err != nil {
		return nil, fmt.Errorf("control: generate IKE IV: %w", err)
	}

	sealed, err := enc.Seal(keys.SKei, iv, aad, padded)
	if err != nil {
		return nil, fmt.Errorf("control: encrypt protected payload: %w", err)
	}

	pkt = append(pkt, iv...)
	pkt = append(pkt, sealed...)

	if !enc.AEAD {
		icv, err := integ.Sign(keys.SKai, pkt)
		if err != nil {
			return nil, fmt.Errorf("control: sign IKE packet: %w", err)
		}
		pkt = append(pkt, icv...)
	}

	return &transport.Frame{Kind: transport.KindIKE, Payload: pkt}, nil
}

// openProtected unwraps one parsed SK envelope: verifies ICV/AEAD tag over
// the re-marshaled AAD prefix, decrypts, strips padding, and returns the
// protected inner payload chain. Parsed SKF envelopes must be handled via
// openProtectedRaw because the parser discards the raw offsets needed for a
// byte-exact AAD reconstruction.
func (h *Handshake) openProtected(m *wire.Message) ([]wire.Payload, error) {
	if m == nil || m.Encrypted == nil {
		return nil, fmt.Errorf("control: message carries no encrypted payload")
	}
	enc := m.Encrypted
	if enc.Fragmented {
		return nil, fmt.Errorf("control: SKF requires raw packet; use openProtectedRaw")
	}
	sel, keys := h.ikeCipherState()
	if sel == nil || keys == nil {
		return nil, fmt.Errorf("control: IKE cipher state missing for protected open")
	}
	aad, err := rebuildPrefix(m)
	if err != nil {
		return nil, err
	}
	plain, err := openEncryptedBody(sel, keys.SKer, keys.SKar, aad, enc.Body)
	if err != nil {
		return nil, err
	}
	payloads, _, err := wire.ParsePayloads(plain, enc.InnerNext, false)
	if err != nil {
		return nil, err
	}
	return payloads, nil
}

// openProtectedRaw decrypts a complete raw IKE packet carrying a terminal SK
// or SKF envelope using the exact byte offsets of the original datagram.
// Skillped for single-fragment and fragmented packets alike. Returns the
// protected inner payload chain.
func (h *Handshake) openProtectedRaw(raw []byte) ([]wire.Payload, error) {
	var cfg *Config
	var state *State
	if h != nil {
		cfg = h.cfg
		state = h.state
	}
	plds, _, err := openProtectedRawState(cfg, state, raw)
	return plds, err
}

// openProtectedRawState implements the raw-offset walk for one packet. It
// returns (innerPayloads, complete, err); complete=false only for incomplete
// SKF reassembly, when it returns (nil, false, nil) like swan2 NeedMore.
func openProtectedRawState(cfg *Config, state *State, raw []byte) ([]wire.Payload, bool, error) {
	if state == nil {
		return nil, false, fmt.Errorf("control: missing SA state for protected open")
	}
	skfTimeout := time.Duration(0)
	if cfg != nil && cfg.Timeouts.SkfReassemblyTimeout > 0 {
		skfTimeout = cfg.Timeouts.SkfReassemblyTimeout
	}
	if skfTimeout <= 0 {
		skfTimeout = SkfReassemblyTimeout
	}
	if state.SelectedIKE == nil || state.IKEKeys == nil {
		return nil, false, fmt.Errorf("control: IKE cipher state missing for protected open")
	}

	hdr, rest, err := wire.ParseHeader(raw)
	if err != nil {
		return nil, false, err
	}

	next := hdr.NextPayload
	off := 0
	for next != wire.PayloadTypeNone {
		if len(rest)-off < wire.PayloadHeaderLen {
			return nil, false, fmt.Errorf("control: protected packet payload header truncated")
		}
		length := int(binary.BigEndian.Uint16(rest[off+2 : off+4]))
		if length < wire.PayloadHeaderLen || off+length > len(rest) {
			return nil, false, fmt.Errorf("control: protected packet payload length out of bounds")
		}

		payloadType := wire.PayloadType(next)
		payloadStart := wire.HeaderLen + off
		bodyStart := payloadStart + wire.PayloadHeaderLen
		innerNext := wire.PayloadType(raw[payloadStart])

		if payloadType == wire.PayloadTypeSK || payloadType == wire.PayloadTypeSKF {
			if off+length != len(rest) {
				return nil, false, fmt.Errorf("control: encrypted payload must terminate the outer chain")
			}
			payloadEnd := payloadStart + length
			encType := payloadType
			var frag wire.SkfHeader
			isSKF := false
			if encType == wire.PayloadTypeSKF {
				if bodyStart+wire.SkfHeaderLen > payloadEnd {
					return nil, false, fmt.Errorf("control: truncated SKF fragment header")
				}
				frag, _, err = wire.ParseSkfHeader(raw[bodyStart : bodyStart+wire.SkfHeaderLen])
				if err != nil {
					return nil, false, err
				}
				isSKF = true
				bodyStart += wire.SkfHeaderLen
			}

			ivStart := bodyStart
			aad := raw[:ivStart]
			body := raw[ivStart:payloadEnd]
			keys := state.IKEKeys
			plain, err := openEncryptedBody(state.SelectedIKE, keys.SKer, keys.SKar, aad, body)
			if err != nil {
				return nil, false, err
			}

			if !isSKF {
				payloads, _, err := wire.ParsePayloads(plain, innerNext, false)
				if err != nil {
					return nil, false, err
				}
				return payloads, true, nil
			}

			envelope := &wire.EncryptedPayload{
				Type:       wire.PayloadTypeSKF,
				InnerNext:  innerNext,
				Fragmented: true,
				Frag:       frag,
				Body:       body,
			}
			fragFirst := skfFirstPayloadUnset
			if state.InboundFragments != nil {
				fragFirst = state.InboundFragments.FirstInnerPayload
			}
			complete, joined, err := collectSKFragment(state, envelope, plain, hdr.MessageID, hdr.ExchangeType, skfTimeout)
			if err != nil {
				return nil, false, err
			}
			if !complete {
				return nil, false, nil
			}
			if fragFirst != skfFirstPayloadUnset {
				envelope.InnerNext = fragFirst
			}
			payloads, _, err := wire.ParsePayloads(joined, envelope.InnerNext, false)
			if err != nil {
				return nil, false, err
			}
			return payloads, true, nil
		}

		next = innerNext
		off += length
	}

	return nil, false, fmt.Errorf("control: protected packet has no encrypted payload")
}

// openEncryptedBody decrypts/authenticates one SK or SKF body
// (IV || ciphertext || ICV) against an already-built AAD prefix.
func openEncryptedBody(sel *xcrypto.Selection, encKey, icvKey []byte, aad, body []byte) ([]byte, error) {
	enc := sel.Encryption
	integ := sel.Integrity
	if len(body) < enc.IVLen {
		return nil, fmt.Errorf("control: protected body shorter than IV")
	}
	iv := body[:enc.IVLen]
	rest := body[enc.IVLen:]

	if enc.AEAD {
		plain, err := enc.Open(encKey, iv, aad, rest)
		if err != nil {
			return nil, fmt.Errorf("control: AEAD protected open failed: %w", err)
		}
		return stripIKEPlaintext(plain)
	}

	if integ == nil || integ.KeyLen == 0 {
		return nil, fmt.Errorf("control: non-AEAD IKE cipher has no integrity transform")
	}
	icvLen := integ.OutputLen
	if len(rest) < icvLen {
		return nil, fmt.Errorf("control: protected body shorter than ICV")
	}
	ct := rest[:len(rest)-icvLen]
	icv := rest[len(rest)-icvLen:]

	signed := append(append([]byte(nil), aad...), iv...)
	signed = append(signed, ct...)
	if !integ.Verify(icvKey, signed, icv) {
		return nil, fmt.Errorf("control: IKE integrity check failed")
	}
	plain, err := enc.Open(encKey, iv, nil, ct)
	if err != nil {
		return nil, fmt.Errorf("control: IKE CBC protected open failed: %w", err)
	}
	return stripIKEPlaintext(plain)
}

// rebuildPrefix reconstructs the byte-exact AAD prefix of a parsed SK
// message (header + cleartext payloads + SK payload header). The critical
// bit of the SK payload header is assumed clear because it is not retained
// by wire.ParseMessage; swan2 treats the encrypted payload as non-critical
// and the MVP never emits critical SK.
func rebuildPrefix(m *wire.Message) ([]byte, error) {
	aad := m.Header.MarshalTo(nil)
	for i := range m.Payloads {
		p := &m.Payloads[i]
		length := wire.PayloadHeaderLen + len(p.Body)
		if length > 0xffff {
			return nil, fmt.Errorf("control: cannot rebuild AAD: payload too long")
		}
		var ph [wire.PayloadHeaderLen]byte
		ph[0] = byte(p.Next)
		if p.Critical {
			ph[1] = 0x80
		}
		binary.BigEndian.PutUint16(ph[2:4], uint16(length))
		aad = append(aad, ph[:]...)
		aad = append(aad, p.Body...)
	}
	if m.Encrypted == nil {
		return nil, fmt.Errorf("control: cannot rebuild AAD: no encrypted payload")
	}
	enc := m.Encrypted
	bodyLen := len(enc.Body)
	if enc.Fragmented {
		bodyLen += wire.SkfHeaderLen
	}
	payloadLen := wire.PayloadHeaderLen + bodyLen
	if payloadLen > 0xffff {
		return nil, fmt.Errorf("control: cannot rebuild AAD: encrypted payload too long")
	}
	var ph [wire.PayloadHeaderLen]byte
	ph[0] = byte(enc.InnerNext)
	binary.BigEndian.PutUint16(ph[2:4], uint16(payloadLen))
	aad = append(aad, ph[:]...)
	if enc.Fragmented {
		var fh [wire.SkfHeaderLen]byte
		binary.BigEndian.PutUint16(fh[0:2], enc.Frag.FragmentNumber)
		binary.BigEndian.PutUint16(fh[2:4], enc.Frag.TotalFragments)
		aad = append(aad, fh[:]...)
	}
	return aad, nil
}

// collectFragment is the Handshake wrapper around the package reassembly
// engine.
func (h *Handshake) collectFragment(enc *wire.EncryptedPayload, plain []byte, msgID uint32, exchange wire.ExchangeType) (complete bool, joined []byte, err error) {
	if h == nil || h.state == nil {
		return false, nil, fmt.Errorf("control: missing SA state for SKF reassembly")
	}
	timeout := SkfReassemblyTimeout
	if h.cfg != nil && h.cfg.Timeouts.SkfReassemblyTimeout > 0 {
		timeout = h.cfg.Timeouts.SkfReassemblyTimeout
	}
	return collectSKFragment(h.state, enc, plain, msgID, exchange, timeout)
}

// collectSKFragment applies the swan2 handle_skf rules: fragments must all
// belong to the same exchange and message-id, a larger total-fragment count
// resets the stored set, only fragment 1 may carry the inner first-payload,
// and the stored set expires after SkfReassemblyTimeout.
func collectSKFragment(state *State, enc *wire.EncryptedPayload, plain []byte, msgID uint32, exchange wire.ExchangeType, timeout time.Duration) (complete bool, joined []byte, err error) {
	if enc == nil || enc.Type != wire.PayloadTypeSKF || !enc.Fragmented {
		return false, nil, fmt.Errorf("control: collectFragment requires an SKF envelope")
	}
	frag := enc.Frag
	if frag.FragmentNumber == 0 || frag.TotalFragments == 0 || frag.FragmentNumber > frag.TotalFragments {
		return false, nil, fmt.Errorf("control: invalid SKF fragment numbers %d/%d", frag.FragmentNumber, frag.TotalFragments)
	}

	now := time.Now()
	existing := state.InboundFragments
	if existing != nil && existing.ExpiresAt.Before(now) {
		existing = nil
		state.InboundFragments = nil
	}
	if existing != nil {
		if existing.ExchangeType != exchange {
			return false, nil, fmt.Errorf("control: SKF exchange mismatch")
		}
		if existing.MessageID != msgID {
			return false, nil, fmt.Errorf("control: SKF message-id mismatch")
		}
		if int(frag.TotalFragments) > len(existing.Fragments) {
			// A previously stored table with fewer fragments becomes stale;
			// swan2 drops it and starts over for the larger expectation.
			existing = nil
			state.InboundFragments = nil
		}
	}

	if existing == nil {
		existing = &FragmentReassembly{
			ExchangeType:      exchange,
			MessageID:         msgID,
			FirstInnerPayload: skfFirstPayloadUnset,
			Fragments:         make([][]byte, int(frag.TotalFragments)),
		}
		state.InboundFragments = existing
	}
	existing.ExpiresAt = now.Add(timeout)

	// An arriving fragment whose declared total is SMALLER than the table
	// we are collecting against is ignored: swan2 keeps waiting for the
	// larger expected set and never mixes different fragment sets.
	if int(frag.TotalFragments) < len(existing.Fragments) {
		return false, nil, nil
	}

	slot := int(frag.FragmentNumber) - 1
	if frag.FragmentNumber == 1 {
		if existing.FirstInnerPayload == skfFirstPayloadUnset {
			existing.FirstInnerPayload = enc.InnerNext
		} else if existing.FirstInnerPayload != enc.InnerNext {
			return false, nil, fmt.Errorf("control: SKF first-fragment payload mismatch")
		}
	} else if enc.InnerNext != wire.PayloadTypeNone {
		return false, nil, fmt.Errorf("control: non-initial SKF fragment must not carry next-payload")
	}

	if existing.Fragments[slot] == nil {
		existing.Fragments[slot] = plain
	}
	for _, part := range existing.Fragments {
		if part == nil {
			return false, nil, nil
		}
	}

	total := 0
	for _, part := range existing.Fragments {
		total += len(part)
	}
	joined = make([]byte, 0, total)
	for _, part := range existing.Fragments {
		joined = append(joined, part...)
	}
	state.InboundFragments = nil
	return true, joined, nil
}

// padIKEPlaintext appends 1..padLen bytes followed by the pad-length byte
// such that len(padded) is a multiple of the cipher padding block.
func padIKEPlaintext(enc *xcrypto.EncryptionAlg, plain []byte) []byte {
	block := enc.BlockLen
	if block < 1 {
		block = 1
	}
	base := len(plain) + 1
	padLen := (block - (base % block)) % block
	padded := append([]byte(nil), plain...)
	for i := 1; i <= padLen; i++ {
		padded = append(padded, byte(i))
	}
	return append(padded, byte(padLen))
}

// stripIKEPlaintext removes the RFC 7296 padding trailer: the trailing byte
// is the pad length, the bytes before it are the pad itself. The decrypted
// (padded) plaintext must be non-empty before the strip; empty inner
// payloads (informational responses) are legal after the strip.
func stripIKEPlaintext(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, fmt.Errorf("control: empty protected plaintext")
	}
	padLen := int(plain[len(plain)-1])
	if padLen >= len(plain) {
		return nil, fmt.Errorf("control: invalid protected padding length %d", padLen)
	}
	return plain[:len(plain)-1-padLen], nil
}

// iconKeyMaterial resolves the directional key halves for the local
// initiator role (outbound = e|a-initiator, inbound = e|a-responder) and is
// the only place directionality is encoded for protected traffic.
func (h *Handshake) ikeCipherState() (*xcrypto.Selection, *xcrypto.IKEKeys) {
	if h == nil || h.state == nil {
		return nil, nil
	}
	return h.state.SelectedIKE, h.state.IKEKeys
}
