package wire

// EncryptedPayload is the terminal SK (or one SKF fragment), kept opaque
// here. swan/control unwraps it with the negotiated algorithms and IKE keys;
// this layer only guarantees the envelope below is structurally sound.
type EncryptedPayload struct {
	// Type is PayloadTypeSK or PayloadTypeSKF.
	Type PayloadType
	// InnerNext is the first payload type carried in the protected
	// plaintext. For SKF it is valid only on fragment 1 (0 on others).
	InnerNext PayloadType
	// Fragmented reports whether a SkfHeader is present.
	Fragmented bool
	Frag       SkfHeader
	// Body is IV || ciphertext || ICV, in wire order, undecrypted.
	Body []byte
}

// Message is one parsed IKE packet. Payloads holds the cleartext outer chain
// (in wire order); Encrypted is set when the chain terminated in SK/SKF.
// SK/SKF must be the final outer payload by construction.
type Message struct {
	Header    Header
	Payloads  []Payload
	Encrypted *EncryptedPayload
}

// ParseMessage decodes one complete IKE message: header, outer payload chain
// and the terminal SK/SKF envelope (still encrypted). All returned bodies
// alias the input buffer.
func ParseMessage(b []byte) (*Message, error) {
	hdr, rest, err := ParseHeader(b)
	if err != nil {
		return nil, err
	}
	payloads, encrypted, err := ParsePayloads(rest, hdr.NextPayload, true)
	if err != nil {
		return nil, err
	}
	return &Message{Header: hdr, Payloads: payloads, Encrypted: encrypted}, nil
}

// ParsePayloads walks a payload chain starting at first. When stopAtEncrypted
// is true it stops after a terminal SK/SKF payload and returns the envelope
// via encrypted without recursing into the (encrypted) body.
func ParsePayloads(buf []byte, first PayloadType, stopAtEncrypted bool) (payloads []Payload, encrypted *EncryptedPayload, err error) {
	rest := buf
	next := first
	for next != PayloadTypeNone {
		if len(rest) < PayloadHeaderLen {
			return nil, nil, errPayloadHeader(next, len(rest))
		}

		payloadNext := PayloadType(rest[0])
		critical := rest[1]&0x80 != 0
		length := int(beUint16(rest[2:4]))
		if length < PayloadHeaderLen {
			return nil, nil, errPayloadLength(next, length)
		}
		if length > len(rest) {
			return nil, nil, errPayloadLength(next, length)
		}
		body := rest[PayloadHeaderLen:length]

		currentType := next
		next = payloadNext

		if currentType == PayloadTypeSK || currentType == PayloadTypeSKF {
			if !stopAtEncrypted {
				return nil, nil, errUnexpectedEncrypted(currentType)
			}
			if length != len(rest) {
				return nil, nil, errNotTerminal(currentType, len(rest)-length)
			}
			envelope := &EncryptedPayload{Type: currentType, InnerNext: payloadNext}
			bodyStart := body
			if currentType == PayloadTypeSKF {
				frag, tail, ferr := ParseSkfHeader(body)
				if ferr != nil {
					return nil, nil, ferr
				}
				envelope.Fragmented = true
				envelope.Frag = frag
				bodyStart = tail
			}
			envelope.Body = bodyStart
			return payloads, envelope, nil
		}

		payloads = append(payloads, Payload{
			Type:     currentType,
			Critical: critical,
			Next:     payloadNext,
			Body:     body,
		})
		rest = rest[length:]
	}

	// Cleartext chain terminated with Next Payload = None.
	if len(rest) != 0 {
		return nil, nil, errTrailingBytes(len(rest))
	}
	return payloads, nil, nil
}

// FindPayload returns the first payload of the given type, or nil.
func (m *Message) FindPayload(t PayloadType) *Payload {
	for i := range m.Payloads {
		if m.Payloads[i].Type == t {
			return &m.Payloads[i]
		}
	}
	return nil
}
