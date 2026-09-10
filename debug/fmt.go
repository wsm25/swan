// This file contains the centralized log renderers. Rendering is layered:
// Message walks the parsed payload chain and defers each payload to a
// per-type renderer shaped like the RFC view (headers, then attributes,
// then byte dumps for keys/nonces/hashes).

package debug

import (
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/wsm25/swan/transport"
	"github.com/wsm25/swan/wire"
	"github.com/wsm25/swan/wire/payload"
)

// Message renders one parsed IKE message ("recv"/"send"): header summary,
// outer payload chain, and the plaintext chain after the control layer
// unwraps SK. Used only when a debug logger is configured; nil logger turns
// every call into a no-op.
func Message(log *slog.Logger, dir string, m *wire.Message) {
	if log == nil || m == nil {
		return
	}
	h := m.Header
	log.Debug("ike message",
		"dir", dir,
		"exchange", ExchangeName(h.ExchangeType),
		"initiator_spi", fmt.Sprintf("0x%016x", h.InitiatorSPI.Uint64()),
		"responder_spi", fmt.Sprintf("0x%016x", h.ResponderSPI.Uint64()),
		"message_id", h.MessageID,
		"next_payload", PayloadName(h.NextPayload),
		"payload_count", len(m.Payloads),
	)
	for i := range m.Payloads {
		renderPayload(log, dir, &m.Payloads[i])
	}
	if enc := m.Encrypted; enc != nil {
		log.Debug("ike encrypted envelope",
			"dir", dir,
			"type", PayloadName(enc.Type),
			"inner_next", PayloadName(enc.InnerNext),
			"fragmented", enc.Fragmented,
			"frag", fmt.Sprintf("%d/%d", enc.Frag.FragmentNumber, enc.Frag.TotalFragments),
			"body_len", len(enc.Body),
		)
	}
}

// Packet renders one unframed NAT-T datagram by kind (IKE/ESP/NAT-KA).
func Packet(log *slog.Logger, dir string, kind transport.Kind, b []byte) {
	if log == nil {
		return
	}
	switch kind {
	case transport.KindIKE:
		if hdr, _, err := wire.ParseHeader(b); err == nil {
			log.Debug("transport packet",
				"dir", dir,
				"kind", FrameKindName(kind),
				"exchange", ExchangeName(hdr.ExchangeType),
				"initiator_spi", fmt.Sprintf("0x%016x", hdr.InitiatorSPI.Uint64()),
				"responder_spi", fmt.Sprintf("0x%016x", hdr.ResponderSPI.Uint64()),
				"message_id", hdr.MessageID,
				"len", len(b),
			)
			return
		}
		log.Debug("transport packet", "dir", dir, "kind", FrameKindName(kind), "len", len(b))
	case transport.KindESP:
		ESP(log, dir, b)
	case transport.KindKeepalive:
		log.Debug("transport packet", "dir", dir, "kind", FrameKindName(kind), "len", len(b))
	default:
		log.Debug("transport packet", "dir", dir, "kind", FrameKindName(kind), "len", len(b))
	}
}

// Bytes emits a labeled hex dump; secret material (keys, MSKs, hashes) uses
// the same sanitized shape swan2 logs.
func Bytes(log *slog.Logger, dir, label string, b []byte) {
	if log == nil {
		return
	}
	log.Debug("bytes", "dir", dir, "label", label, "len", len(b))
	if len(b) > 0 {
		log.Debug("hex", "dir", dir, "label", label, "dump", hex.EncodeToString(b))
	}
}

// EAP renders one EAP packet (code, identifier, type, flags/opcode detail).
func EAP(log *slog.Logger, dir string, b []byte) {
	if log == nil || len(b) < 4 {
		return
	}
	code, id, typ := b[0], b[1], uint8(0)
	length := int(b[2])<<8 | int(b[3])
	detail := ""
	if length >= 5 {
		typ = b[4]
		switch typ {
		case 25: // PEAP
			if length >= 6 {
				flags := b[5]
				detail = fmt.Sprintf("flags=0x%02x l=%v m=%v s=%v v=%d",
					flags, flags&0x80 != 0, flags&0x40 != 0, flags&0x20 != 0, flags&0x07)
			}
		case 26: // MSCHAPv2
			if length >= 6 {
				op := b[5]
				opName := fmt.Sprintf("opcode=%d", op)
				switch op {
				case 1:
					opName += " CHALLENGE"
				case 2:
					opName += " RESPONSE"
				case 3:
					opName += " SUCCESS"
				case 4:
					opName += " FAILURE"
				}
				detail = opName
			}
		}
	}
	log.Debug("eap packet",
		"dir", dir,
		"code", EAPCodeName(code),
		"identifier", id,
		"type", EAPTypeName(typ),
		"len", length,
		"detail", detail,
	)
}

// ESP renders one UDP-encapsulated ESP datagram summary (SPI, seq, lengths).
func ESP(log *slog.Logger, dir string, b []byte) {
	if log == nil {
		return
	}
	if len(b) < 8 {
		log.Debug("esp packet", "dir", dir, "len", len(b), "note", "truncated header")
		return
	}
	spi := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	seq := uint32(b[4])<<24 | uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7])
	log.Debug("esp packet",
		"dir", dir,
		"spi", fmt.Sprintf("0x%08x", spi),
		"seq", seq,
		"len", len(b),
	)
}

// renderPayload logs one payload with a compact, protocol-shaped summary.
func renderPayload(log *slog.Logger, dir string, p *wire.Payload) {
	name := PayloadName(p.Type)
	attrs := []any{"dir", dir, "payload", name, "len", len(p.Body)}
	switch p.Type {
	case wire.PayloadTypeSA:
		if sa, err := payload.ParseSA(p.Body); err == nil {
			for _, prop := range sa.Proposals {
				attrs = append(attrs, "proposal",
					fmt.Sprintf("num=%d proto=%d spi=%x transforms=%d",
						prop.Num, prop.ProtocolID, prop.SPI, len(prop.Transforms)))
			}
		}
	case wire.PayloadTypeKE:
		if ke, err := payload.ParseKE(p.Body); err == nil {
			attrs = append(attrs, "dh_group", ke.DHGroup, "key_len", len(ke.Data))
		}
	case wire.PayloadTypeNonce:
		attrs = append(attrs, "nonce_len", len(p.Body))
	case wire.PayloadTypeIDi, wire.PayloadTypeIDr:
		if id, err := payload.ParseID(p.Body); err == nil {
			attrs = append(attrs, "id_type", IDTypeName(id.Type), "id", shortString(id.Data))
		}
	case wire.PayloadTypeCert:
		if cert, err := payload.ParseCert(p.Body); err == nil {
			attrs = append(attrs, "encoding", CertEncodingName(uint8(cert.Encoding)), "der_len", len(cert.DER))
		}
	case wire.PayloadTypeAuth:
		if auth, err := payload.ParseAuth(p.Body); err == nil {
			attrs = append(attrs, "method", AuthMethodName(uint8(auth.Method)), "auth_len", len(auth.Data))
		}
	case wire.PayloadTypeNotify:
		if n, err := payload.ParseNotify(p.Body); err == nil {
			attrs = append(attrs, "notify", NotifyName(n.Type), "spi_len", len(n.SPI), "data_len", len(n.Data))
		}
	case wire.PayloadTypeDelete:
		if d, err := payload.ParseDelete(p.Body); err == nil {
			attrs = append(attrs, "protocol", d.ProtocolID, "spis", spisHex(d.SPIs))
		}
	case wire.PayloadTypeTSi, wire.PayloadTypeTSr:
		if ts, err := payload.ParseTS(p.Body); err == nil {
			attrs = append(attrs, "selectors", tsSummary(ts))
		}
	case wire.PayloadTypeCP:
		if cp, err := payload.ParseConfigPayload(p.Body); err == nil {
			attrs = append(attrs, "kind", ConfigTypeName(cp.Kind), "attributes", cpSummary(cp))
		}
	case wire.PayloadTypeEAP:
		EAP(log, dir, p.Body)
	default:
	}
	log.Debug("ike payload", attrs...)
}

func shortString(b []byte) string {
	const max = 48
	if len(b) > max {
		return string(b[:max]) + "..."
	}
	return string(b)
}

func spisHex(spis []uint32) string {
	s := "["
	for i, spi := range spis {
		if i > 0 {
			s += " "
		}
		s += fmt.Sprintf("0x%08x", spi)
	}
	return s + "]"
}

func tsSummary(ts payload.TrafficSelectors) string {
	if len(ts.Selectors) == 0 {
		return "[]"
	}
	s := fmt.Sprintf("%d:[", len(ts.Selectors))
	for i, sel := range ts.Selectors {
		if i > 0 {
			s += " "
		}
		s += fmt.Sprintf("t=%d ports=%d-%d %v..%v",
			sel.Type, sel.StartPort, sel.EndPort, sel.StartAddr, sel.EndAddr)
	}
	return s + "]"
}

func cpSummary(cp payload.ConfigPayload) string {
	s := "["
	for i, attr := range cp.Attributes {
		if i > 0 {
			s += " "
		}
		s += fmt.Sprintf("%s(len=%d)", ConfigAttributeName(attr.Type), len(attr.Value))
	}
	return s + "]"
}
