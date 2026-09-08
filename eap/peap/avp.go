package peap

import (
	"fmt"

	"swan/eap"
)

// MS-AVP framing for tunneled EAP (strongSwan semantics):
//
//   - A tunneled packet that already parses as a complete inner EAP Request
//     (declared length == bytes) passes through as-is.
//   - Inner Identity requests (len 5, type Identity) pass through.
//   - Server MS-AVP packets (type 33) carrying the success/failure AVP are
//     replaced by a synthetic 4-byte inner Success/Failure packet.
//   - Anything else is wrapped into a synthetic inner Request: the outer
//     eap identifier of the PEAP request is used and the 4-byte EAP header
//     is prepended before the tunneled bytes.
//
// EncodeInnerResponse reverses this for peer->server traffic: Success and
// Failure become MS-AVP responses, other packets are stripped to their
// type-and-data tail.

// MS-AVP success/failure payloads (mirrors strongSwan / swan2 avp.rs).
var (
	msAVPSuccess = []byte{0x80, 0x03, 0x00, 0x02, 0x00, 0x01}
	msAVPFailure = []byte{0x80, 0x03, 0x00, 0x02, 0x00, 0x02}
)

// isMSAVP reports whether tlsData is an 11-byte MSTLV request carrying one
// of the recognized AVPs, and returns its payload.
func isMSAVP(tlsData []byte) ([]byte, bool) {
	if len(tlsData) != 11 || tlsData[4] != byte(eap.TypeMSTLV) {
		return nil, false
	}
	return tlsData[5:], true
}

// completeEAPPacket reports whether b is a self-consistent EAP packet: at
// least 4 bytes with the declared big-endian length equal to len(b).
func completeEAPPacket(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	declared := int(b[2])<<8 | int(b[3])
	return declared == len(b)
}

// completeInnerRequest is swan2's decode_peer_request gate: only a complete
// inner Request is passed through or AVP-mapped; anything else is treated as
// a bare tunneled body and wrapped into a synthetic Request.
func completeInnerRequest(b []byte) bool {
	return completeEAPPacket(b) && eap.Code(b[0]) == eap.CodeRequest
}

// DecodeInnerRequest converts tunneled TLS plaintext into the inner EAP
// request packet the method stack can parse.
func DecodeInnerRequest(tlsData []byte, eapID uint8) ([]byte, error) {
	if len(tlsData) > 4 && completeInnerRequest(tlsData) {
		// 5-byte inner Identity request: pass through untouched.
		if len(tlsData) == 5 && tlsData[4] == byte(eap.TypeIdentity) {
			return append([]byte(nil), tlsData...), nil
		}
		// 11-byte MSTLV request: translate server success/failure AVPs
		// into synthetic inner terminal packets.
		if payload, ok := isMSAVP(tlsData); ok {
			switch {
			case equalBytes(payload, msAVPSuccess):
				return []byte{byte(eap.CodeSuccess), tlsData[1], 0, 4}, nil
			case equalBytes(payload, msAVPFailure):
				return []byte{byte(eap.CodeFailure), tlsData[1], 0, 4}, nil
			default:
				return nil, fmt.Errorf("swan/eap/peap: unknown ms-avp message")
			}
		}
		// Any other complete inner packet passes through.
		return append([]byte(nil), tlsData...), nil
	}

	// Not a complete inner packet: wrap into a synthetic inner Request
	// with the outer PEAP request identifier.
	total := 4 + len(tlsData)
	if total > 65535 {
		return nil, fmt.Errorf("swan/eap/peap: inner eap packet too large: %d", total)
	}
	out := make([]byte, 0, total)
	out = append(out, byte(eap.CodeRequest), eapID, byte(total>>8), byte(total))
	out = append(out, tlsData...)
	return out, nil
}

// EncodeInnerResponse converts a complete inner EAP response into tunneled
// bytes (MS-AVP for success/failure, tail otherwise).
func EncodeInnerResponse(inner []byte) ([]byte, error) {
	if !completeEAPPacket(inner) {
		return nil, fmt.Errorf("swan/eap/peap: inner eap packet too short or length mismatch")
	}
	code := eap.Code(inner[0])
	id := inner[1]

	switch code {
	case eap.CodeSuccess, eap.CodeFailure:
		payload := msAVPPayloadFor(code)
		out := make([]byte, 11)
		out[0] = byte(eap.CodeResponse)
		out[1] = id
		out[2] = 0
		out[3] = 11
		out[4] = byte(eap.TypeMSTLV)
		copy(out[5:], payload)
		return out, nil
	default:
		// Non-terminal inner packets (Request/Response) strip the EAP header:
		// the tunneled bytes are [type, data]. swan2 encode_peer_response
		// applies this to every complete non-success/failure packet.
		if len(inner) < 5 {
			return nil, fmt.Errorf("swan/eap/peap: inner eap packet missing type")
		}
		return append([]byte(nil), inner[4:]...), nil
	}
}

// msAVPPayloadFor maps an inner terminal code to its 6-byte MS-AVP payload.
func msAVPPayloadFor(code eap.Code) []byte {
	if code == eap.CodeSuccess {
		return append([]byte(nil), msAVPSuccess...)
	}
	return append([]byte(nil), msAVPFailure...)
}

func equalBytes(a, b []byte) bool {
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
