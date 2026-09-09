package eap

import (
	"encoding/binary"
	"fmt"
)

// Code is the EAP packet code (RFC 3748 section 4).
type Code uint8

const (
	CodeRequest  Code = 1
	CodeResponse Code = 2
	CodeSuccess  Code = 3
	CodeFailure  Code = 4
)

// Type is the EAP method type (RFC 3748 5.1 registry excerpts used by MVP).
type Type uint8

const (
	TypeIdentity Type = 1
	TypeNAK      Type = 3
	// TypeMSTLV is the Microsoft TLS-length/AVP EAP type used by PEAP
	// inner success/failure mapping (swan2 avp.rs EAP_TYPE_MSTLV).
	TypeMSTLV    Type = 33
	TypePEAP     Type = 25
	TypeMSCHAPV2 Type = 26
)

// Packet is one parsed EAP packet. Data is the area after the type byte for
// Request packets; for Success/Failure (no type) Data is whatever follows
// the 4-byte header.
type Packet struct {
	Code       Code
	Identifier uint8
	Type       Type
	Data       []byte
}

// Parse decodes one peer->method EAP packet with strict length checks
// (declared length must equal the buffer length). Like swan2 parse_eap, it
// accepts Request / Success / Failure and rejects Response and unknown
// codes; requests must carry a type byte.
func Parse(b []byte) (*Packet, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("swan/eap: packet too short: %d bytes", len(b))
	}

	declared := int(binary.BigEndian.Uint16(b[2:4]))
	if declared != len(b) {
		return nil, fmt.Errorf("swan/eap: declared length %d does not match buffer length %d", declared, len(b))
	}

	packet := &Packet{
		Code:       Code(b[0]),
		Identifier: b[1],
	}

	switch packet.Code {
	case CodeRequest:
		if declared < 5 {
			return nil, fmt.Errorf("swan/eap: %s packet missing type byte", codeName(packet.Code))
		}
		packet.Type = Type(b[4])
		packet.Data = b[5:]
	case CodeSuccess, CodeFailure:
		// Success/Failure carry no type byte; any trailing bytes are kept
		// as Data for observability.
		packet.Data = b[4:]
	default:
		return nil, fmt.Errorf("swan/eap: unsupported code %d", packet.Code)
	}

	return packet, nil
}

// BuildRequest builds a complete EAP request/response packet (4-byte header
// + type + data, big-endian length).
func BuildRequest(code Code, id uint8, typ Type, data []byte) []byte {
	hasType := code == CodeRequest || code == CodeResponse
	packetLen := 4 + len(data)
	if hasType {
		packetLen++
	}
	if packetLen > 0xFFFF {
		panic(fmt.Sprintf("swan/eap: packet too large: %d bytes", packetLen))
	}

	out := make([]byte, packetLen)
	out[0] = uint8(code)
	out[1] = id
	binary.BigEndian.PutUint16(out[2:4], uint16(packetLen))
	off := 4
	if hasType {
		out[off] = uint8(typ)
		off++
	}
	copy(out[off:], data)
	return out
}

// codeName returns a short name for error text.
func codeName(c Code) string {
	switch c {
	case CodeRequest:
		return "Request"
	case CodeResponse:
		return "Response"
	case CodeSuccess:
		return "Success"
	case CodeFailure:
		return "Failure"
	default:
		return fmt.Sprintf("code(%d)", c)
	}
}

// Action reports what the method wants next in the outer EAP conversation.
type Action uint8

const (
	// ActionSend sends the built response as EAP payload of a new
	// protected IKE_AUTH request.
	ActionSend Action = iota
	// ActionComplete terminates the method: the MSK is exported and the
	// control layer expects the final IKE_AUTH exchange.
	ActionComplete
)

// Result is one method step result.
type Result struct {
	Action      Action
	Response    []byte // valid when Action == ActionSend
	ExportedMSK []byte // valid when Action == ActionComplete
}

// Method is one EAP peer method FSM. Instances are not safe for concurrent
// use: the eap Worker serializes Handle calls per session.
type Method interface {
	// Name returns the method name ("peap", "mschapv2") for events/logs.
	Name() string
	// Initialize resets the FSM to the first state and validates config.
	Initialize() error
	// Handle consumes the next inbound EAP packet (already stripped of the
	// IKE envelope) and computes the next step. round is the IKE_AUTH
	// message-id of the round and may be used by inner methods.
	Handle(packet []byte, round uint16) (Result, error)
	// Close releases per-session resources (TLS engines, goroutines) once
	// the control layer knows no further Handle calls will arrive. It is
	// safe to call multiple times.
	Close() error
}

// Config selects an EAP method and supplies credentials. Defined here (a
// flat struct) so swan/control and the root swan package can share it
// without importing the method packages.
type Config struct {
	Method   string // "peap" | "mschapv2"
	Identity string
	Password string

	// ServerName is the PEAP TLS server identity (aaa_identity). Required
	// for Method == "peap".
	ServerName string

	// PEAP options (ignored by mschapv2).
	FragmentSize    int
	MaxMessageCount int
	IncludeLength   bool
	// StrongswanCompatible selects the strongSwan-compatible TLS 1.3
	// exporter label for the EAP MSK (standard RFC export otherwise).
	StrongswanCompatible bool
	// InsecureSkipVerify disables PEAP TLS chain verification only;
	// identity is still checked after the tunnel is ready.
	InsecureSkipVerify bool
}
