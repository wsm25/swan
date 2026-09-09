package swan

import "strings"

// ErrorKind classifies failures surfaced by the library. Lower layers wrap
// stdlib errors with precise context (section, offset, payload chain path);
// the public Session maps them onto these kinds so callers can switch
// without string matching.
type ErrorKind uint8

const (
	// ErrorDecode marks malformed wire data (IKE/EAP/ESP/CERT ASN.1 ...).
	ErrorDecode ErrorKind = iota
	// ErrorProtocol marks well-formed but protocol-invalid data (bad state
	// transitions, unexpected message-id, invalid flags...).
	ErrorProtocol
	// ErrorNegotiation marks proposal/algorithm negotiation failures.
	ErrorNegotiation
	// ErrorAuth marks peer authentication failures (AUTH, TLS, certificate).
	ErrorAuth
	// ErrorPeerIdentity marks IDr / rightid mismatches.
	ErrorPeerIdentity
	// ErrorClosed marks use of a closed Session or Tunnel.
	ErrorClosed
)

func (k ErrorKind) String() string {
	switch k {
	case ErrorDecode:
		return "decode"
	case ErrorProtocol:
		return "protocol"
	case ErrorNegotiation:
		return "negotiation"
	case ErrorAuth:
		return "auth"
	case ErrorPeerIdentity:
		return "peer_identity"
	case ErrorClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// Error is the optional public error surface. Layers may return any error;
// when structured, it carries the kind plus a human-readable chain.
type Error struct {
	Kind    ErrorKind
	Op      string // operation, e.g. "swan/control: run_sa_init"
	Section string // protocol section, e.g. "payload.KE", "eap.peap.tls"
	Offset  int    // byte offset in the offending datagram, -1 when n/a
	Err     error
}

// Error formats Kind, Op, Section, Offset and the wrapped error chain.
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	var b strings.Builder
	b.WriteString(e.Kind.String())
	if e.Op != "" {
		b.WriteString(": ")
		b.WriteString(e.Op)
	}
	if e.Section != "" {
		b.WriteString(": ")
		b.WriteString(e.Section)
		if e.Offset >= 0 {
			b.WriteString("@")
			b.WriteString(itoa(e.Offset))
		}
	}
	if e.Err != nil {
		b.WriteString(": ")
		b.WriteString(e.Err.Error())
	}
	return b.String()
}

// Unwrap implements errors.Unwrap for the wrapped cause.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
