package payload

import (
	"fmt"
	"net"
	"strings"

	"swan/wire"
)

// ID is the body of an IDi/IDr payload: type byte plus the identifier data.
// Empty data is rejected on construction: every identity the MVP sends or
// accepts is non-empty.
type ID struct {
	Type wire.IDType
	Data []byte
}

// AppendID serializes the ID payload body (type, 3 reserved bytes, data).
func AppendID(dst []byte, id ID) []byte {
	dst = append(dst, byte(id.Type), 0, 0, 0)
	return append(dst, id.Data...)
}

// ParseID decodes the payload and rejects truncated bodies.
func ParseID(b []byte) (ID, error) {
	if len(b) < IDFixedLen {
		return ID{}, fmt.Errorf("id payload too short: %d bytes", len(b))
	}
	data := b[IDFixedLen:]
	if len(data) == 0 {
		return ID{}, fmt.Errorf("id payload is missing identity data")
	}
	return ID{Type: wire.IDType(b[0]), Data: data}, nil
}

// ClassifyID maps a strongswan-style identity string to an ID payload:
//
//	keyid:X | @#X | #X     -> KEY_ID
//	fqdn:X | dns:X | %X | @X -> FQDN
//	rfc822:X | email:X | userfqdn:X | @@X -> RFC822_ADDR
//	ipv4:X (parseable)     -> IPV4_ADDR
//	ipv6:X (parseable)     -> IPV6_ADDR
//	bare parseable IP      -> IPV4/IPV6_ADDR
//	X containing "@"       -> RFC822_ADDR
//	otherwise              -> FQDN
func ClassifyID(s string) (ID, error) {
	value := strings.TrimSpace(s)
	if value == "" {
		return ID{}, fmt.Errorf("identity must not be empty")
	}

	// Ordered prefix table, checked before generic rules (swan2 order).
	if rest, ok := trimPrefix(value, "keyid:"); ok {
		return keyID(rest)
	}
	if rest, ok := trimPrefix(value, "@#"); ok {
		return keyID(rest)
	}
	if rest, ok := trimPrefix(value, "#"); ok {
		return keyID(rest)
	}
	if rest, ok := trimPrefix(value, "fqdn:", "dns:", "%"); ok {
		return id(wire.IDFqdn, rest)
	}
	if rest, ok := trimPrefix(value, "rfc822:", "email:", "userfqdn:", "@@"); ok {
		return id(wire.IDRfc822Addr, rest)
	}
	if rest, ok := trimPrefix(value, "@"); ok && !strings.HasPrefix(value, "@@") {
		return id(wire.IDFqdn, rest)
	}
	if rest, ok := trimPrefix(value, "ipv4:"); ok {
		if net.ParseIP(rest).To4() == nil {
			return ID{}, fmt.Errorf("identity %q is not a valid ipv4 address", value)
		}
		return id(wire.IDIPv4Addr, rest)
	}
	if rest, ok := trimPrefix(value, "ipv6:"); ok {
		if ip := net.ParseIP(rest); ip == nil || ip.To4() != nil {
			return ID{}, fmt.Errorf("identity %q is not a valid ipv6 address", value)
		}
		return id(wire.IDIPv6Addr, rest)
	}
	if strings.Contains(value, "@") {
		return id(wire.IDRfc822Addr, value)
	}
	if ip := net.ParseIP(value); ip != nil {
		if ip.To4() != nil {
			return id(wire.IDIPv4Addr, value)
		}
		return id(wire.IDIPv6Addr, value)
	}
	return id(wire.IDFqdn, value)
}

func keyID(v string) (ID, error) {
	return id(wire.IDKeyID, v)
}

func id(typ wire.IDType, v string) (ID, error) {
	if v == "" {
		return ID{}, fmt.Errorf("identity value must not be empty")
	}
	return ID{Type: typ, Data: []byte(v)}, nil
}

func trimPrefix(v string, prefixes ...string) (string, bool) {
	for _, p := range prefixes {
		if p == "" {
			continue
		}
		if tail, ok := strings.CutPrefix(v, p); ok {
			return strings.TrimSpace(tail), true
		}
	}
	return v, false
}

var _ = wire.PayloadTypeIDi
