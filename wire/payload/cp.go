package payload

import (
	"fmt"
	"net"

	"swan/wire"
)

// ConfigAttribute is one configuration attribute (RFC 7296 2.19/3.15.1):
// 16-bit type plus explicit-length value. INTERNAL_IP4_ADDRESS may use the
// zero-length "request" form; replies carry the real value.
type ConfigAttribute struct {
	Type  uint16
	Value []byte
}

// ConfigPayload is the body of a CP payload: type (request/reply) plus
// attributes.
type ConfigPayload struct {
	IsReply    bool
	Attributes []ConfigAttribute
}

// AppendConfigPayload serializes the CP payload body.
func AppendConfigPayload(dst []byte, cp ConfigPayload) []byte {
	cfgType := byte(wire.ConfigTypeRequest)
	if cp.IsReply {
		cfgType = wire.ConfigTypeReply
	}
	start := len(dst)
	dst = append(dst, cfgType, 0, 0, 0)
	_ = start
	for _, attr := range cp.Attributes {
		dst = appendConfigAttribute(dst, attr)
	}
	return dst
}

// ParseConfigPayload decodes the CP payload body with bounds checks.
func ParseConfigPayload(b []byte) (ConfigPayload, error) {
	if len(b) < ConfigFixedLen {
		return ConfigPayload{}, fmt.Errorf("configuration payload too short: %d bytes", len(b))
	}
	switch b[0] {
	case wire.ConfigTypeRequest, wire.ConfigTypeReply:
	default:
		return ConfigPayload{}, fmt.Errorf("unsupported configuration payload type %d", b[0])
	}
	if b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return ConfigPayload{}, fmt.Errorf("configuration payload has non-zero reserved bytes")
	}

	cp := ConfigPayload{IsReply: b[0] == wire.ConfigTypeReply}
	rest := b[ConfigFixedLen:]
	for len(rest) > 0 {
		attr, tail, err := parseConfigAttribute(rest)
		if err != nil {
			return ConfigPayload{}, err
		}
		cp.Attributes = append(cp.Attributes, attr)
		rest = tail
	}
	return cp, nil
}

// AppendConfigRequest builds the MVP CFG_REQUEST body: INTERNAL_IP4_ADDRESS,
// INTERNAL_IP4_DNS, INTERNAL_IP6_ADDRESS, INTERNAL_IP6_DNS — the exact
// request set swan2 sends in bootstrap IKE_AUTH.
func AppendConfigRequest(dst []byte) []byte {
	cp := ConfigPayload{}
	for _, typ := range []uint16{
		wire.ConfigAttrInternalIPv4Address,
		wire.ConfigAttrInternalIPv4DNS,
		wire.ConfigAttrInternalIPv6Address,
		wire.ConfigAttrInternalIPv6DNS,
	} {
		cp.Attributes = append(cp.Attributes, ConfigAttribute{Type: typ})
	}
	return AppendConfigPayload(dst, cp)
}

// ConfigRenewRequest is the caller-level suggested-address bundle for an
// INFORMATIONAL CP(CFG_REQUEST) lease renewal.
type ConfigRenewRequest struct {
	InternalIPv4       net.IP
	InternalIPv6       net.IP
	InternalIPv6Prefix uint8
}

// AppendConfigRenewRequest builds the CFG_REQUEST body for lease renewal:
// it carries the current assigned addresses as non-empty RFC 7296 3.15
// suggestions and re-requests DNS attributes.
func AppendConfigRenewRequest(dst []byte, req ConfigRenewRequest) []byte {
	cp := ConfigPayload{}
	attrs := make([]ConfigAttribute, 0, 4)
	if v4 := req.InternalIPv4.To4(); v4 != nil {
		attrs = append(attrs, ConfigAttribute{Type: wire.ConfigAttrInternalIPv4Address, Value: append([]byte(nil), v4...)})
	}
	attrs = append(attrs, ConfigAttribute{Type: wire.ConfigAttrInternalIPv4DNS})
	if v6 := req.InternalIPv6.To16(); v6 != nil {
		value := make([]byte, 17)
		copy(value, v6)
		value[16] = req.InternalIPv6Prefix
		attrs = append(attrs, ConfigAttribute{Type: wire.ConfigAttrInternalIPv6Address, Value: value})
	}
	attrs = append(attrs, ConfigAttribute{Type: wire.ConfigAttrInternalIPv6DNS})
	cp.Attributes = attrs
	return AppendConfigPayload(dst, cp)
}

func appendConfigAttribute(dst []byte, attr ConfigAttribute) []byte {
	if len(attr.Value) > 0xFFFF {
		panic(fmt.Sprintf("swan/payload: configuration attribute value %d exceeds wire limit 65535", len(attr.Value)))
	}
	start := len(dst)
	dst = append(dst, 0, 0, 0, 0)
	putUint16(dst[start:start+2], attr.Type)
	putUint16(dst[start+2:start+4], uint16(len(attr.Value)))
	return append(dst, attr.Value...)
}

func parseConfigAttribute(b []byte) (ConfigAttribute, []byte, error) {
	if len(b) < ConfigAttrFixedLen {
		return ConfigAttribute{}, nil, fmt.Errorf("configuration attribute too short: %d bytes", len(b))
	}
	typ := beUint16(b[0:2])
	valueLen := int(beUint16(b[2:4]))
	if ConfigAttrFixedLen+valueLen > len(b) {
		return ConfigAttribute{}, nil, fmt.Errorf("configuration attribute value exceeds remaining bytes")
	}
	attr := ConfigAttribute{Type: typ, Value: b[ConfigAttrFixedLen : ConfigAttrFixedLen+valueLen]}
	return attr, b[ConfigAttrFixedLen+valueLen:], nil
}

var _ = wire.PayloadTypeCP
