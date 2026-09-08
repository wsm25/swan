package payload

import (
	"fmt"

	"swan/wire"
)

// KeyExchange is the body of a KE payload: DH group number plus the public
// value. The value aliases the input buffer on parse; copies are taken only
// when the key must outlive the datagram (KE is stored for AUTH octets).
type KeyExchange struct {
	DHGroup uint16
	Data    []byte
}

// AppendKE serializes the KE payload body (4-byte header + public value).
func AppendKE(dst []byte, ke KeyExchange) []byte {
	start := len(dst)
	dst = append(dst, 0, 0, 0, 0)
	putUint16(dst[start:start+2], ke.DHGroup)
	return append(dst, ke.Data...)
}

// ParseKE decodes a KE payload body and rejects empty public values.
func ParseKE(b []byte) (KeyExchange, error) {
	if len(b) < KeFixedLen {
		return KeyExchange{}, fmt.Errorf("ke payload too short: %d bytes", len(b))
	}
	data := b[KeFixedLen:]
	if len(data) == 0 {
		return KeyExchange{}, fmt.Errorf("ke payload is missing public key data")
	}
	return KeyExchange{DHGroup: beUint16(b[0:2]), Data: data}, nil
}

var _ = wire.PayloadTypeKE
