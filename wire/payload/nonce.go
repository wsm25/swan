package payload

import (
	"fmt"

	"github.com/wsm25/swan/wire"
)

// Nonce payloads carry the raw nonce bytes; there is no inner structure, so
// the body is the nonce itself. Initiate with xcrypto.GenerateNonce.
//
// AppendNonce exists to keep every payload behind the same append-style
// shape used by AES/AUTH codec call sites.

// AppendNonce writes a NONCE payload body (the bytes themselves).
func AppendNonce(dst []byte, nonce []byte) []byte {
	return append(dst, nonce...)
}

// ParseNonce validates a nonce body: RFC 7296 requires >=16 bytes for MVP
// DH trust, and swan2 generates 32, so the parser only enforces non-empty.
func ParseNonce(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("nonce payload is empty")
	}
	return b, nil
}

var _ = wire.PayloadTypeNonce
