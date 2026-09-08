package payload

import (
	"fmt"

	"swan/wire"
)

// Auth is the body of an AUTH payload: method byte, 3 reserved bytes and the
// authentication data (MAC or signature per method). Construction and
// verification of Data happen in swan/control (shared-key MIC from the EAP
// MSK) and swan/xcrypto (peer RSA/ECDSA signatures).
type Auth struct {
	Method wire.AuthMethod
	Data   []byte
}

// AppendAuth serializes the AUTH payload body.
func AppendAuth(dst []byte, a Auth) []byte {
	start := len(dst)
	dst = append(dst, byte(a.Method), 0, 0, 0)
	_ = start
	return append(dst, a.Data...)
}

// ParseAuth decodes the payload and rejects truncated bodies or non-zero
// reserved bytes (swan2 verifies the 3 reserved bytes are zero).
func ParseAuth(b []byte) (Auth, error) {
	if len(b) < AuthFixedLen {
		return Auth{}, fmt.Errorf("auth payload too short: %d bytes", len(b))
	}
	if b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return Auth{}, fmt.Errorf("auth payload has non-zero reserved bytes")
	}
	return Auth{Method: wire.AuthMethod(b[0]), Data: b[AuthFixedLen:]}, nil
}

var _ = wire.PayloadTypeAuth
