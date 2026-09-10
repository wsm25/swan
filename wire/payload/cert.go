package payload

import (
	"fmt"

	"github.com/wsm25/swan/wire"
)

// Cert is the body of a CERT payload: encoding byte plus DER data. The MVP
// accepts CertEncodingX509Signature only (rightsendcert=never means we do
// not send our own chain, but IDr/AUTH responses may carry responder certs).
type Cert struct {
	Encoding wire.CertEncoding
	DER      []byte
}

// AppendCert serializes the CERT payload body.
func AppendCert(dst []byte, c Cert) []byte {
	dst = append(dst, byte(c.Encoding))
	return append(dst, c.DER...)
}

// ParseCert decodes the payload and rejects empty bodies.
func ParseCert(b []byte) (Cert, error) {
	if len(b) < 1 {
		return Cert{}, fmt.Errorf("cert payload too short")
	}
	der := b[1:]
	if len(der) == 0 {
		return Cert{}, fmt.Errorf("cert payload is missing der data")
	}
	return Cert{Encoding: wire.CertEncoding(b[0]), DER: der}, nil
}

var _ = wire.PayloadTypeCert
