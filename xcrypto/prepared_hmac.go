package xcrypto

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"hash"
)

// PreparedIntegrity is an Integrity whose HMAC state has been keyed once.
// Sign/Verify are byte-identical to Integrity.Sign/Verify for the same
// (integrity, key, msg, icv) inputs without constructing a fresh HMAC per
// packet.
//
// PreparedIntegrity is not safe for concurrent use; the ESP Inbound and
// Outbound workers each own one.
type PreparedIntegrity struct {
	outputLen int
	h         hash.Hash
}

// Prepare binds the key and one reusable HMAC state.
func (i *Integrity) Prepare(key []byte) (*PreparedIntegrity, error) {
	if i == nil || i.newHMAC == nil {
		return nil, errors.New("xcrypto: no integrity transform (AEAD carries its own tag)")
	}
	if len(key) != i.KeyLen {
		return nil, fmt.Errorf("xcrypto: integrity key length %d, want %d", len(key), i.KeyLen)
	}
	return &PreparedIntegrity{outputLen: i.OutputLen, h: hmac.New(i.newHMAC, key)}, nil
}

// Sign computes the truncated ICV for msg.
func (p *PreparedIntegrity) Sign(msg []byte) ([]byte, error) {
	if p == nil || p.h == nil {
		return nil, errors.New("xcrypto: no prepared integrity transform")
	}
	p.h.Reset()
	p.h.Write(msg)
	return p.h.Sum(nil)[:p.outputLen], nil
}

// Verify recomputes the ICV and compares it in constant time.
func (p *PreparedIntegrity) Verify(msg, icv []byte) bool {
	got, err := p.Sign(msg)
	if err != nil || len(got) != len(icv) {
		return false
	}
	return hmac.Equal(got, icv)
}
