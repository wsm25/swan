package xcrypto

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
)

// Integrity resolves one IKE integrity/ICV transform:
// HMAC-SHA1-96, HMAC-SHA2-256-128, HMAC-SHA2-384-192, HMAC-SHA2-512-256.
// The special value IntegrityNone (0) is selected with AEAD ciphers only,
// meaning the ICV is supplied by the AEAD tag.
type Integrity struct {
	TransformID uint16
	// OutputLen is the on-wire ICV length produced by Sign (12/16/24/32).
	OutputLen int
	// KeyLen is the IKE key-material split size (AEAD none -> 0).
	KeyLen int

	newHMAC func() hash.Hash
}

// NewIntegrity resolves a transform ID.
func NewIntegrity(id uint16) (*Integrity, error) {
	switch id {
	case TransformIntegrityNone:
		return &Integrity{TransformID: id}, nil
	case TransformIntegrityHMACSHA196:
		return &Integrity{TransformID: id, OutputLen: 12, KeyLen: 20, newHMAC: sha1.New}, nil
	case TransformIntegrityHMACSHA2256128:
		return &Integrity{TransformID: id, OutputLen: 16, KeyLen: 32, newHMAC: sha256.New}, nil
	case TransformIntegrityHMACSHA2384192:
		return &Integrity{TransformID: id, OutputLen: 24, KeyLen: 48, newHMAC: sha512.New384}, nil
	case TransformIntegrityHMACSHA2512256:
		return &Integrity{TransformID: id, OutputLen: 32, KeyLen: 64, newHMAC: sha512.New}, nil
	default:
		return nil, fmt.Errorf("xcrypto: unsupported integrity transform %d", id)
	}
}

// Sign computes the truncated ICV for msg.
func (i *Integrity) Sign(key, msg []byte) ([]byte, error) {
	if i == nil || i.newHMAC == nil {
		return nil, errors.New("xcrypto: no integrity transform (AEAD carries its own tag)")
	}
	if len(key) != i.KeyLen {
		return nil, fmt.Errorf("xcrypto: integrity key length %d, want %d", len(key), i.KeyLen)
	}
	m := hmac.New(i.newHMAC, key)
	m.Write(msg)
	return m.Sum(nil)[:i.OutputLen], nil
}

// Verify recomputes the ICV and compares it in constant time.
func (i *Integrity) Verify(key, msg, icv []byte) bool {
	got, err := i.Sign(key, msg)
	if err != nil || len(got) != len(icv) {
		return false
	}
	return hmac.Equal(got, icv)
}
