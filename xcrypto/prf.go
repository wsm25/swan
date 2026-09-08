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

// PRF is one HMAC-based pseudorandom function (RFC 7296). Only the output
// length differs between the registered variants; the key may be any length.
type PRF struct {
	TransformID uint16
	OutputLen   int

	newHMAC func() hash.Hash
}

// NewPRF resolves a transform ID to its PRF description.
func NewPRF(id uint16) (*PRF, error) {
	switch id {
	case TransformPRFHMACSHA1:
		return &PRF{TransformID: id, OutputLen: 20, newHMAC: sha1.New}, nil
	case TransformPRFHMACSHA256:
		return &PRF{TransformID: id, OutputLen: 32, newHMAC: sha256.New}, nil
	case TransformPRFHMACSHA512:
		return &PRF{TransformID: id, OutputLen: 64, newHMAC: sha512.New}, nil
	default:
		return nil, fmt.Errorf("xcrypto: unsupported PRF transform %d", id)
	}
}

// Sum computes PRF(key, data) once.
func (p *PRF) Sum(key, data []byte) ([]byte, error) {
	if err := p.ready(); err != nil {
		return nil, err
	}
	m := hmac.New(p.newHMAC, key)
	m.Write(data)
	return m.Sum(nil), nil
}

// Fill writes PRF(key, data) into out (len(out) must equal OutputLen).
func (p *PRF) Fill(key, data, out []byte) error {
	if err := p.ready(); err != nil {
		return err
	}
	if len(out) != p.OutputLen {
		return fmt.Errorf("xcrypto: PRF output buffer length %d, want %d", len(out), p.OutputLen)
	}
	m := hmac.New(p.newHMAC, key)
	m.Write(data)
	m.Sum(out[:0])
	return nil
}

// Plus implements PRF+ (RFC 7296 2.14): T1 || T2 || ... truncated to
// outLen, where Tn = PRF(S, T(n-1) | seed | n).
func (p *PRF) Plus(key, seed []byte, outLen int) ([]byte, error) {
	if err := p.ready(); err != nil {
		return nil, err
	}
	if outLen < 0 {
		return nil, errors.New("xcrypto: negative PRF+ output length")
	}
	out := make([]byte, 0, outLen)
	var previous []byte
	for counter := byte(1); len(out) < outLen; counter++ {
		m := hmac.New(p.newHMAC, key)
		m.Write(previous)
		m.Write(seed)
		m.Write([]byte{counter})
		previous = m.Sum(previous[:0])
		out = append(out, previous...)
	}
	return out[:outLen], nil
}

func (p *PRF) ready() error {
	if p == nil || p.newHMAC == nil {
		return errors.New("xcrypto: uninitialized PRF")
	}
	return nil
}
