package xcrypto

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

// HashKind names the registered digests.
type HashKind uint8

const (
	HashSHA1 HashKind = iota + 1
	HashSHA256
	HashSHA384
	HashSHA512
)

// Hash is a resolved digest description. Callers that need streaming build
// a hash.Hash via New; one-shot callers use Sum.
type Hash struct {
	Kind      HashKind
	OutputLen int

	newHash func() hash.Hash
}

// SHA1 returns the SHA1 description (NAT-D; PEAP SSL-stack dependency
// mirror only in name — the TLS engine uses crypto/tls).
func SHA1() *Hash {
	return &Hash{Kind: HashSHA1, OutputLen: sha1.Size, newHash: sha1.New}
}

// SHA256 returns the SHA2-256 description.
func SHA256() *Hash {
	return &Hash{Kind: HashSHA256, OutputLen: sha256.Size, newHash: sha256.New}
}

// SHA384 returns the SHA2-384 description.
func SHA384() *Hash {
	return &Hash{Kind: HashSHA384, OutputLen: sha512.Size384, newHash: sha512.New384}
}

// SHA512 returns the SHA2-512 description.
func SHA512() *Hash {
	return &Hash{Kind: HashSHA512, OutputLen: sha512.Size, newHash: sha512.New}
}

// Sum digests data in one call.
func (h *Hash) Sum(data []byte) []byte {
	d := h.New()
	d.Write(data)
	return d.Sum(nil)
}

// New returns a streaming hash.Hash state.
func (h *Hash) New() hash.Hash {
	if h == nil || h.newHash == nil {
		return nil
	}
	return h.newHash()
}

func (h *Hash) ready() error {
	if h == nil || h.newHash == nil {
		return errors.New("xcrypto: uninitialized hash")
	}
	return nil
}
