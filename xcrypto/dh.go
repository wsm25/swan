package xcrypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
)

// DH is the static description of one Diffie-Hellman group. The MVP ships
// X25519 only and hard-fails on any other offered group from the local
// config.
type DH struct {
	TransformID uint16
	Name        string
}

// DHKey is one ephemeral private key for a DH exchange. The underlying
// crypto/ecdh key is fixed after construction; the struct is not safe for
// concurrent use (each handshake owns one).
type DHKey struct {
	dh  DH
	key *ecdh.PrivateKey
}

// GenerateDH creates one ephemeral keypair for the group.
func GenerateDH(group uint16) (*DHKey, error) {
	dh, err := newDH(group)
	if err != nil {
		return nil, err
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("xcrypto: generate X25519 keypair: %w", err)
	}
	return &DHKey{dh: *dh, key: key}, nil
}

// Group reports the negotiated group id.
func (k *DHKey) Group() uint16 {
	return k.dh.TransformID
}

// PublicBytes returns the public key for the KE payload.
func (k *DHKey) PublicBytes() ([]byte, error) {
	if k.key == nil {
		return nil, errors.New("xcrypto: DH private key already consumed")
	}
	return k.key.PublicKey().Bytes(), nil
}

// ECDH derives the shared secret and takes the private key out of play:
// the secret is zeroized after the SKEYSEED derivation has consumed it.
func (k *DHKey) ECDH(peer []byte) ([]byte, error) {
	if k.key == nil {
		return nil, errors.New("xcrypto: DH private key already consumed")
	}
	if len(peer) != 32 {
		return nil, fmt.Errorf("xcrypto: invalid X25519 peer public key length %d", len(peer))
	}
	pub, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return nil, fmt.Errorf("xcrypto: parse X25519 peer public key: %w", err)
	}
	secret, err := k.key.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("xcrypto: derive X25519 shared secret: %w", err)
	}
	k.key = nil
	return secret, nil
}

func newDH(group uint16) (*DH, error) {
	if group == TransformDHCurve25519 {
		return &DH{TransformID: group, Name: "curve25519"}, nil
	}
	return nil, fmt.Errorf("xcrypto: unsupported DH group %d", group)
}
