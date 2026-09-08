package xcrypto

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// AuthKeyPad is the RFC 7296 section 2.15 key-pad string used to derive the
// AUTH prf keys from the EAP MSK (or sk_pi/sk_pr when no MSK is available).
const AuthKeyPad = "Key Pad for IKEv2"

// IKEKeys is the IKE SA key material split (RFC 7296 2.14):
//
//	{SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr}
//	= prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)
//
// Key lengths follow prf_len + 2*integ_len + 2*enc_len + 2*prf_len where
// AEAD ciphers use integ_len=0 (their key material already includes salt).
type IKEKeys struct {
	SKd  []byte
	SKai []byte
	SKar []byte
	SKei []byte
	SKer []byte
	SKpi []byte
	SKpr []byte
}

// ChildKeys is the CHILD_SA key material:
//
//	prf+(SK_d, Ni | Nr) -> {SK_ei | SK_ai | SK_er | SK_ar}
type ChildKeys struct {
	SKei []byte
	SKai []byte
	SKer []byte
	SKar []byte
}

// SKEYSEED derives prf(Ni | Nr, g^ir) per RFC 7296 2.14.
func SKEYSEED(prf *PRF, Ni, Nr, sharedSecret []byte) ([]byte, error) {
	key := make([]byte, 0, len(Ni)+len(Nr))
	key = append(key, Ni...)
	key = append(key, Nr...)
	return prf.Sum(key, sharedSecret)
}

// DeriveIKEKeys expands SKEYSEED into the seven IKE keys with the lengths
// implied by the selected encryption and integrity transforms.
func DeriveIKEKeys(prf *PRF, skeyseed, Ni, Nr []byte, spiI, spiR uint64, enc *EncryptionAlg, integ *Integrity) (*IKEKeys, error) {
	seed := make([]byte, 0, len(Ni)+len(Nr)+16)
	seed = append(seed, Ni...)
	seed = append(seed, Nr...)
	var spi [16]byte
	binary.BigEndian.PutUint64(spi[:8], spiI)
	binary.BigEndian.PutUint64(spi[8:], spiR)
	seed = append(seed, spi[:]...)

	integLen := 0
	if integ != nil {
		integLen = integ.KeyLen
	}
	total := prf.OutputLen + 2*integLen + 2*enc.KeyLen + 2*prf.OutputLen
	keymat, err := prf.Plus(skeyseed, seed, total)
	if err != nil {
		return nil, err
	}

	off := 0
	take := func(n int) []byte {
		out := make([]byte, n)
		copy(out, keymat[off:off+n])
		off += n
		return out
	}
	return &IKEKeys{
		SKd:  take(prf.OutputLen),
		SKai: take(integLen),
		SKar: take(integLen),
		SKei: take(enc.KeyLen),
		SKer: take(enc.KeyLen),
		SKpi: take(prf.OutputLen),
		SKpr: take(prf.OutputLen),
	}, nil
}

// DeriveChildKeys expands SKd into the four CHILD_SA keys.
func DeriveChildKeys(prf *PRF, skd, Ni, Nr []byte, enc *EncryptionAlg, integ *Integrity) (*ChildKeys, error) {
	seed := make([]byte, 0, len(Ni)+len(Nr))
	seed = append(seed, Ni...)
	seed = append(seed, Nr...)

	integLen := 0
	if integ != nil {
		integLen = integ.KeyLen
	}
	keymat, err := prf.Plus(skd, seed, 2*(enc.KeyLen+integLen))
	if err != nil {
		return nil, err
	}

	off := 0
	take := func(n int) []byte {
		out := make([]byte, n)
		copy(out, keymat[off:off+n])
		off += n
		return out
	}
	return &ChildKeys{
		SKei: take(enc.KeyLen),
		SKai: take(integLen),
		SKer: take(enc.KeyLen),
		SKar: take(integLen),
	}, nil
}

// NatDetectionHash computes RFC 3947/7383 NAT-D hash:
// SHA1(SPIi | SPIr | addr | port), port being the logical NAT-T port.
func NatDetectionHash(spiI, spiR uint64, ip net.IP, port uint16) ([]byte, error) {
	ipBytes := ip.To4()
	if ipBytes == nil {
		ipBytes = ip.To16()
	}
	if ipBytes == nil {
		return nil, errors.New("xcrypto: invalid NAT-D address")
	}

	h := sha1.New()
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], spiI)
	h.Write(b[:])
	binary.BigEndian.PutUint64(b[:], spiR)
	h.Write(b[:])
	h.Write(ipBytes)
	binary.BigEndian.PutUint16(b[:2], port)
	h.Write(b[:2])
	return h.Sum(nil), nil
}

// MACedID computes prf(key, ID payload body) for AUTH signed octets.
func MACedID(prf *PRF, key, idPayload []byte) ([]byte, error) {
	return prf.Sum(key, idPayload)
}

// AuthMAC computes the shared-key AUTH MIC:
// prf(prf(secret, AuthKeyPad), octets).
func AuthMAC(prf *PRF, secret, octets []byte) ([]byte, error) {
	key, err := prf.Sum(secret, []byte(AuthKeyPad))
	if err != nil {
		return nil, err
	}
	return prf.Sum(key, octets)
}

// GenerateSPI returns a random non-zero 64-bit IKE SPI.
func GenerateSPI() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("xcrypto: generate SPI: %w", err)
	}
	v := binary.BigEndian.Uint64(b[:])
	if v == 0 {
		v = 1
	}
	return v, nil
}

// GenerateNonce returns n cryptographically random bytes (swan2 uses 32 for
// both Ni and Nr).
func GenerateNonce(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("xcrypto: invalid nonce length %d", n)
	}
	b := make([]byte, n)
	if err := Fill(b); err != nil {
		return nil, fmt.Errorf("xcrypto: generate nonce: %w", err)
	}
	return b, nil
}
