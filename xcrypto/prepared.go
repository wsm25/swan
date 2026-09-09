package xcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"fmt"
)

// PreparedEncryption is an EncryptionAlg whose AES key schedule and AEAD/CTR
// block state have been constructed once for a fixed key. Seal/Open are
// byte-identical to EncryptionAlg.Seal/Open for the same (alg, key, iv,
// aad, body) inputs, but do not construct a fresh AES block per packet.
//
// PreparedEncryption is not safe for concurrent use. ESP gives each
// Inbound/Outbound instance exactly one goroutine, so that is the intended
// owner.
type PreparedEncryption struct {
	alg   *EncryptionAlg
	block cipher.Block // CBC + CCM AES block
	gcm   cipher.AEAD  // GCM state (tag size fixed)
	salt  []byte       // AEAD salt copied from the key material
}

// Prepare builds the reusable keyed cipher state. key is the full
// key-material split (transform key + AEAD salt), exactly as accepted by
// EncryptionAlg.Seal/Open.
func (a *EncryptionAlg) Prepare(key []byte) (*PreparedEncryption, error) {
	if a == nil {
		return nil, errors.New("xcrypto: nil encryption algorithm")
	}
	if len(key) != a.KeyLen {
		return nil, fmt.Errorf("xcrypto: %s key length %d, want %d", a.Name, len(key), a.KeyLen)
	}

	p := &PreparedEncryption{alg: a}
	switch {
	case !a.AEAD:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		p.block = block
	case a.isCCM():
		block, err := aes.NewCipher(key[:a.TransformKeyLen])
		if err != nil {
			return nil, err
		}
		p.block = block
		p.salt = append([]byte(nil), key[a.TransformKeyLen:]...)
	default:
		aesKey, salt := a.splitAEADKey(key)
		g, err := newGCM(aesKey, a.ICVLen)
		if err != nil {
			return nil, err
		}
		p.gcm = g
		p.salt = append([]byte(nil), salt...)
	}
	return p, nil
}

func (p *PreparedEncryption) checkIV(iv []byte) error {
	if p == nil || p.alg == nil {
		return errors.New("xcrypto: nil prepared encryption")
	}
	if len(iv) != p.alg.IVLen {
		return fmt.Errorf("xcrypto: %s IV length %d, want %d", p.alg.Name, len(iv), p.alg.IVLen)
	}
	return nil
}

// Seal mirrors EncryptionAlg.Seal for the key fixed by Prepare.
func (p *PreparedEncryption) Seal(iv, aad, plain []byte) ([]byte, error) {
	return p.seal(nil, iv, aad, plain)
}

// SealTo behaves like Seal but appends the ciphertext (and AEAD tag) to
// dst, returning the extended slice. dst is normally a slice with the
// already-written ESP header+IV prefix and enough remaining capacity.
func (p *PreparedEncryption) SealTo(dst, iv, aad, plain []byte) ([]byte, error) {
	return p.seal(dst, iv, aad, plain)
}

func (p *PreparedEncryption) seal(dst, iv, aad, plain []byte) ([]byte, error) {
	if err := p.checkIV(iv); err != nil {
		return nil, err
	}
	switch {
	case !p.alg.AEAD:
		return p.cbcSeal(dst, iv, plain)
	case p.alg.isCCM():
		return p.ccmSeal(dst, iv, aad, plain)
	default:
		return p.gcmSeal(dst, iv, aad, plain)
	}
}

// Open mirrors EncryptionAlg.Open for the key fixed by Prepare.
func (p *PreparedEncryption) Open(iv, aad, ciphertext []byte) ([]byte, error) {
	return p.OpenTo(nil, iv, aad, ciphertext)
}

// OpenTo behaves like Open but decrypts into dst, appending the plaintext
// to it. dst is normally a zero-length slice over a reusable buffer with
// enough remaining capacity for the plaintext, so the common ESP inbound
// path performs no per-packet plaintext allocation. On success the result
// is prefix-preserving: dst content before the append is untouched, and the
// returned slice is len(dst)+plaintextLen long.
func (p *PreparedEncryption) OpenTo(dst, iv, aad, ciphertext []byte) ([]byte, error) {
	if err := p.checkIV(iv); err != nil {
		return nil, err
	}
	switch {
	case !p.alg.AEAD:
		return p.cbcOpenTo(dst, iv, ciphertext)
	case p.alg.isCCM():
		return p.ccmOpenTo(dst, iv, aad, ciphertext)
	default:
		return p.gcmOpenTo(dst, iv, aad, ciphertext)
	}
}

// ---- AES-CBC ----

func (p *PreparedEncryption) cbcSeal(dst, iv, plain []byte) ([]byte, error) {
	if len(plain)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("xcrypto: AES-CBC plaintext length %d not a multiple of 16", len(plain))
	}
	base := len(dst)
	out := growDst(dst, len(plain))
	cipher.NewCBCEncrypter(p.block, iv).CryptBlocks(out[base:], plain)
	return out, nil
}

func (p *PreparedEncryption) cbcOpenTo(dst, iv, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("xcrypto: AES-CBC ciphertext length %d not a multiple of 16", len(ciphertext))
	}
	base := len(dst)
	out := growDst(dst, len(ciphertext))
	cipher.NewCBCDecrypter(p.block, iv).CryptBlocks(out[base:], ciphertext)
	return out, nil
}

// ---- AES-GCM ----

func (p *PreparedEncryption) gcmNonce(iv []byte) [saltLenGCM + ivLenGCM]byte {
	var nonce [saltLenGCM + ivLenGCM]byte
	copy(nonce[:saltLenGCM], p.salt)
	copy(nonce[saltLenGCM:], iv)
	return nonce
}

func (p *PreparedEncryption) gcmSeal(dst, iv, aad, plain []byte) ([]byte, error) {
	nonce := p.gcmNonce(iv)
	return p.gcm.Seal(dst, nonce[:], plain, aad), nil
}

func (p *PreparedEncryption) gcmOpenTo(dst, iv, aad, ciphertext []byte) ([]byte, error) {
	nonce := p.gcmNonce(iv)
	plain, err := p.gcm.Open(dst, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("xcrypto: AES-GCM auth/open: %w", err)
	}
	return plain, nil
}

// ---- AES-CCM (RFC 3610 + RFC 4309, length field L=4) ----

func (p *PreparedEncryption) ccmNonce(iv []byte) [saltLenCCM + ivLenCCM]byte {
	var nonce [saltLenCCM + ivLenCCM]byte
	copy(nonce[:saltLenCCM], p.salt)
	copy(nonce[saltLenCCM:], iv)
	return nonce
}

func (p *PreparedEncryption) ccmSeal(dst, iv, aad, plain []byte) ([]byte, error) {
	nonce := p.ccmNonce(iv)
	fullTag := ccmMAC(p.block, nonce[:], aad, plain, p.alg.ICVLen)

	ctr := cipher.NewCTR(p.block, p.alg.ccmCounterIV(p.block, nonce[:]))
	var tagKs [16]byte
	ctr.XORKeyStream(tagKs[:], tagKs[:])
	for i := range fullTag {
		fullTag[i] ^= tagKs[i]
	}

	base := len(dst)
	out := growDst(dst, len(plain)+p.alg.ICVLen)
	ctr.XORKeyStream(out[base:base+len(plain)], plain)
	copy(out[base+len(plain):], fullTag[:p.alg.ICVLen])
	return out, nil
}

func (p *PreparedEncryption) ccmOpenTo(dst, iv, aad, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < p.alg.ICVLen {
		return nil, fmt.Errorf("xcrypto: AES-CCM ciphertext too short: %d", len(ciphertext))
	}
	dataLen := len(ciphertext) - p.alg.ICVLen

	nonce := p.ccmNonce(iv)
	ctr := cipher.NewCTR(p.block, p.alg.ccmCounterIV(p.block, nonce[:]))
	var tagKs [16]byte
	ctr.XORKeyStream(tagKs[:], tagKs[:])

	base := len(dst)
	out := growDst(dst, dataLen)
	ctr.XORKeyStream(out[base:], ciphertext[:dataLen])

	received := ciphertext[dataLen:]
	tag := make([]byte, p.alg.ICVLen)
	for i := range tag {
		tag[i] = received[i] ^ tagKs[i]
	}
	expected := ccmMAC(p.block, nonce[:], aad, out[base:], p.alg.ICVLen)
	if subtle.ConstantTimeCompare(tag, expected[:p.alg.ICVLen]) != 1 {
		return nil, errors.New("xcrypto: AES-CCM auth failed")
	}
	return out, nil
}

func growDst(dst []byte, n int) []byte {
	if cap(dst)-len(dst) >= n {
		return dst[:len(dst)+n]
	}
	out := make([]byte, len(dst)+n)
	copy(out, dst)
	return out
}
