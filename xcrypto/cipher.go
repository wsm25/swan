package xcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// EncryptionAlg describes one symmetric IKE/ESP algorithm variant. The
// implementation is standard:
//
//   - AES-CBC  (id 12): crypto/cipher CBC with the IKE/ESP padding handled
//     by the caller (control/protected, esp); no PKCS-style padding here.
//   - AES-CCM  (ids 14/15/16): standard RFC 3610 + RFC 4309 implementation
//     on crypto/aes: AES-CBC-MAC for the tag plus AES-CTR for
//     confidentiality, 11-byte nonce (3B salt + 8B IV), length field L=4.
//   - AES-GCM  (ids 19/20): crypto/cipher GCM, 8-byte IKE IV + 4-byte salt.
type EncryptionAlg struct {
	TransformID     uint16
	Name            string
	TransformKeyLen int // key length advertised in the transform, bytes
	KeyLen          int // key-material split size (transform key + AEAD salt)
	SaltLen         int // AEAD salt appended to the key material
	IVLen           int // explicit IV carried on the wire
	BlockLen        int // padding block size (CBC 16, AEAD 1)
	ICVLen          int // AEAD tag length (CBC: 0, integrity supplies ICV)
	AEAD            bool
}

// NewEncryption resolves (transform id, key length in bytes) to a variant.
func NewEncryption(transformID uint16, keyLen uint16) (*EncryptionAlg, error) {
	if keyLen != 16 && keyLen != 32 {
		return nil, fmt.Errorf("xcrypto: unsupported AES key length %d", keyLen)
	}
	kl := int(keyLen)
	baseName := "aes128"
	if kl == 32 {
		baseName = "aes256"
	}
	switch transformID {
	case TransformEncryptionAESCBC:
		return &EncryptionAlg{
			TransformID: transformID, Name: baseName,
			TransformKeyLen: kl, KeyLen: kl, SaltLen: 0,
			IVLen: 16, BlockLen: 16, ICVLen: 0, AEAD: false,
		}, nil
	case TransformEncryptionAESCCM8, TransformEncryptionAESCCM12, TransformEncryptionAESCCM16:
		tag := 8
		switch transformID {
		case TransformEncryptionAESCCM12:
			tag = 12
		case TransformEncryptionAESCCM16:
			tag = 16
		}
		return &EncryptionAlg{
			TransformID: transformID, Name: fmt.Sprintf("%sccm%d", baseName, tag),
			TransformKeyLen: kl, KeyLen: kl + 3, SaltLen: 3,
			IVLen: 8, BlockLen: 1, ICVLen: tag, AEAD: true,
		}, nil
	case TransformEncryptionAESGCM12, TransformEncryptionAESGCM16:
		tag := 12
		if transformID == TransformEncryptionAESGCM16 {
			tag = 16
		}
		return &EncryptionAlg{
			TransformID: transformID, Name: fmt.Sprintf("%sgcm%d", baseName, tag),
			TransformKeyLen: kl, KeyLen: kl + 4, SaltLen: 4,
			IVLen: 8, BlockLen: 1, ICVLen: tag, AEAD: true,
		}, nil
	default:
		return nil, fmt.Errorf("xcrypto: unsupported encryption transform %d", transformID)
	}
}

// Seal encrypts plaintext under (key, iv, aad) and returns
// ciphertext||tag for AEAD, or bare ciphertext for CBC (the IKE packet
// authenticator is still supplied by the outer ICV). key must contain the
// full key-material split (transform key + AEAD salt).
func (a *EncryptionAlg) Seal(key, iv, aad, plain []byte) ([]byte, error) {
	if err := a.checkKeyIV(key, iv); err != nil {
		return nil, err
	}
	switch {
	case !a.AEAD:
		return a.cbcSeal(key, iv, plain)
	case a.isCCM():
		return a.ccmSeal(key, iv, aad, plain)
	default:
		return a.gcmSeal(key, iv, aad, plain)
	}
}

// Open reverses Seal; AEAD tag mismatch and CBC truncations are errors.
// The authentication context for IKE CBC (the outer ICV) is verified
// separately by Integrity, exactly like swan2.
func (a *EncryptionAlg) Open(key, iv, aad, ciphertext []byte) ([]byte, error) {
	if err := a.checkKeyIV(key, iv); err != nil {
		return nil, err
	}
	switch {
	case !a.AEAD:
		return a.cbcOpen(key, iv, ciphertext)
	case a.isCCM():
		return a.ccmOpen(key, iv, aad, ciphertext)
	default:
		return a.gcmOpen(key, iv, aad, ciphertext)
	}
}

func (a *EncryptionAlg) checkKeyIV(key, iv []byte) error {
	if a == nil {
		return errors.New("xcrypto: nil encryption algorithm")
	}
	if len(key) != a.KeyLen {
		return fmt.Errorf("xcrypto: %s key length %d, want %d", a.Name, len(key), a.KeyLen)
	}
	if len(iv) != a.IVLen {
		return fmt.Errorf("xcrypto: %s IV length %d, want %d", a.Name, len(iv), a.IVLen)
	}
	return nil
}

func (a *EncryptionAlg) isCCM() bool {
	return a.TransformID >= TransformEncryptionAESCCM8 && a.TransformID <= TransformEncryptionAESCCM16
}

// splitAEADKey splits the key-material split into the raw AES key and the
// fixed salt. The wire transform key length is the AES key length.
func (a *EncryptionAlg) splitAEADKey(key []byte) (aesKey, salt []byte) {
	return key[:a.TransformKeyLen], key[a.TransformKeyLen:]
}

// ---- AES-CBC ----

func (a *EncryptionAlg) cbcSeal(key, iv, plain []byte) ([]byte, error) {
	if len(plain)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("xcrypto: AES-CBC plaintext length %d not a multiple of 16", len(plain))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return out, nil
}

func (a *EncryptionAlg) cbcOpen(key, iv, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("xcrypto: AES-CBC ciphertext length %d not a multiple of 16", len(ciphertext))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	return out, nil
}

// ---- AES-GCM ----

// gcmNonce builds the standard 12-byte GCM nonce salt(4) || IV(8).
func (a *EncryptionAlg) gcmNonce(key, iv []byte) ([]byte, error) {
	aesKey, salt := a.splitAEADKey(key)
	_ = aesKey
	nonce := make([]byte, saltLenGCM+ivLenGCM)
	copy(nonce[:saltLenGCM], salt)
	copy(nonce[saltLenGCM:], iv)
	return nonce, nil
}

const (
	saltLenGCM = 4
	ivLenGCM   = 8
)

func (a *EncryptionAlg) gcmSeal(key, iv, aad, plain []byte) ([]byte, error) {
	aesKey, _ := a.splitAEADKey(key)
	nonce, err := a.gcmNonce(key, iv)
	if err != nil {
		return nil, err
	}
	g, err := newGCM(aesKey, a.ICVLen)
	if err != nil {
		return nil, err
	}
	return g.Seal(nil, nonce, plain, aad), nil
}

func (a *EncryptionAlg) gcmOpen(key, iv, aad, ciphertext []byte) ([]byte, error) {
	aesKey, _ := a.splitAEADKey(key)
	nonce, err := a.gcmNonce(key, iv)
	if err != nil {
		return nil, err
	}
	g, err := newGCM(aesKey, a.ICVLen)
	if err != nil {
		return nil, err
	}
	plain, err := g.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("xcrypto: AES-GCM auth/open: %w", err)
	}
	return plain, nil
}

func newGCM(key []byte, tag int) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if tag == 16 {
		return cipher.NewGCM(block)
	}
	return cipher.NewGCMWithTagSize(block, tag)
}

// ---- AES-CCM (RFC 3610 + RFC 4309, length field L=4) ----

// ccmNonce builds the standard RFC 4309 IKE/ESP CCM nonce: the 3-byte key
// salt followed by the 8-byte explicit IV (11 bytes in total).
func (a *EncryptionAlg) ccmNonce(key, iv []byte) []byte {
	_, salt := a.splitAEADKey(key)
	nonce := make([]byte, saltLenCCM+ivLenCCM)
	copy(nonce[:saltLenCCM], salt)
	copy(nonce[saltLenCCM:], iv)
	return nonce
}

const (
	saltLenCCM = 3
	ivLenCCM   = 8
)

func (a *EncryptionAlg) ccmSeal(key, iv, aad, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:a.TransformKeyLen])
	if err != nil {
		return nil, err
	}
	nonce := a.ccmNonce(key, iv)
	fullTag := ccmMAC(block, nonce, aad, plain, a.ICVLen)

	// CTR keystream starts at A0. The first 16 bytes encrypt the full tag;
	// the following bytes encrypt the plaintext (RFC 3610 section 2.2).
	ctr := cipher.NewCTR(block, a.ccmCounterIV(block, nonce))
	var tagKs [16]byte
	ctr.XORKeyStream(tagKs[:], tagKs[:])
	for i := range fullTag {
		fullTag[i] ^= tagKs[i]
	}

	out := make([]byte, len(plain)+a.ICVLen)
	ctr.XORKeyStream(out[:len(plain)], plain)
	copy(out[len(plain):], fullTag[:a.ICVLen])
	return out, nil
}

func (a *EncryptionAlg) ccmOpen(key, iv, aad, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < a.ICVLen {
		return nil, fmt.Errorf("xcrypto: AES-CCM ciphertext too short: %d", len(ciphertext))
	}
	dataLen := len(ciphertext) - a.ICVLen

	block, err := aes.NewCipher(key[:a.TransformKeyLen])
	if err != nil {
		return nil, err
	}
	nonce := a.ccmNonce(key, iv)

	ctr := cipher.NewCTR(block, a.ccmCounterIV(block, nonce))
	var tagKs [16]byte
	ctr.XORKeyStream(tagKs[:], tagKs[:])

	// CCM authenticates the plaintext: decrypt first, then verify the ICV
	// over the recovered plaintext (same order as strongSwan ccm_aead).
	out := make([]byte, dataLen)
	ctr.XORKeyStream(out, ciphertext[:dataLen])

	received := ciphertext[dataLen:]
	tag := make([]byte, a.ICVLen)
	for i := range tag {
		tag[i] = received[i] ^ tagKs[i]
	}
	expected := ccmMAC(block, nonce, aad, out, a.ICVLen)
	if subtle.ConstantTimeCompare(tag, expected[:a.ICVLen]) != 1 {
		return nil, errors.New("xcrypto: AES-CCM auth failed")
	}
	return out, nil
}

// ccmCounterIV builds A0, the initial counter block used to generate the
// keystream: flags(L-1) || nonce(11) || counter(4, zero).
func (a *EncryptionAlg) ccmCounterIV(block cipher.Block, nonce []byte) []byte {
	ctr := make([]byte, block.BlockSize())
	ctr[0] = byte(ccmLenParameter - 1) // L-1, adata bit zero
	copy(ctr[1:], nonce)
	return ctr
}

const ccmLenParameter = 4

// ccmMAC computes the full CBC-MAC over B0 || encoded adata || encoded msg,
// zero-padding every partial block per RFC 3610. tagLen only selects the
// M encoding in the flags byte; the returned value is always the full CBC
// result, because CCM encrypts the full tag before truncating it (RFC 3610
// section 2.2).
func ccmMAC(block cipher.Block, nonce, aad, msg []byte, tagLen int) [16]byte {
	flags := byte((tagLen-2)/2) << 3
	if len(aad) != 0 {
		flags |= 0x40
	}
	flags |= byte(ccmLenParameter - 1)

	var b0 [16]byte
	b0[0] = flags
	copy(b0[1:], nonce)
	putCCMSize(b0[16-ccmLenParameter:], len(msg))
	block.Encrypt(b0[:], b0[:])

	x := b0
	ccmProcess(block, &x, aadEncoding(aad))
	ccmProcess(block, &x, msg)
	return x
}

func putCCMSize(dst []byte, n int) {
	for i := len(dst) - 1; i >= 0; i-- {
		dst[i] = byte(n)
		n >>= 8
	}
}

// aadEncoding returns the length-prefixed, zero-padded adata blocks used by
// the CBC-MAC. The length prefix is 2 bytes below 0xFF00 and the special
// 6-byte form 0xFF FE followed by a 4-byte length above that.
func aadEncoding(aad []byte) []byte {
	if len(aad) == 0 {
		return nil
	}
	var out []byte
	switch {
	case len(aad) < 0xFF00:
		out = make([]byte, 2+len(aad))
		putCCMSize(out[:2], len(aad))
		copy(out[2:], aad)
	default:
		out = make([]byte, 6+len(aad))
		out[0], out[1] = 0xFF, 0xFE
		binary.BigEndian.PutUint32(out[2:6], uint32(len(aad)))
		copy(out[6:], aad)
	}
	if pad := len(out) % 16; pad != 0 {
		out = append(out, make([]byte, 16-pad)...)
	}
	return out
}

// ccmProcess folds each 16-byte (zero-padded) block into the CBC-MAC
// running state x.
func ccmProcess(block cipher.Block, x *[16]byte, data []byte) {
	var buf [16]byte
	for len(data) > 0 {
		n := len(data)
		if n > 16 {
			n = 16
		}
		clear(buf[:])
		copy(buf[:n], data[:n])
		for i := 0; i < 16; i++ {
			buf[i] ^= x[i]
		}
		block.Encrypt(x[:], buf[:])
		data = data[n:]
	}
}
