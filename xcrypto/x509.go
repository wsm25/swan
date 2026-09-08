package xcrypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"unicode/utf8"
)

// Signature hash algorithm IDs from the SIGNATURE_HASH_ALGORITHMS notify
// (swan2 advertises 2/3/4 = SHA2-256/384/512).
const (
	HashAlgorithmSHA256 uint16 = 2
	HashAlgorithmSHA384 uint16 = 3
	HashAlgorithmSHA512 uint16 = 4
)

// PublicKeyType narrows AUTH method 14 verification to RSA or ECDSA per the
// AlgorithmIdentifier of the signature value.
type PublicKeyType uint8

const (
	PublicKeyRSA PublicKeyType = iota + 1
	PublicKeyECDSA
)

// SignatureAlgorithm is the parsed AUTH method 14 AlgorithmIdentifier:
// hash algorithm plus expected key type.
type SignatureAlgorithm struct {
	HashID  uint16
	Hash    *Hash
	KeyType PublicKeyType
}

// sigAlgID is one supported AUTH method 14 AlgorithmIdentifier (the exact
// ASN.1 DER byte strings swan2 peer_auth.rs recognizes).
type sigAlgID struct {
	der     []byte
	hashID  uint16
	hashFn  func() *Hash
	keyType PublicKeyType
}

var signatureAlgIDs = []sigAlgID{
	{[]byte{0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00}, HashAlgorithmSHA256, SHA256, PublicKeyRSA},
	{[]byte{0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c, 0x05, 0x00}, HashAlgorithmSHA384, SHA384, PublicKeyRSA},
	{[]byte{0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x05, 0x00}, HashAlgorithmSHA512, SHA512, PublicKeyRSA},
	{[]byte{0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}, HashAlgorithmSHA256, SHA256, PublicKeyECDSA},
	{[]byte{0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03}, HashAlgorithmSHA384, SHA384, PublicKeyECDSA},
	{[]byte{0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04}, HashAlgorithmSHA512, SHA512, PublicKeyECDSA},
}

// ParseSignatureAuthData splits AUTH method 14 data into its
// AlgorithmIdentifier (ASN.1 length-prefixed) and signature value, and maps
// the six supported identifiers (RSA/ECDSA with SHA256/384/512).
func ParseSignatureAuthData(data []byte) (SignatureAlgorithm, []byte, error) {
	if len(data) < 2 {
		return SignatureAlgorithm{}, nil, errors.New("xcrypto: AUTH method 14 data too short")
	}
	algLen := int(data[0])
	if algLen == 0 || len(data) <= 1+algLen {
		return SignatureAlgorithm{}, nil, errors.New("xcrypto: AUTH method 14 missing AlgorithmIdentifier")
	}
	algID := data[1 : 1+algLen]
	signature := data[1+algLen:]

	for _, entry := range signatureAlgIDs {
		if bytes.Equal(algID, entry.der) {
			return SignatureAlgorithm{HashID: entry.hashID, Hash: entry.hashFn(), KeyType: entry.keyType}, signature, nil
		}
	}
	return SignatureAlgorithm{}, nil, fmt.Errorf("xcrypto: unsupported AUTH method 14 AlgorithmIdentifier %x", algID)
}

// VerifyCertificateChain verifies leaf (with intermediates) against the
// provided trust pool for serverAuth usage, honoring the MVP's optional
// skip (which skips chain verification only — identity/signature are still
// checked by the callers). nil roots falls back to the system pool.
func VerifyCertificateChain(leaf *x509.Certificate, intermediates []*x509.Certificate, roots *x509.CertPool, skipVerify bool) error {
	if skipVerify {
		return nil
	}
	if leaf == nil {
		return errors.New("xcrypto: missing responder leaf certificate")
	}
	if roots == nil {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			return fmt.Errorf("xcrypto: load system trust anchors: %w", err)
		}
	}
	pool := x509.NewCertPool()
	for _, cert := range intermediates {
		pool.AddCert(cert)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: pool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("xcrypto: verify responder certificate chain: %w", err)
	}
	return nil
}

// VerifyPeerAuthSignature performs the full responder AUTH signature check:
// cert chain verification, IDr identity match (FQDN/IP SAN; RFC822 and
// KEY_ID hard-fail for the MVP) and the RSA PKCS1v15 / ECDSA signature over
// the signed octets.
func VerifyPeerAuthSignature(certs []*x509.Certificate, idType uint8, idData, octets, signature []byte, alg SignatureAlgorithm, roots *x509.CertPool, skipChainVerify bool) error {
	if len(certs) == 0 {
		return errors.New("xcrypto: responder AUTH used a certificate signature without CERT payload")
	}
	leaf := certs[0]
	intermediates := certs[1:]

	if err := VerifyCertificateChain(leaf, intermediates, roots, skipChainVerify); err != nil {
		return err
	}
	if err := verifyCertIdentity(leaf, idType, idData); err != nil {
		return err
	}
	return verifySignature(leaf, octets, signature, alg)
}

func verifyCertIdentity(leaf *x509.Certificate, idType uint8, idData []byte) error {
	switch idType {
	case 2: // FQDN
		if !utf8.Valid(idData) {
			return errors.New("xcrypto: IDr FQDN is not valid UTF-8")
		}
		if err := leaf.VerifyHostname(string(idData)); err != nil {
			return fmt.Errorf("xcrypto: responder certificate does not match IDr FQDN: %w", err)
		}
	case 1: // IPv4 address (wire form is the raw 4 address bytes)
		if len(idData) != net.IPv4len {
			return fmt.Errorf("xcrypto: invalid IDr IPv4 address length %d", len(idData))
		}
		ip := net.IPv4(idData[0], idData[1], idData[2], idData[3])
		if err := leaf.VerifyHostname(ip.String()); err != nil {
			return fmt.Errorf("xcrypto: responder certificate does not match IDr IP address: %w", err)
		}
	case 5: // IPv6 address (wire form is the raw 16 address bytes)
		if len(idData) != net.IPv6len {
			return fmt.Errorf("xcrypto: invalid IDr IPv6 address length %d", len(idData))
		}
		ip := make(net.IP, net.IPv6len)
		copy(ip, idData)
		if err := leaf.VerifyHostname(ip.String()); err != nil {
			return fmt.Errorf("xcrypto: responder certificate does not match IDr IP address: %w", err)
		}
	case 3: // RFC822 address
		return errors.New("xcrypto: certificate identity verification does not support RFC822 IDr for MVP")
	case 11: // KEY_ID
		return errors.New("xcrypto: certificate identity verification does not support KEY_ID IDr for MVP")
	default:
		return fmt.Errorf("xcrypto: unsupported IDr type %d for certificate identity verification", idType)
	}
	return nil
}

func verifySignature(leaf *x509.Certificate, octets, signature []byte, alg SignatureAlgorithm) error {
	if alg.Hash == nil {
		return errors.New("xcrypto: signature algorithm has no assigned hash")
	}
	digest := alg.Hash.Sum(octets)
	switch alg.KeyType {
	case PublicKeyRSA:
		pub, ok := leaf.PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("xcrypto: AUTH method 14 declared RSA, peer certificate is not RSA")
		}
		if err := rsa.VerifyPKCS1v15(pub, sigCryptoHash(alg.Hash.Kind), digest, signature); err != nil {
			return fmt.Errorf("xcrypto: AUTH RSA signature verification failed: %w", err)
		}
	case PublicKeyECDSA:
		pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("xcrypto: AUTH method 14 declared ECDSA, peer certificate is not ECDSA")
		}
		if !ecdsa.VerifyASN1(pub, digest, signature) {
			return errors.New("xcrypto: AUTH ECDSA signature verification failed")
		}
	default:
		return fmt.Errorf("xcrypto: unsupported AUTH method 14 public key type %d", alg.KeyType)
	}
	return nil
}

func sigCryptoHash(kind HashKind) crypto.Hash {
	switch kind {
	case HashSHA1:
		return crypto.SHA1
	case HashSHA256:
		return crypto.SHA256
	case HashSHA384:
		return crypto.SHA384
	case HashSHA512:
		return crypto.SHA512
	default:
		return 0
	}
}
