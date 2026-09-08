// Package xcrypto owns every cryptographic primitive the MVP needs, as
// plain synchronous functions (no goroutines): they execute inside whatever
// worker calls them. All implementations are standard Go (stdlib +
// x/crypto), no cgo:
//
//   - DH:     crypto/ecdh X25519
//   - PRF:    crypto/hmac (SHA1/SHA256/SHA512)
//   - hash:   crypto/sha1|sha256|sha384|sha512 (+ export-length discipline)
//   - cipher: crypto/cipher AES-CBC, crypto/cipher GCM, and CCM implemented
//     on crypto/aes as RFC 3610/4309 CBC-MAC + CTR
//   - RNG:    crypto/rand
//   - x509:   crypto/x509 cert chains and responder AUTH signatures
//
// Behavioral alignment: the suite/negotiation semantics mirror the swan2
// MVP (same transform IDs, same selection order), but the implementations
// are standard Go — nothing here is written to byte-match rustls or ring.
package xcrypto
