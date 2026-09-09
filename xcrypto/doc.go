// Package xcrypto owns the cryptographic primitives swan4 needs as plain
// synchronous functions. They run no goroutines; they execute inside
// whatever worker calls them. Implementations use the Go standard library
// only (crypto/aes, crypto/ecdh, crypto/hmac, crypto/rand, crypto/x509,
// and the hash packages):
//
//   - DH: crypto/ecdh X25519
//   - PRF: crypto/hmac (SHA1/SHA256/SHA512)
//   - hash: crypto/sha1|sha256|sha384|sha512
//   - cipher: crypto/cipher AES-CBC, AES-GCM, and AES-CCM built on
//     crypto/aes as RFC 3610/4309 CBC-MAC + CTR
//   - RNG: crypto/rand
//   - x509: crypto/x509 cert chains and responder AUTH signature checks
//
// # Prepared keyed state
//
// EncryptionAlg.Prepare and Integrity.Prepare build keyed AES/HMAC state
// once. The returned PreparedEncryption / PreparedIntegrity values are not
// safe for concurrent use; each ESP Inbound and Outbound worker owns one,
// which removes per-packet cipher/HMAC construction from the data path.
//
// # Proposal/suite behavior
//
// The proposal-string parsing and selection in suite.go uses the same
// strongSwan-style token names and selection order as the swan2 baseline.
// The crypto underneath is standard Go; it is not intended to match rustls
// or ring byte-for-byte except where the protocol derives bytes
// (PRF+, key splits, NAT-D, AUTH MAC).
package xcrypto
