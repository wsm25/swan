package xcrypto

import "crypto/rand"

// Fill overwrites buf with cryptographically secure random bytes via
// crypto/rand. Callers use it for SPIs, nonces, IKE/ESP IVs and MSCHAPv2
// challenges. The error is returned (rather than panicking) so handshake
// code can fail cleanly on RNG exhaustion.
func Fill(buf []byte) error {
	_, err := rand.Read(buf)
	return err
}

// Read is a thin alias of crypto/rand.Read kept for symmetric APIs that
// already hold their own buffers.
var Read = rand.Read
