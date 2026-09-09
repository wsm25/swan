// Package wire implements the syntax layer of IKEv2 packet handling.
//
// It has no crypto, no goroutines, and no IO. Header and payload codecs are
// append-style (write into a caller buffer) or subslice-style (parse returns
// slices of the caller's datagram without copying). Byte fields are
// big-endian and follow the IKEv2 wire layout.
//
// Boundaries:
//
//   - header/message/builder handle the IKE header and the outer payload
//     chain (next-payload chaining, length/critical flags).
//   - swan/wire/payload holds one codec file per payload kind.
//   - SK/SKF bodies are parsed structurally here (IV/ciphertext/ICV stay
//     opaque); encryption, padding, and fragment reassembly belong to
//     swan/control's protected-message helper, which knows the negotiated
//     algorithms and key material.
//   - Transform encoding/decoding is syntax-only: numeric transform IDs and
//     attributes. Algorithm meaning and negotiation live in swan/xcrypto.
package wire
