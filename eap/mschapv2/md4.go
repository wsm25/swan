package mschapv2

import (
	"encoding/binary"
	"math/bits"
)

// md4 implements the MD4 message digest (RFC 1320) as a small local,
// dependency-free helper: the NT password hash is MD4(UTF-16LE(password)).
// It is unexported on purpose; x/crypto/md4 is deliberately avoided so the
// module stays stdlib-only.
func md4(input []byte) [16]byte {
	const blockLen = 64

	a, b, c, d := uint32(0x67452301), uint32(0xefcdab89), uint32(0x98badcfe), uint32(0x10325476)

	fullBlocks := len(input) / blockLen
	for i := 0; i < fullBlocks; i++ {
		a, b, c, d = md4Transform(a, b, c, d, input[i*blockLen:(i+1)*blockLen])
	}
	tail := input[fullBlocks*blockLen:]

	block := make([]byte, blockLen)
	copy(block, tail)
	block[len(tail)] = 0x80

	// RFC 1320 padding rule: if the length field does not fit into the
	// current block, pad with a whole extra block first.
	if len(tail) >= 56 {
		a, b, c, d = md4Transform(a, b, c, d, block)
		block = make([]byte, blockLen)
	}

	binary.LittleEndian.PutUint64(block[56:64], uint64(len(input))*8)
	a, b, c, d = md4Transform(a, b, c, d, block)

	var out [16]byte
	binary.LittleEndian.PutUint32(out[0:4], a)
	binary.LittleEndian.PutUint32(out[4:8], b)
	binary.LittleEndian.PutUint32(out[8:12], c)
	binary.LittleEndian.PutUint32(out[12:16], d)
	return out
}

// md4Transform processes one 64-byte block through MD4's three rounds.
// The step functions update the tuple in the same positional rotation as
// the reference implementation (a, d, c, b, ...), which is why each step
// returns the tuple shifted one position left with the accumulator first.
func md4Transform(a0, b0, c0, d0 uint32, block []byte) (uint32, uint32, uint32, uint32) {
	var x [16]uint32
	for i := range x {
		x[i] = binary.LittleEndian.Uint32(block[i*4 : i*4+4])
	}

	a, b, c, d := a0, b0, c0, d0

	order1 := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	shifts1 := []uint32{3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19}
	for i := range order1 {
		a, b, c, d = md4StepF(a, b, c, d, x[order1[i]], shifts1[i])
	}

	order2 := []int{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
	shifts2 := []uint32{3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13}
	for i := range order2 {
		a, b, c, d = md4StepG(a, b, c, d, x[order2[i]], shifts2[i])
	}

	order3 := []int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
	shifts3 := []uint32{3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15}
	for i := range order3 {
		a, b, c, d = md4StepH(a, b, c, d, x[order3[i]], shifts3[i])
	}

	return a0 + a, b0 + b, c0 + c, d0 + d
}

func md4F(x, y, z uint32) uint32 { return (x & y) | (^x & z) }
func md4G(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
func md4H(x, y, z uint32) uint32 { return x ^ y ^ z }

// Step functions update the first tuple slot accumulator-style and rotate
// the tuple so the next call accumulates on the slot the reference
// implementation updates next (d, then c, then b).
func md4StepF(a, b, c, d, x, s uint32) (uint32, uint32, uint32, uint32) {
	a = bits.RotateLeft32(a+md4F(b, c, d)+x, int(s))
	return d, a, b, c
}

func md4StepG(a, b, c, d, x, s uint32) (uint32, uint32, uint32, uint32) {
	a = bits.RotateLeft32(a+md4G(b, c, d)+x+0x5a827999, int(s))
	return d, a, b, c
}

func md4StepH(a, b, c, d, x, s uint32) (uint32, uint32, uint32, uint32) {
	a = bits.RotateLeft32(a+md4H(b, c, d)+x+0x6ed9eba1, int(s))
	return d, a, b, c
}
