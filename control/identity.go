package control

import (
	"bytes"

	"github.com/wsm25/swan/wire"
	"github.com/wsm25/swan/wire/payload"
)

// Identity matching helpers for rightid checking.

// RightIDMatches compares a received ID payload against the configured
// rightid expectation:
//   - zero expected type means wildcard (accept anything);
//   - types must match exactly;
//   - FQDN/RFC822 compare ASCII case-insensitively and support '*' / '?'
//     wildcards (swan2 rightid_matches semantics);
//   - KEY_ID/IP addresses compare the raw bytes.
func RightIDMatches(expected payload.ID, received payload.ID) bool {
	if expected.Type == 0 {
		return true
	}
	if expected.Type != received.Type {
		return false
	}
	switch expected.Type {
	case wire.IDFqdn, wire.IDRfc822Addr:
		return wildcardMatch(expected.Data, received.Data, true)
	default:
		return bytes.Equal(expected.Data, received.Data)
	}
}

// wildcardMatch is the classic two-pointer glob matcher: '*' matches any run
// (including empty), '?' matches exactly one byte, and every other byte
// matches literally (ASCII case-insensitively when fold is set).
func wildcardMatch(pattern, value []byte, fold bool) bool {
	if fold {
		p := make([]byte, len(pattern))
		v := make([]byte, len(value))
		for i, b := range pattern {
			p[i] = asciiLower(b)
		}
		for i, b := range value {
			v[i] = asciiLower(b)
		}
		pattern, value = p, v
	}

	var pi, vi int
	var starPi, starVi = -1, 0
	for vi < len(value) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == value[vi]):
			pi++
			vi++
		case pi < len(pattern) && pattern[pi] == '*':
			starPi = pi
			pi++
			starVi = vi
		case starPi != -1:
			// Backtrack to the last star and consume one more byte.
			pi = starPi + 1
			starVi++
			vi = starVi
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

func asciiLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

var _ = wire.IDType(0)
