// Package payload contains one encoder/decoder pair per IKEv2 payload body.
//
// Conventions:
//
//   - Append* functions write into a caller-provided buffer (append-style;
//     they allocate only when the buffer grows) and return the extended
//     slice.
//   - Parse* functions take a payload body (the generic payload header is
//     already removed by swan/wire) and return parsed values plus any
//     remaining bytes. Every length is bounds-checked before use.
//   - No function here encrypts, decrypts, or negotiates anything;
//     algorithm IDs are numeric.
package payload

import "github.com/wsm25/swan/wire"

// Common fixed sizes checked during parsing.
const (
	ProposalHeaderLen  = 8
	TransformHeaderLen = 8
	NotifyFixedLen     = 4
	DeleteFixedLen     = 4
	KeFixedLen         = 4
	IDFixedLen         = 4
	AuthFixedLen       = 4
	ConfigFixedLen     = 4
	ConfigAttrFixedLen = 4
	// TsSelectorFixedLen is the count/reserved header in front of the
	// selectors inside TSi/TSr.
	TsSelectorFixedLen = 4
	TsEntryFixedLen    = 8
)

// placeholder to keep the wire import used by sub-packages even before
// implementations exist (doc-only files may not reference it).
var _ = wire.PayloadTypeNone
