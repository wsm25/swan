package xcrypto

import (
	"errors"
	"fmt"
)

// Transform IDs registered by this library (RFC 7296 IANA numbers).
// The full registry table lives here, not in swan/wire: algorithm meaning
// belongs to the crypto layer; swan/wire can only see syntax (numbers).
const (
	// DH groups.
	TransformDHCurve25519 uint16 = 31

	// PRFs.
	TransformPRFHMACSHA1   uint16 = 2
	TransformPRFHMACSHA256 uint16 = 5
	TransformPRFHMACSHA512 uint16 = 7

	// Integrity algorithms.
	TransformIntegrityNone           uint16 = 0
	TransformIntegrityHMACSHA196     uint16 = 2
	TransformIntegrityHMACSHA2256128 uint16 = 12
	TransformIntegrityHMACSHA2384192 uint16 = 13
	TransformIntegrityHMACSHA2512256 uint16 = 14

	// Encryption algorithms (transform key length is the second selector).
	TransformEncryptionAESCBC   uint16 = 12
	TransformEncryptionAESCCM8  uint16 = 14
	TransformEncryptionAESCCM12 uint16 = 15
	TransformEncryptionAESCCM16 uint16 = 16
	TransformEncryptionAESGCM12 uint16 = 19
	TransformEncryptionAESGCM16 uint16 = 20
)

// Best defines the default algorithm preference order for the MVP
// (strongswan style, AES-GCM16 > AES-GCM12 > CCM16 > ... with PRF-HMAC-SHA2
// and Curve25519).
const Best = "aes256gcm16-prfsha512-curve25519"

// EncryptionID is one offered encryption transform: algorithm + transform
// key length in bytes (16/32 for AES; the wire KEY_LENGTH attribute is
// derived in bits).
type EncryptionID struct {
	TransformID uint16
	KeyLen      uint16
}

// Proposal lists algorithms per transform family, in local preference order.
// It mirrors one strongswan proposal string.
type Proposal struct {
	Encryption []EncryptionID
	Integrity  []uint16
	PRF        []uint16
	DH         []uint16
}

// Selection is the negotiated outcome: concrete algorithm objects plus
// their cipher metadata. It is read-only after selection and may be shared
// across workers by pointer.
type Selection struct {
	Encryption *EncryptionAlg
	Integrity  *Integrity
	PRF        *PRF
	DH         *DH
}

// Strongswan-style token tables. A token belongs to exactly one family;
// exact-match lookups make "aes256" and "aes256ccm8" unambiguous.
var encryptionTokens = map[string]EncryptionID{
	"aes":          {TransformEncryptionAESCBC, 16},
	"aes128":       {TransformEncryptionAESCBC, 16},
	"aes256":       {TransformEncryptionAESCBC, 32},
	"aes128ccm8":   {TransformEncryptionAESCCM8, 16},
	"aes128ccm64":  {TransformEncryptionAESCCM8, 16},
	"aes128ccm12":  {TransformEncryptionAESCCM12, 16},
	"aes128ccm96":  {TransformEncryptionAESCCM12, 16},
	"aes128ccm16":  {TransformEncryptionAESCCM16, 16},
	"aes128ccm128": {TransformEncryptionAESCCM16, 16},
	"aes256ccm8":   {TransformEncryptionAESCCM8, 32},
	"aes256ccm64":  {TransformEncryptionAESCCM8, 32},
	"aes256ccm12":  {TransformEncryptionAESCCM12, 32},
	"aes256ccm96":  {TransformEncryptionAESCCM12, 32},
	"aes256ccm16":  {TransformEncryptionAESCCM16, 32},
	"aes256ccm128": {TransformEncryptionAESCCM16, 32},
	"aes128gcm12":  {TransformEncryptionAESGCM12, 16},
	"aes128gcm96":  {TransformEncryptionAESGCM12, 16},
	"aes128gcm":    {TransformEncryptionAESGCM16, 16},
	"aes128gcm16":  {TransformEncryptionAESGCM16, 16},
	"aes128gcm128": {TransformEncryptionAESGCM16, 16},
	"aes256gcm12":  {TransformEncryptionAESGCM12, 32},
	"aes256gcm96":  {TransformEncryptionAESGCM12, 32},
	"aes256gcm":    {TransformEncryptionAESGCM16, 32},
	"aes256gcm16":  {TransformEncryptionAESGCM16, 32},
	"aes256gcm128": {TransformEncryptionAESGCM16, 32},
}

var integrityTokens = map[string]uint16{
	"sha":      TransformIntegrityHMACSHA196,
	"sha1":     TransformIntegrityHMACSHA196,
	"sha256":   TransformIntegrityHMACSHA2256128,
	"sha2_256": TransformIntegrityHMACSHA2256128,
	"sha384":   TransformIntegrityHMACSHA2384192,
	"sha2_384": TransformIntegrityHMACSHA2384192,
	"sha512":   TransformIntegrityHMACSHA2512256,
	"sha2_512": TransformIntegrityHMACSHA2512256,
}

var prfTokens = map[string]uint16{
	"prfsha1":     TransformPRFHMACSHA1,
	"prfsha256":   TransformPRFHMACSHA256,
	"prfsha2_256": TransformPRFHMACSHA256,
	"prfsha512":   TransformPRFHMACSHA512,
	"prfsha2_512": TransformPRFHMACSHA512,
}

var dhTokens = map[string]uint16{
	"curve25519": TransformDHCurve25519,
	"x25519":     TransformDHCurve25519,
}

// ParseProposal parses one strongswan-style proposal string, e.g.
// "aes256gcm16-prfsha512-curve25519". Supported tokens mirror the swan2
// strongswan tables: aes/aes128/aes256, aes128|256ccm8|12|16 (and
// ccm64|ccm96|ccm128 aliases), aes128|256gcm12|gcm16 (and gcm|gcm96|gcm128
// aliases), sha/sha1/sha256/sha2_256/sha384/sha2_384/sha512/sha2_512
// (integrity), prfsha1/prfsha256/prfsha2_256/prfsha512/prfsha2_512, and
// curve25519/x25519. AEAD proposals must not carry integrity transforms;
// non-AEAD proposals must. PRF defaults to the matching integrity family
// when omitted; a PRF-less sha384 integrity is rejected (no swan2 default).
func ParseProposal(s string) (Proposal, error) {
	var p Proposal
	for _, token := range splitTokens(s) {
		if token == "" {
			continue
		}
		if enc, ok := encryptionTokens[token]; ok {
			pushEncryption(&p.Encryption, enc)
			continue
		}
		if id, ok := integrityTokens[token]; ok {
			pushU16(&p.Integrity, id)
			continue
		}
		if id, ok := prfTokens[token]; ok {
			pushU16(&p.PRF, id)
			continue
		}
		if id, ok := dhTokens[token]; ok {
			pushU16(&p.DH, id)
			continue
		}
		return Proposal{}, fmt.Errorf("xcrypto: unsupported strongswan proposal token %q", token)
	}

	if len(p.Encryption) == 0 {
		return Proposal{}, errors.New("xcrypto: proposal is missing an encryption transform")
	}
	if len(p.DH) == 0 {
		return Proposal{}, errors.New("xcrypto: proposal is missing a DH group")
	}

	hasAEAD := false
	hasNonAEAD := false
	for _, enc := range p.Encryption {
		alg, err := NewEncryption(enc.TransformID, enc.KeyLen)
		if err != nil {
			return Proposal{}, err
		}
		if alg.AEAD {
			hasAEAD = true
		} else {
			hasNonAEAD = true
		}
	}
	if hasAEAD && hasNonAEAD {
		return Proposal{}, errors.New("xcrypto: mixed AEAD and non-AEAD encryption transforms in one proposal")
	}
	if hasAEAD {
		if len(p.Integrity) != 0 {
			return Proposal{}, errors.New("xcrypto: AEAD proposal must not include integrity transforms")
		}
	} else if len(p.Integrity) == 0 {
		return Proposal{}, errors.New("xcrypto: non-AEAD proposal is missing an integrity transform")
	}

	if len(p.PRF) == 0 {
		for _, id := range p.Integrity {
			def := prfFromIntegrity(id)
			if def == 0 {
				return Proposal{}, fmt.Errorf("xcrypto: integrity transform %d has no default PRF; add an explicit PRF", id)
			}
			pushU16(&p.PRF, def)
		}
	}
	if len(p.PRF) == 0 {
		return Proposal{}, errors.New("xcrypto: proposal is missing a PRF")
	}
	return p, nil
}

// ParseProposals parses a comma-separated proposal list.
func ParseProposals(s string) ([]Proposal, error) {
	var out []Proposal
	seen := false
	for _, part := range commaSplit(s) {
		p, err := ParseProposal(part)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
		seen = true
	}
	if !seen {
		return nil, errors.New("xcrypto: proposal list is empty")
	}
	return out, nil
}

// Select negotiates local preference (p) against a responder proposal,
// returning the first supported combination. Encryption picks the first
// common (transform id, key length) pair; DH picks the first common group;
// PRF picks the first common id in local order.
func (p Proposal) Select(remote *Proposal) (*Selection, error) {
	if remote == nil {
		return nil, errors.New("xcrypto: nil remote proposal")
	}

	enc, err := p.selectEncryption(remote)
	if err != nil {
		return nil, err
	}

	var integ *Integrity
	if enc.AEAD {
		integ, err = NewIntegrity(TransformIntegrityNone)
	} else {
		integ, err = p.selectIntegrity(remote)
	}
	if err != nil {
		return nil, err
	}

	prf, err := p.selectPRF(remote, integ)
	if err != nil {
		return nil, err
	}

	dh, err := p.selectDH(remote)
	if err != nil {
		return nil, err
	}

	return &Selection{Encryption: enc, Integrity: integ, PRF: prf, DH: dh}, nil
}

func (p Proposal) selectEncryption(remote *Proposal) (*EncryptionAlg, error) {
	for _, want := range p.Encryption {
		if !hasEncryption(remote.Encryption, want) {
			continue
		}
		alg, err := NewEncryption(want.TransformID, want.KeyLen)
		if err != nil {
			return nil, err
		}
		if alg.AEAD && (len(p.Integrity) != 0 || len(remote.Integrity) != 0) {
			return nil, errors.New("xcrypto: AEAD proposal must not negotiate integrity transforms")
		}
		return alg, nil
	}
	return nil, errors.New("xcrypto: no compatible encryption transform")
}

func (p Proposal) selectIntegrity(remote *Proposal) (*Integrity, error) {
	for _, want := range p.Integrity {
		if !hasU16(remote.Integrity, want) {
			continue
		}
		return NewIntegrity(want)
	}
	return nil, errors.New("xcrypto: no compatible integrity transform")
}

func (p Proposal) selectPRF(remote *Proposal, integ *Integrity) (*PRF, error) {
	if integ == nil {
		return nil, errors.New("xcrypto: no integrity selection for PRF negotiation")
	}
	for _, want := range p.PRF {
		if !prfMatchesIntegrity(want, integ) || !hasU16(remote.PRF, want) {
			continue
		}
		return NewPRF(want)
	}
	// A caller-built (not Parsed) local proposal may have left PRF empty;
	// fall back to the PRF family implied by the negotiated integrity.
	if integ.TransformID != TransformIntegrityNone {
		if id := prfFromIntegrity(integ.TransformID); id != 0 && hasU16(remote.PRF, id) {
			return NewPRF(id)
		}
	}
	return nil, errors.New("xcrypto: no compatible PRF transform")
}

// prfMatchesIntegrity reports whether a PRF may serve as the keyed PRF for
// the negotiated integrity transform. AEAD selections may use any registered
// PRF; CBC selections require the matching HMAC family (swan2 child/IKE
// keying uses the same family for integrity and PRF).
func prfMatchesIntegrity(prf uint16, integ *Integrity) bool {
	if integ == nil {
		return false
	}
	if integ.TransformID == TransformIntegrityNone {
		return true
	}
	return prfFromIntegrity(integ.TransformID) == prf
}

func (p Proposal) selectDH(remote *Proposal) (*DH, error) {
	for _, want := range p.DH {
		if !hasU16(remote.DH, want) {
			continue
		}
		switch want {
		case TransformDHCurve25519:
			return &DH{TransformID: want, Name: "curve25519"}, nil
		}
	}
	return nil, errors.New("xcrypto: no compatible DH group")
}

func prfFromIntegrity(id uint16) uint16 {
	switch id {
	case TransformIntegrityHMACSHA196:
		return TransformPRFHMACSHA1
	case TransformIntegrityHMACSHA2256128:
		return TransformPRFHMACSHA256
	case TransformIntegrityHMACSHA2512256:
		return TransformPRFHMACSHA512
	default:
		return 0
	}
}

// Token helpers avoid importing strings for the tiny delimiters used here.
func splitTokens(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '-' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}

func commaSplit(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			part := s[start:i]
			// Trim ASCII spaces around the comma-separated proposal.
			for len(part) > 0 && part[0] == ' ' {
				part = part[1:]
			}
			for len(part) > 0 && part[len(part)-1] == ' ' {
				part = part[:len(part)-1]
			}
			if part != "" {
				out = append(out, part)
			}
			start = i + 1
		}
	}
	return out
}

func pushEncryption(list *[]EncryptionID, v EncryptionID) {
	for _, have := range *list {
		if have == v {
			return
		}
	}
	*list = append(*list, v)
}

func pushU16(list *[]uint16, v uint16) {
	for _, have := range *list {
		if have == v {
			return
		}
	}
	*list = append(*list, v)
}

func hasEncryption(list []EncryptionID, v EncryptionID) bool {
	for _, have := range list {
		if have == v {
			return true
		}
	}
	return false
}

func hasU16(list []uint16, v uint16) bool {
	for _, have := range list {
		if have == v {
			return true
		}
	}
	return false
}
