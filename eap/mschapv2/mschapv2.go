// Package mschapv2 implements the EAP-MSCHAPv2 peer method, both as the
// standalone outer method and as the inner method used by PEAP (swan2
// eap/mschapv2 semantics).
//
// Standard crypto only:
//
//   - MD4:   local RFC 1320 implementation in md4.go (NT hash)
//   - DES:   crypto/des (challenge/response obfuscation)
//   - SHA1:  crypto/sha1 (challenge hash, magic constants)
//
// The challenge (16 bytes), response (49-byte payload) and MSK derivation
// follow RFC 2759 / MS-CHAPv2; no Microsoft stack is involved.
package mschapv2

import (
	"crypto/des"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"swan/eap"
)

// MSCHAPv2 opcodes (payload[0]).
const (
	OpChallenge = 1
	OpResponse  = 2
	OpSuccess   = 3
	OpFailure   = 4
)

// Sizing constants of the MSCHAPv2 payloads.
const (
	ChallengeLen     = 16
	ResponseDataLen  = 49
	NTResponseLen    = 24
	AuthStringHexLen = 40
)

// MSCHAPv2 magic constants (RFC 2759, section 8 + 8.1.2 / RFC 3079).
var (
	magic1    = []byte("Magic server to client signing constant")
	magic2    = []byte("Pad to make it do more than one iteration")
	mskMagic1 = []byte("This is the MPPE Master Key")
	mskMagic2 = []byte("On the client side, this is the send key; on the server side, it is the receive key.")
	mskMagic3 = []byte("On the client side, this is the receive key; on the server side, it is the send key.")

	shapad1 = make([]byte, 40) // all 0x00
	shapad2 = []byte{
		0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2,
		0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2,
		0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2,
		0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2,
		0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2,
	}
)

const responseValueSize = 49

// Phase tracks the outer MSCHAPv2 FSM.
type Phase uint8

const (
	PhaseNegotiating Phase = iota
	PhaseChallenging
	PhaseVerifying
	PhaseCompleted
	PhaseFailed
)

// Method is the EAP-MSCHAPv2 peer FSM (standard implementation aligned with
// swan2 behavior: single challenge, verify via Success, MSK export).
type Method struct {
	identity string
	password string
	phase    Phase
	// state carries the running challenge state once challenge processing
	// starts; nil outside the challenge/verify window.
	state *state
}

// state is the in-flight challenge context (never leaves this package).
type state struct {
	mschapID         uint8
	expectingSuccess bool
	authHex          string
	msk              []byte
}

// New builds a method; validation happens in Initialize.
func New(identity, password string) *Method {
	return &Method{identity: identity, password: password, phase: PhaseNegotiating}
}

var _ eap.Method = (*Method)(nil)

// Name implements eap.Method.
func (m *Method) Name() string {
	return "mschapv2"
}

// Initialize implements eap.Method: validates credentials and resets the
// FSM to the Negotiating phase.
func (m *Method) Initialize() error {
	if m.identity == "" {
		return errors.New("mschapv2 identity is empty")
	}
	if m.password == "" {
		return errors.New("mschapv2 password is empty")
	}
	m.reset()
	return nil
}

// Handle implements eap.Method: Identity -> identity response, foreign
// request -> NAK, challenge/verify round -> RFC 2759 response, Success
// after a verified challenge -> Completed with exported MSK, Failure ->
// Failed. Once Failed the FSM rejects every further packet until a new
// Initialize.
func (m *Method) Handle(packet []byte, round uint16) (eap.Result, error) {
	_ = round
	if m.phase == PhaseFailed {
		return eap.Result{}, errors.New("mschapv2 method is in failure state")
	}
	pkt, err := eap.Parse(packet)
	if err != nil {
		m.phase = PhaseFailed
		return eap.Result{}, err
	}

	switch pkt.Code {
	case eap.CodeRequest:
		switch pkt.Type {
		case eap.TypeIdentity:
			m.phase = PhaseNegotiating
			resp := eap.BuildRequest(eap.CodeResponse, pkt.Identifier, eap.TypeIdentity, []byte(m.identity))
			return eap.Result{Action: eap.ActionSend, Response: resp}, nil
		case eap.TypeMSCHAPV2:
			if m.state != nil {
				m.phase = PhaseVerifying
			} else {
				m.phase = PhaseChallenging
			}
			resp, err := m.onRequest(pkt.Identifier, pkt.Data)
			if err != nil {
				m.phase = PhaseFailed
				return eap.Result{}, err
			}
			return eap.Result{Action: eap.ActionSend, Response: resp}, nil
		default:
			m.phase = PhaseNegotiating
			resp := nakResponse(pkt.Identifier)
			return eap.Result{Action: eap.ActionSend, Response: resp}, nil
		}
	case eap.CodeSuccess:
		if m.state == nil {
			m.phase = PhaseFailed
			return eap.Result{}, errors.New("mschapv2 success without prior challenge")
		}
		if m.state.expectingSuccess {
			m.phase = PhaseFailed
			return eap.Result{}, errors.New("outer eap success before verified mschapv2")
		}
		msk := append([]byte(nil), m.state.msk...)
		m.phase = PhaseCompleted
		return eap.Result{Action: eap.ActionComplete, ExportedMSK: msk}, nil
	case eap.CodeFailure:
		m.phase = PhaseFailed
		return eap.Result{}, fmt.Errorf("received eap failure with identifier %d", pkt.Identifier)
	default:
		m.phase = PhaseFailed
		return eap.Result{}, fmt.Errorf("unsupported outer eap code %d for mschapv2", pkt.Code)
	}
}

// reset returns the method to the pre-challenge phase.
func (m *Method) reset() {
	m.phase = PhaseNegotiating
	m.state = nil
}

// Close implements eap.Method: drops challenge state and makes the FSM
// terminal; a later Initialize resets it.
func (m *Method) Close() error {
	m.state = nil
	m.phase = PhaseFailed
	return nil
}

// onRequest processes one MSCHAPv2 request payload (the bytes after the EAP
// type field) and returns the complete EAP response packet.
func (m *Method) onRequest(eapID uint8, payload []byte) ([]byte, error) {
	if len(payload) < 4 {
		m.phase = PhaseFailed
		return nil, errors.New("mschapv2 payload too short")
	}
	opcode := payload[0]
	mschapID := payload[1]
	declaredLen := int(payload[2])<<8 | int(payload[3])
	if declaredLen < 4 || declaredLen != len(payload) {
		m.phase = PhaseFailed
		return nil, errors.New("invalid mschapv2 length")
	}
	data := payload[4:]

	switch opcode {
	case OpChallenge:
		if m.state != nil && m.state.expectingSuccess {
			return nil, errors.New("received unexpected mschapv2 challenge while waiting for success")
		}
		// swan2 core.rs requires parsed.data.len() > CHALLENGE_LEN + 1
		// (value-size, challenge, and at least one trailing byte).
		if len(data) <= ChallengeLen+1 {
			return nil, errors.New("mschapv2 challenge payload too short")
		}
		valueSize := int(data[0])
		if valueSize != ChallengeLen {
			return nil, fmt.Errorf("unsupported mschapv2 challenge size %d", valueSize)
		}
		var authChallenge [ChallengeLen]byte
		copy(authChallenge[:], data[1:1+ChallengeLen])

		var peerChallenge [ChallengeLen]byte
		if _, err := rand.Read(peerChallenge[:]); err != nil {
			return nil, fmt.Errorf("generate mschapv2 peer challenge: %w", err)
		}

		username := extractUsername(m.identity)
		ntResponse, err := generateNTResponse(&peerChallenge, &authChallenge, []byte(username), m.password)
		if err != nil {
			return nil, err
		}
		authHex, err := generateAuthenticatorResponse(&peerChallenge, &authChallenge, []byte(username), m.password, &ntResponse)
		if err != nil {
			return nil, err
		}
		msk, err := generateMSK(m.password, &ntResponse)
		if err != nil {
			return nil, err
		}

		m.state = &state{
			mschapID:         mschapID,
			expectingSuccess: true,
			authHex:          authHex,
			msk:              msk,
		}
		return buildResponse(eapID, mschapID, peerChallenge[:], ntResponse[:], []byte(m.identity)), nil

	case OpSuccess:
		if m.state == nil {
			return nil, errors.New("mschapv2 success without prior challenge")
		}
		if !m.state.expectingSuccess {
			return nil, errors.New("unexpected mschapv2 success in current state")
		}
		if m.state.mschapID != mschapID {
			return nil, fmt.Errorf("mschapv2 id mismatch: expected %d, got %d", m.state.mschapID, mschapID)
		}
		if err := verifySuccess(data, m.state.authHex); err != nil {
			return nil, err
		}
		m.state.expectingSuccess = false
		return buildSuccess(eapID), nil

	case OpFailure:
		if m.state == nil {
			return nil, errors.New("mschapv2 failure without prior challenge")
		}
		if !m.state.expectingSuccess {
			return nil, errors.New("unexpected mschapv2 failure in current state")
		}
		if m.state.mschapID != mschapID {
			return nil, fmt.Errorf("mschapv2 id mismatch: expected %d, got %d", m.state.mschapID, mschapID)
		}
		if err := parseFailureTokens(data); err != nil {
			return nil, err
		}
		// Fail closed: no further Success packet may export an MSK after
		// the server rejected the challenge.
		m.state = nil
		return nil, errors.New("inner mschapv2 authentication failed")

	default:
		return nil, fmt.Errorf("unsupported mschapv2 opcode %d", opcode)
	}
}

// nakResponse builds an EAP NAK response advertising only EAP-MSCHAPv2.
func nakResponse(eapID uint8) []byte {
	return eap.BuildRequest(eap.CodeResponse, eapID, eap.TypeNAK, []byte{byte(eap.TypeMSCHAPV2)})
}

// extractUsername strips a DOMAIN\ prefix, leaving the bare username for the
// challenge hash (swan2 semantics: everything after the first backslash).
func extractUsername(identity string) string {
	if idx := strings.IndexByte(identity, '\\'); idx >= 0 {
		return identity[idx+1:]
	}
	return identity
}

// buildResponse builds the MSCHAPv2 Response payload and wraps it in an EAP
// response envelope:
//
//	opcode(2) | id | 2-byte length | value-size(49) | peer-challenge(16) |
//	reserved(8) | nt-response(24) | flags(0) | name
func buildResponse(eapID uint8, mschapID uint8, peerChallenge, ntResponse []byte, identity []byte) []byte {
	body := make([]byte, 0, 54+len(identity))
	body = append(body, OpResponse, mschapID, 0, 0)
	body = append(body, responseValueSize)
	body = append(body, peerChallenge...)
	body = append(body, make([]byte, 8)...)
	body = append(body, ntResponse...)
	body = append(body, 0)
	body = append(body, identity...)
	// MSCHAPv2 length field covers the whole payload after the opcode/id.
	body[2], body[3] = byte(len(body)>>8), byte(len(body))
	return eap.BuildRequest(eap.CodeResponse, eapID, eap.TypeMSCHAPV2, body)
}

// buildSuccess builds the MSCHAPv2 Success response payload (opcode only)
// and wraps it in an EAP response envelope; the MSCHAPv2 length field is
// intentionally omitted, mirroring swan2.
func buildSuccess(eapID uint8) []byte {
	return eap.BuildRequest(eap.CodeResponse, eapID, eap.TypeMSCHAPV2, []byte{OpSuccess})
}

// generateNTResponse computes the 24-byte NT challenge response.
func generateNTResponse(peerChallenge, authChallenge *[ChallengeLen]byte, username []byte, password string) ([NTResponseLen]byte, error) {
	challenge := challengeHash(peerChallenge, authChallenge, username)
	pwHash := ntPasswordHash(password)
	var zeroPadded [21]byte
	copy(zeroPadded[:], pwHash[:])

	var out [NTResponseLen]byte
	for i := 0; i < 3; i++ {
		var key7 [7]byte
		copy(key7[:], zeroPadded[i*7:(i+1)*7])
		key8 := expandDesKey(&key7)
		block, err := desEncryptBlock(&key8, &challenge)
		if err != nil {
			return out, err
		}
		copy(out[i*8:(i+1)*8], block[:])
	}
	return out, nil
}

// generateAuthenticatorResponse returns the expected uppercase hex
// authenticator string verified against the success payload.
func generateAuthenticatorResponse(peerChallenge, authChallenge *[ChallengeLen]byte, username []byte, password string, ntResponse *[NTResponseLen]byte) (string, error) {
	pwHash := ntPasswordHash(password)
	pwHashHash := md4(pwHash[:])

	first := sha1Sum(appendCopy(pwHashHash[:], ntResponse[:], magic1))
	challenge := challengeHash(peerChallenge, authChallenge, username)
	second := sha1Sum(appendCopy(first, challenge[:], magic2))
	return strings.ToUpper(hexEncode(second)), nil
}

// generateMSK derives the 64-byte Master Session Key with the RFC 3079
// MPPE constants.
func generateMSK(password string, ntResponse *[NTResponseLen]byte) ([]byte, error) {
	pwHash := ntPasswordHash(password)
	pwHashHash := md4(pwHash[:])

	masterKey := sha1Sum(appendCopy(pwHashHash[:], ntResponse[:], mskMagic1))
	master := masterKey[:16]

	recv := sha1Sum(appendCopy(master, shapad1, mskMagic2, shapad2))
	send := sha1Sum(appendCopy(master, shapad1, mskMagic3, shapad2))

	out := make([]byte, 0, 64)
	out = append(out, recv[:16]...)
	out = append(out, send[:16]...)
	out = append(out, make([]byte, 16)...)
	out = append(out, make([]byte, 16)...)
	return out, nil
}

// verifySuccess checks the "S=..." authenticator response in a success
// payload against the expected value.
func verifySuccess(payload []byte, expected string) error {
	if len(payload) < 2+AuthStringHexLen {
		return errors.New("mschapv2 success payload too short")
	}
	if !utf8.Valid(payload) {
		return errors.New("mschapv2 success payload is not utf8")
	}
	text := string(payload)
	sig := ""
	for _, token := range strings.Fields(text) {
		if v, ok := strings.CutPrefix(token, "S="); ok {
			sig = v
			break
		}
	}
	if sig == "" {
		return errors.New("mschapv2 success missing authenticator response")
	}
	if len(sig) != AuthStringHexLen {
		return errors.New("mschapv2 success invalid auth string length")
	}
	if _, err := hexDecode(sig); err != nil {
		return errors.New("mschapv2 success invalid auth string encoding")
	}
	if !strings.EqualFold(sig, expected) {
		return errors.New("mschapv2 success authenticator response mismatch")
	}
	return nil
}

// parseFailureTokens validates the failure payload's E/R/C/V/M tokens the
// same way swan2 does.
func parseFailureTokens(payload []byte) error {
	if len(payload) < 3 {
		return errors.New("mschapv2 failure payload too short")
	}
	if !utf8.Valid(payload) {
		return errors.New("mschapv2 failure payload is not utf8")
	}
	var (
		hasErrorCode, hasRetryFlag, hasChallenge bool
		hasVersion, hasMessage                   bool
	)
	for _, token := range strings.Fields(string(payload)) {
		key, value, ok := strings.Cut(token, "=")
		if !ok {
			return fmt.Errorf("mschapv2 failure has malformed token %q", token)
		}
		switch key {
		case "E":
			if value == "" {
				return errors.New("mschapv2 failure has invalid E code")
			}
			if _, err := strconv.ParseUint(value, 10, 32); err != nil {
				return errors.New("mschapv2 failure has invalid E code")
			}
			hasErrorCode = true
		case "R":
			if value != "0" && value != "1" {
				return errors.New("mschapv2 failure has invalid R token")
			}
			hasRetryFlag = true
		case "C":
			if len(value) != ChallengeLen*2 || !isHex(value) {
				return errors.New("mschapv2 failure has invalid challenge token")
			}
			hasChallenge = true
		case "V":
			if value == "" || !isDigits(value) {
				return errors.New("mschapv2 failure has invalid V token")
			}
			hasVersion = true
		case "M":
			if value == "" {
				return errors.New("mschapv2 failure has invalid M token")
			}
			hasMessage = true
		default:
			return fmt.Errorf("mschapv2 failure has unsupported token %q", key)
		}
	}
	_ = hasVersion
	_ = hasMessage
	if !hasErrorCode {
		return errors.New("mschapv2 failure payload missing E token")
	}
	if !hasRetryFlag {
		return errors.New("mschapv2 failure payload missing R token")
	}
	if !hasChallenge {
		return errors.New("mschapv2 failure payload missing C token")
	}
	return nil
}

// ---- small crypto helpers ----

func ntPasswordHash(password string) [16]byte {
	return md4(utf16LE(password))
}

// challengeHash returns the first 8 bytes of SHA1(peer|auth|username).
func challengeHash(peerChallenge, authChallenge *[ChallengeLen]byte, username []byte) [8]byte {
	h := sha1.New()
	h.Write(peerChallenge[:])
	h.Write(authChallenge[:])
	h.Write(username)
	var out [8]byte
	copy(out[:], h.Sum(nil))
	return out
}

// sha1Sum appends all parts in order and returns the SHA1 digest.
func sha1Sum(parts []byte) []byte {
	h := sha1.New()
	h.Write(parts)
	return h.Sum(nil)
}

// appendCopy concatenates byte parts into one newly allocated slice.
func appendCopy(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func utf16LE(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*2)
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

// expandDesKey expands a 7-byte value into an 8-byte DES key with odd
// parity (RFC 2759, section 8.1.2).
func expandDesKey(key7 *[7]byte) [8]byte {
	var out [8]byte
	out[0] = key7[0] & 0xFE
	out[1] = ((key7[0] << 7) | (key7[1] >> 1)) & 0xFE
	out[2] = ((key7[1] << 6) | (key7[2] >> 2)) & 0xFE
	out[3] = ((key7[2] << 5) | (key7[3] >> 3)) & 0xFE
	out[4] = ((key7[3] << 4) | (key7[4] >> 4)) & 0xFE
	out[5] = ((key7[4] << 3) | (key7[5] >> 5)) & 0xFE
	out[6] = ((key7[5] << 2) | (key7[6] >> 6)) & 0xFE
	out[7] = key7[6] << 1
	for i := range out {
		out[i] = oddParity(out[i])
	}
	return out
}

// oddParity forces odd parity on the low 7-bit DES key bytes.
func oddParity(b byte) byte {
	b &= 0xFE
	if onesCount(b)%2 == 0 {
		b |= 1
	}
	return b
}

func onesCount(b byte) int {
	n := 0
	for b != 0 {
		b &= b - 1
		n++
	}
	return n
}

func desEncryptBlock(key, block *[8]byte) ([8]byte, error) {
	c, err := des.NewCipher(key[:])
	if err != nil {
		return [8]byte{}, err
	}
	var out [8]byte
	c.Encrypt(out[:], block[:])
	return out, nil
}

// hex helpers kept as tiny wrappers so the file reads without importing
// encoding/hex directly at every call site.
func hexEncode(b []byte) string {
	const hexDigits = "0123456789ABCDEF"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexDigits[v>>4]
		out[i*2+1] = hexDigits[v&0x0F]
	}
	return string(out)
}

// hexDecode validates uppercase or lowercase hex text.
func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errors.New("odd length hex")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi, okHi := hexDigit(s[i])
		lo, okLo := hexDigit(s[i+1])
		if !okHi || !okLo {
			return nil, errors.New("invalid hex")
		}
		out[i/2] = hi<<4 | lo
	}
	return out, nil
}

func hexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func isHex(s string) bool {
	_, err := hexDecode(s)
	return err == nil
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
