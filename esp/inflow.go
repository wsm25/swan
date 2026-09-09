package esp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"swan/xcrypto"
)

// Layout constants for UDP-encapsulated ESP (RFC 3948/4303): the 8-byte
// ESP header is followed by IV, ciphertext and then either the AEAD tag or
// the separate HMAC ICV.
const (
	espHeaderLen = 8
	// nextHeaderIPv4 / nextHeaderIPv6 are the ESP trailer next-header
	// values for the two IP versions the MVP transports.
	nextHeaderIPv4 = 4
	nextHeaderIPv6 = 41
)

// InboundConfig freezes the per-SA read-only state handed to the inbound
// worker at establishment.
type InboundConfig struct {
	// SPI is the initiator-side inbound SPI (we generated it).
	SPI       uint32
	Selection *xcrypto.Selection
	Keys      *xcrypto.ChildKeys
}

// Inbound decrypts ESP datagrams: SPI filter, replay check, AEAD/ICV
// verification, CBC/GCM/CCM decryption, padding/trailer strip and inner
// protocol filter (IPv4=4 / IPv6=41). Unsupported/malformed packets are
// dropped with a debug record, mirroring swan2's per-packet tolerance.
type Inbound struct {
	cfg      InboundConfig
	window   ReplayWindow
	enc      *xcrypto.PreparedEncryption
	integ    *xcrypto.PreparedIntegrity
	stateErr error

	// plainPool recycles the plaintext backings used by ProcessPooled.
	// The wrapper (not the slice) is pooled, so released backings keep
	// their full length/capacity across cycles.
	plainPool sync.Pool
}

// inboundPlainBufSize is the initial plaintext backing class size. Larger
// packets replace the pooled slice on demand; the larger backing is
// recycled intact by the next pool cycle.
const inboundPlainBufSize = 2048

// inboundPlain is the pooled plaintext backing wrapper.
type inboundPlain struct {
	b []byte
}

// NewInbound binds the frozen configuration. Reusable keyed cipher state is
// prepared here; any preparation failure is reported by Process.
func NewInbound(cfg InboundConfig) *Inbound {
	p := &Inbound{cfg: cfg}
	p.plainPool = sync.Pool{New: func() any { return &inboundPlain{b: make([]byte, inboundPlainBufSize)} }}
	p.enc, p.integ, p.stateErr = prepareInbound(cfg)
	return p
}

// Process decrypts one UDP-encapsulated ESP datagram (without any NAT-T
// marker: transport already stripped it) and returns the inner raw IP
// packet. Ownership of the returned bytes transfers to the caller; the
// function must not alias the input after return and returns fresh GC
// memory (the pooled plaintext is copied and released internally).
func (p *Inbound) Process(datagram []byte) (packet []byte, err error) {
	inner, release, err := p.ProcessPooled(datagram)
	if err != nil {
		return nil, err
	}
	packet = bytes.Clone(inner)
	release()
	return packet, nil
}

// ProcessPooled decrypts one UDP-encapsulated ESP datagram exactly like
// Process, but returns the inner packet as a slice into Inbound-owned pool
// memory. The returned release func must be called exactly once after the
// packet bytes are no longer needed; it recycles the whole backing wrapper,
// so callers do not need to restore the slice length. It may be shorter
// than the backing array. The inner slice never aliases datagram.
//
// The release func is single-shot: it is only safe for the ESP pipeline's
// single-owner delivery path. On error the pooled backing is already
// recycled and the returned release is nil.
func (p *Inbound) ProcessPooled(datagram []byte) (packet []byte, release func(), err error) {
	if p == nil || p.stateErr != nil {
		if p == nil {
			return nil, nil, errors.New("swan/esp: inbound configuration is incomplete")
		}
		return nil, nil, p.stateErr
	}
	if !p.AcceptSPI(datagram) {
		return nil, nil, errors.New("swan/esp: ESP SPI does not match the inbound SPI")
	}
	if len(datagram) < espHeaderLen {
		return nil, nil, errors.New("swan/esp: ESP packet too short for header")
	}

	seq := binary.BigEndian.Uint32(datagram[4:8])
	if seq == 0 {
		return nil, nil, errors.New("swan/esp: ESP sequence number 0 is invalid")
	}

	enc := p.cfg.Selection.Encryption
	integ := p.cfg.Selection.Integrity
	icvLen := enc.ICVLen
	if !enc.AEAD {
		if integ == nil {
			return nil, nil, errors.New("swan/esp: CBC requires an integrity transform")
		}
		icvLen = integ.OutputLen
	}

	body := datagram[espHeaderLen:]
	if len(body) < enc.IVLen+icvLen {
		return nil, nil, errors.New("swan/esp: ESP packet too short for IV and ICV")
	}
	iv := body[:enc.IVLen]
	rest := body[enc.IVLen:]

	// The decrypted plaintext is exactly the ciphertext minus the trailing
	// ICV (the AEAD tag for GCM/CCM, the separate HMAC ICV for CBC).
	plainLen := len(rest) - icvLen
	wb := p.plainPool.Get().(*inboundPlain)
	if cap(wb.b) < plainLen {
		wb.b = make([]byte, plainLen)
	}
	release = func() { p.plainPool.Put(wb) }
	fail := func(err error) ([]byte, func(), error) {
		release()
		return nil, nil, err
	}

	var (
		plain []byte
		opErr error
	)
	if enc.AEAD {
		// AEAD authenticates the whole packet prefix through the ESP header
		// as additional authenticated data; the tag is the trailing ICVLen
		// bytes of rest.
		plain, opErr = p.enc.OpenTo(wb.b[:0], iv, datagram[:espHeaderLen], rest)
	} else {
		if p.integ == nil {
			return fail(errors.New("swan/esp: CBC requires an integrity transform"))
		}
		cipherLen := len(rest) - icvLen
		ciphertext := rest[:cipherLen]
		receivedICV := rest[cipherLen:]

		// CBC authenticates the packet up to (excluding) the ICV with the
		// responder-side integrity key, then decrypts the ciphertext.
		authArea := datagram[:len(datagram)-icvLen]
		if !p.integ.Verify(authArea, receivedICV) {
			return fail(errors.New("swan/esp: ESP integrity check failed"))
		}
		plain, opErr = p.enc.OpenTo(wb.b[:0], iv, nil, ciphertext)
	}
	if opErr != nil {
		return fail(fmt.Errorf("swan/esp: decrypt ESP: %w", opErr))
	}

	// ESP trailer: padLength, then payload data, then nextHeader. The two
	// trailer bytes sit at the end of the decrypted plaintext; the inner
	// packet is everything before the padding.
	if len(plain) < 2 {
		return fail(errors.New("swan/esp: ESP plaintext is missing the trailer"))
	}
	padLen := int(plain[len(plain)-2])
	nextHeader := plain[len(plain)-1]
	if padLen+2 > len(plain) {
		return fail(errors.New("swan/esp: ESP padding length does not fit the plaintext"))
	}
	if nextHeader != nextHeaderIPv4 && nextHeader != nextHeaderIPv6 {
		return fail(fmt.Errorf("swan/esp: unsupported inner protocol %d", nextHeader))
	}
	inner := plain[:len(plain)-padLen-2]
	if len(inner) == 0 {
		return fail(errors.New("swan/esp: empty inner packet"))
	}
	// The replay window advances only for fully authenticated packets:
	// moving it before AEAD/ICV verification would let a spoofed datagram
	// (plaintext-visible SPI and sequence number, garbage body) shift the
	// window into the future and blackhole the real traffic.
	if !p.window.Accept(seq) {
		return fail(errors.New("swan/esp: ESP replay window rejected the packet"))
	}
	return inner, release, nil
}

// AcceptSPI reports whether datagram targets the inbound SPI (used before
// touching the replay window, so foreign SPIs cannot shift it).
func (p *Inbound) AcceptSPI(datagram []byte) bool {
	if p == nil || len(datagram) < espHeaderLen {
		return false
	}
	return binary.BigEndian.Uint32(datagram[:4]) == p.cfg.SPI
}

// prepareInbound builds the keyed cipher states the inbound worker reuses
// for the lifetime of the CHILD_SA.
func prepareInbound(cfg InboundConfig) (*xcrypto.PreparedEncryption, *xcrypto.PreparedIntegrity, error) {
	if cfg.Selection == nil || cfg.Selection.Encryption == nil || cfg.Keys == nil {
		return nil, nil, errors.New("swan/esp: inbound configuration is incomplete")
	}
	enc := cfg.Selection.Encryption
	state, err := enc.Prepare(cfg.Keys.SKer)
	if err != nil {
		return nil, nil, fmt.Errorf("swan/esp: prepare ESP encryption: %w", err)
	}
	var integ *xcrypto.PreparedIntegrity
	if !enc.AEAD {
		if cfg.Selection.Integrity == nil {
			return nil, nil, errors.New("swan/esp: CBC requires an integrity transform")
		}
		integ, err = cfg.Selection.Integrity.Prepare(cfg.Keys.SKar)
		if err != nil {
			return nil, nil, fmt.Errorf("swan/esp: prepare ESP integrity: %w", err)
		}
	}
	return state, integ, nil
}
