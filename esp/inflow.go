package esp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

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
	cfg    InboundConfig
	window ReplayWindow
}

// NewInbound binds the frozen configuration.
func NewInbound(cfg InboundConfig) *Inbound {
	return &Inbound{cfg: cfg}
}

// Process decrypts one UDP-encapsulated ESP datagram (without any NAT-T
// marker: transport already stripped it) and returns the inner raw IP
// packet. Ownership of the returned bytes transfers to the caller; the
// function must not alias the input after return.
func (p *Inbound) Process(datagram []byte) (packet []byte, err error) {
	if err := p.validateConfig(); err != nil {
		return nil, err
	}
	if !p.AcceptSPI(datagram) {
		return nil, errors.New("swan/esp: ESP SPI does not match the inbound SPI")
	}
	if len(datagram) < espHeaderLen {
		return nil, errors.New("swan/esp: ESP packet too short for header")
	}

	seq := binary.BigEndian.Uint32(datagram[4:8])
	if seq == 0 {
		return nil, errors.New("swan/esp: ESP sequence number 0 is invalid")
	}
	if !p.window.Accept(seq) {
		return nil, errors.New("swan/esp: ESP replay window rejected the packet")
	}

	enc := p.cfg.Selection.Encryption
	integ := p.cfg.Selection.Integrity
	icvLen := enc.ICVLen
	if !enc.AEAD {
		if integ == nil {
			return nil, errors.New("swan/esp: CBC requires an integrity transform")
		}
		icvLen = integ.OutputLen
	}

	body := datagram[espHeaderLen:]
	if len(body) < enc.IVLen+icvLen {
		return nil, errors.New("swan/esp: ESP packet too short for IV and ICV")
	}
	iv := body[:enc.IVLen]
	rest := body[enc.IVLen:]

	var (
		plain []byte
		opErr error
	)
	if enc.AEAD {
		// AEAD authenticates the whole packet prefix through the ESP header
		// as additional authenticated data; the tag is the trailing ICVLen
		// bytes of rest.
		plain, opErr = enc.Open(p.cfg.Keys.SKer, iv, datagram[:espHeaderLen], rest)
	} else {
		cipherLen := len(rest) - icvLen
		ciphertext := rest[:cipherLen]
		receivedICV := rest[cipherLen:]

		// CBC authenticates the packet up to (excluding) the ICV with the
		// responder-side integrity key, then decrypts the ciphertext.
		authArea := datagram[:len(datagram)-icvLen]
		if !integ.Verify(p.cfg.Keys.SKar, authArea, receivedICV) {
			return nil, errors.New("swan/esp: ESP integrity check failed")
		}
		plain, opErr = enc.Open(p.cfg.Keys.SKer, iv, nil, ciphertext)
	}
	if opErr != nil {
		return nil, fmt.Errorf("swan/esp: decrypt ESP: %w", opErr)
	}

	// ESP trailer: padLength, then payload data, then nextHeader. The two
	// trailer bytes sit at the end of the decrypted plaintext; the inner
	// packet is everything before the padding.
	if len(plain) < 2 {
		return nil, errors.New("swan/esp: ESP plaintext is missing the trailer")
	}
	padLen := int(plain[len(plain)-2])
	nextHeader := plain[len(plain)-1]
	if padLen+2 > len(plain) {
		return nil, errors.New("swan/esp: ESP padding length does not fit the plaintext")
	}
	if nextHeader != nextHeaderIPv4 && nextHeader != nextHeaderIPv6 {
		return nil, fmt.Errorf("swan/esp: unsupported inner protocol %d", nextHeader)
	}
	inner := plain[:len(plain)-padLen-2]
	if len(inner) == 0 {
		return nil, errors.New("swan/esp: empty inner packet")
	}
	return bytes.Clone(inner), nil
}

// AcceptSPI reports whether datagram targets the inbound SPI (used before
// touching the replay window, so foreign SPIs cannot shift it).
func (p *Inbound) AcceptSPI(datagram []byte) bool {
	if p == nil || len(datagram) < espHeaderLen {
		return false
	}
	return binary.BigEndian.Uint32(datagram[:4]) == p.cfg.SPI
}

func (p *Inbound) validateConfig() error {
	if p == nil || p.cfg.Selection == nil || p.cfg.Selection.Encryption == nil || p.cfg.Keys == nil {
		return errors.New("swan/esp: inbound configuration is incomplete")
	}
	return nil
}
