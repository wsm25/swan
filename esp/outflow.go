package esp

import (
	"encoding/binary"
	"errors"
	"fmt"

	"swan/xcrypto"
)

// OutboundConfig freezes the per-SA read-only state handed to the outbound
// worker at establishment.
type OutboundConfig struct {
	// SPI is the responder-provided outbound SPI.
	SPI       uint32
	Selection *xcrypto.Selection
	Keys      *xcrypto.ChildKeys
}

// Outbound encrypts raw IP packets into UDP-encapsulated ESP datagrams.
// Sequence numbers are allocated strictly in order by this single worker
// (starting at 1; wrap is an error, per RFC 4303).
type Outbound struct {
	cfg OutboundConfig

	seq uint32
}

// NewOutbound binds the frozen configuration with the sequence number at
// its RFC 4303 initial value of 1.
func NewOutbound(cfg OutboundConfig) *Outbound {
	return &Outbound{cfg: cfg, seq: 1}
}

// Process pads/encrypts one raw IP packet and returns the ESP datagram
// (without any NAT-T marker; the transport writer applies none for ESP).
// IPv4/IPv6 are translated to the ESP next-header values 4/41; other
// versions are rejected.
func (p *Outbound) Process(packet []byte) (datagram []byte, err error) {
	if err := p.validateConfig(); err != nil {
		return nil, err
	}
	if len(packet) == 0 {
		return nil, errors.New("swan/esp: outbound packet is empty")
	}

	nextHeader, err := ipNextHeader(packet[0])
	if err != nil {
		return nil, err
	}

	enc := p.cfg.Selection.Encryption
	integ := p.cfg.Selection.Integrity

	// ESP padding (RFC 4303 2.4): pad bytes 1..padLen, followed by the
	// pad length byte and the IP next-header byte. The full plaintext
	// (payload + padding + trailer) must be a multiple of the cipher block
	// size: 16 for CBC, 1 for AEAD (no padding).
	padLen := (enc.BlockLen - (len(packet)+2)%enc.BlockLen) % enc.BlockLen
	plain := make([]byte, 0, len(packet)+padLen+2)
	plain = append(plain, packet...)
	for i := 1; i <= padLen; i++ {
		plain = append(plain, byte(i))
	}
	plain = append(plain, byte(padLen), nextHeader)

	iv := make([]byte, enc.IVLen)
	if err := xcrypto.Fill(iv); err != nil {
		return nil, fmt.Errorf("swan/esp: generate ESP IV: %w", err)
	}

	if p.seq == 0 {
		return nil, errors.New("swan/esp: ESP sequence number wrapped")
	}
	seq := p.seq
	p.seq++

	hdr := make([]byte, espHeaderLen, espHeaderLen+enc.IVLen+len(plain)+enc.ICVLen+integOuterICV(integ))
	binary.BigEndian.PutUint32(hdr[:4], p.cfg.SPI)
	binary.BigEndian.PutUint32(hdr[4:8], seq)

	ciphertext, err := enc.Seal(p.cfg.Keys.SKei, iv, hdr[:espHeaderLen], plain)
	if err != nil {
		return nil, fmt.Errorf("swan/esp: encrypt ESP: %w", err)
	}
	hdr = append(hdr, iv...)
	hdr = append(hdr, ciphertext...)

	if !enc.AEAD {
		if integ == nil {
			return nil, errors.New("swan/esp: CBC requires an integrity transform")
		}
		icv, err := integ.Sign(p.cfg.Keys.SKai, hdr)
		if err != nil {
			return nil, fmt.Errorf("swan/esp: sign ESP ICV: %w", err)
		}
		hdr = append(hdr, icv...)
	}

	return hdr, nil
}

func (p *Outbound) validateConfig() error {
	if p == nil || p.cfg.Selection == nil || p.cfg.Selection.Encryption == nil || p.cfg.Keys == nil {
		return errors.New("swan/esp: outbound configuration is incomplete")
	}
	return nil
}

// ipNextHeader maps the IP version nibble to the ESP trailer next-header
// value: IPv4 -> 4, IPv6 -> 41.
func ipNextHeader(firstByte byte) (byte, error) {
	switch firstByte >> 4 {
	case 4:
		return nextHeaderIPv4, nil
	case 6:
		return nextHeaderIPv6, nil
	default:
		return 0, fmt.Errorf("swan/esp: unsupported outbound IP version %d", firstByte>>4)
	}
}

// integOuterICV reports the extra trailing bytes on the wire for the
// non-AEAD ICV (AEAD tags are already included in ciphertext by Seal).
func integOuterICV(integ *xcrypto.Integrity) int {
	if integ == nil {
		return 0
	}
	return integ.OutputLen
}
