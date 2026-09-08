package wire

import "fmt"

// SPI is the 8-byte security parameter index pair carried in the IKE header.
// It is emitted and compared as a fixed-size array so passing headers around
// never allocates.
type SPI [8]byte

// Uint64SPI converts a numeric SPI to its wire form (big-endian bytes).
func Uint64SPI(v uint64) SPI {
	var s SPI
	putUint64(s[:], v)
	return s
}

// Uint64 converts a wire SPI back to a number for comparisons and NAT-D.
func (s SPI) Uint64() uint64 {
	return beUint64(s[:])
}

// IsZero reports whether all bytes are zero.
func (s SPI) IsZero() bool {
	return s == SPI{}
}

// Header is the fixed 28-byte IKE header (RFC 7296 section 3.1), stored in
// protocol field order as a plain data struct. All multi-byte fields use
// big-endian encoding; parse/build helpers below are the only place that
// knows the layout.
type Header struct {
	InitiatorSPI SPI
	ResponderSPI SPI
	NextPayload  PayloadType
	Version      uint8
	ExchangeType ExchangeType
	Flags        Flags
	MessageID    uint32
	Length       uint32
}

// Payload is one parsed outer payload: the generic 4-byte payload header is
// dissolved into fields, Body is a subslice of the input datagram (zero
// copy). It is legal only in a cleartext outer chain.
type Payload struct {
	Type     PayloadType
	Critical bool
	Next     PayloadType
	Body     []byte
}

// SkfHeader is the 4-byte SKF fragment header (fragment number and total
// fragments, both 1-based).
type SkfHeader struct {
	FragmentNumber uint16
	TotalFragments uint16
}

// flagsMask covers the only defined IKE header flag bits (RFC 7296 3.1):
// Response, Version and Initiator. All other bits must be zero.
const flagsMask = FlagResponse | FlagVersion | FlagInitiator

// ParseHeader decodes the first HeaderLen bytes and returns the remaining
// datagram. It validates version 2.x, flag bits and the declared total
// length against the input size.
func ParseHeader(b []byte) (Header, []byte, error) {
	if len(b) < HeaderLen {
		return Header{}, nil, fmt.Errorf("ike packet too short: have %d, want at least %d", len(b), HeaderLen)
	}

	declared := int(beUint32(b[24:28]))
	if declared < HeaderLen {
		return Header{}, nil, fmt.Errorf("invalid ike total length %d: below header size", declared)
	}
	if declared > len(b) {
		return Header{}, nil, fmt.Errorf("invalid ike total length %d: only %d bytes available", declared, len(b))
	}

	h := Header{
		InitiatorSPI: SPI(b[0:8]),
		ResponderSPI: SPI(b[8:16]),
		NextPayload:  PayloadType(b[16]),
		Version:      b[17],
		ExchangeType: ExchangeType(b[18]),
		Flags:        Flags(b[19]),
		MessageID:    beUint32(b[20:24]),
		Length:       uint32(declared),
	}

	if h.Version != IKEDefaultVersion {
		return Header{}, nil, fmt.Errorf("unexpected ike version 0x%02x", h.Version)
	}
	if uint8(h.Flags)&^uint8(flagsMask) != 0 {
		return Header{}, nil, fmt.Errorf("invalid ike flags 0x%02x", h.Flags)
	}

	return h, b[HeaderLen:declared], nil
}

// MarshalTo writes the header into dst (HeaderLen bytes, returned appended).
func (h Header) MarshalTo(dst []byte) []byte {
	start := len(dst)
	dst = append(dst, make([]byte, HeaderLen)...)
	b := dst[start : start+HeaderLen]
	copy(b[0:8], h.InitiatorSPI[:])
	copy(b[8:16], h.ResponderSPI[:])
	b[16] = byte(h.NextPayload)
	b[17] = h.Version
	b[18] = byte(h.ExchangeType)
	b[19] = byte(h.Flags)
	putUint32(b[20:24], h.MessageID)
	putUint32(b[24:28], h.Length)
	return dst
}

// ParseSkfHeader decodes the SKF fragment header and returns the rest.
func ParseSkfHeader(b []byte) (SkfHeader, []byte, error) {
	if len(b) < SkfHeaderLen {
		return SkfHeader{}, nil, fmt.Errorf("skf fragment header too short: have %d, want %d", len(b), SkfHeaderLen)
	}
	h := SkfHeader{
		FragmentNumber: beUint16(b[0:2]),
		TotalFragments: beUint16(b[2:4]),
	}
	if h.FragmentNumber == 0 || h.TotalFragments == 0 || h.FragmentNumber > h.TotalFragments {
		return SkfHeader{}, nil, fmt.Errorf("invalid skf fragment numbers %d/%d", h.FragmentNumber, h.TotalFragments)
	}
	return h, b[SkfHeaderLen:], nil
}
