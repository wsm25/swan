package payload

import (
	"fmt"

	"github.com/wsm25/swan/wire"
)

// Transform is one SA transform substructure (RFC 7296 3.3.2): type, 16-bit
// algorithm id and raw attributes (e.g. a KEY_LENGTH TV attribute). Numeric
// only; algorithm meaning lives in swan/xcrypto.
type Transform struct {
	Type  wire.TransformType
	ID    uint16
	Attrs []byte
}

// Proposal is one SA proposal (RFC 7296 3.3.1). SPI is empty for IKE
// proposals (spi size 0) and 4 bytes for ESP proposals.
type Proposal struct {
	Num        uint8
	ProtocolID uint8
	SPI        []byte
	Transforms []Transform
}

// AppendTransform appends one transform substructure; last controls the
// chain marker (TransformChainLast vs TransformChainMore). Attribute areas
// that overflow the wire length field fail hard (panic).
func AppendTransform(dst []byte, t Transform, last bool) []byte {
	if TransformHeaderLen+len(t.Attrs) > 0xFFFF {
		panic(fmt.Sprintf("github.com/wsm25/swan/payload: transform length %d exceeds wire limit 65535", TransformHeaderLen+len(t.Attrs)))
	}
	start := len(dst)
	dst = append(dst, 0, 0, 0, 0, byte(t.Type), 0, 0, 0)
	if last {
		dst[start] = wire.TransformChainLast
	} else {
		dst[start] = wire.TransformChainMore
	}
	putUint16(dst[start+2:start+4], uint16(TransformHeaderLen+len(t.Attrs)))
	putUint16(dst[start+6:start+8], t.ID)
	return append(dst, t.Attrs...)
}

// ParseTransform decodes one transform and returns any remaining bytes.
func ParseTransform(b []byte) (Transform, []byte, error) {
	if len(b) < TransformHeaderLen {
		return Transform{}, nil, fmt.Errorf("transform too short: %d bytes", len(b))
	}
	length := int(beUint16(b[2:4]))
	if length < TransformHeaderLen {
		return Transform{}, nil, fmt.Errorf("invalid transform length %d", length)
	}
	if length > len(b) {
		return Transform{}, nil, fmt.Errorf("transform length %d exceeds remaining %d", length, len(b))
	}
	t := Transform{
		Type:  wire.TransformType(b[4]),
		ID:    beUint16(b[6:8]),
		Attrs: b[TransformHeaderLen:length],
	}
	return t, b[length:], nil
}

// AppendProposal appends one proposal header plus its transform bodies;
// more controls the proposal chain marker (ProposalChainMore / last).
// SPI chunks longer than 255, more than 255 transforms, or proposal bodies
// exceeding the wire length field fail hard (panic).
func AppendProposal(dst []byte, p Proposal, more bool) []byte {
	if len(p.SPI) > 255 {
		panic(fmt.Sprintf("github.com/wsm25/swan/payload: proposal SPI length %d exceeds wire limit 255", len(p.SPI)))
	}
	if len(p.Transforms) > 255 {
		panic(fmt.Sprintf("github.com/wsm25/swan/payload: %d proposal transforms exceed the wire limit 255", len(p.Transforms)))
	}
	transformLen := 0
	for i := range p.Transforms {
		transformLen += TransformHeaderLen + len(p.Transforms[i].Attrs)
	}
	total := ProposalHeaderLen + len(p.SPI) + transformLen
	if total > 0xFFFF {
		panic(fmt.Sprintf("github.com/wsm25/swan/payload: proposal length %d exceeds wire limit 65535", total))
	}

	start := len(dst)
	dst = append(dst, 0, 0, 0, 0, p.Num, p.ProtocolID, byte(len(p.SPI)), byte(len(p.Transforms)))
	if more {
		dst[start] = wire.ProposalChainMore
	} else {
		dst[start] = wire.TransformChainLast
	}
	putUint16(dst[start+2:start+4], uint16(total))
	dst = append(dst, p.SPI...)
	for i := range p.Transforms {
		dst = AppendTransform(dst, p.Transforms[i], i == len(p.Transforms)-1)
	}
	return dst
}

// ParseProposal decodes one proposal (header, SPI and all chained
// transforms) and returns any remaining bytes.
func ParseProposal(b []byte) (Proposal, []byte, error) {
	if len(b) < ProposalHeaderLen {
		return Proposal{}, nil, fmt.Errorf("proposal too short: %d bytes", len(b))
	}
	length := int(beUint16(b[2:4]))
	if length < ProposalHeaderLen {
		return Proposal{}, nil, fmt.Errorf("invalid proposal length %d", length)
	}
	if length > len(b) {
		return Proposal{}, nil, fmt.Errorf("proposal length %d exceeds remaining %d", length, len(b))
	}
	end := length
	spiSize := int(b[6])
	numTransforms := int(b[7])
	if ProposalHeaderLen+spiSize > end {
		return Proposal{}, nil, fmt.Errorf("proposal spi exceeds declared length")
	}
	if numTransforms == 0 {
		return Proposal{}, nil, fmt.Errorf("proposal declares no transforms")
	}

	p := Proposal{
		Num:        b[4],
		ProtocolID: b[5],
		SPI:        b[ProposalHeaderLen : ProposalHeaderLen+spiSize],
	}
	rest := b[ProposalHeaderLen+spiSize : end]
	for i := 0; i < numTransforms; i++ {
		if len(rest) < TransformHeaderLen {
			return Proposal{}, nil, fmt.Errorf("transform %d too short: %d bytes", i, len(rest))
		}
		marker := rest[0]
		t, tail, err := ParseTransform(rest)
		if err != nil {
			return Proposal{}, nil, err
		}
		p.Transforms = append(p.Transforms, t)
		rest = tail

		last := i == numTransforms-1
		if marker == wire.TransformChainLast {
			if !last {
				return Proposal{}, nil, fmt.Errorf("transform chain ended after %d of %d transforms", i+1, numTransforms)
			}
			break
		}
		if marker != wire.TransformChainMore {
			return Proposal{}, nil, fmt.Errorf("invalid transform chain marker 0x%02x", marker)
		}
		if last {
			return Proposal{}, nil, fmt.Errorf("transform chain missing last marker")
		}
	}
	if len(rest) != 0 {
		return Proposal{}, nil, fmt.Errorf("proposal has %d trailing bytes", len(rest))
	}
	return p, b[end:], nil
}

// KeyLengthAttr encodes the KEY_LENGTH transform attribute (TV format,
// value in bits) as the 4 raw attribute bytes.
func KeyLengthAttr(bits uint16) []byte {
	out := make([]byte, 4)
	putUint16(out[0:2], wire.TransformAttrKeyLength|wire.TransformAttrFormatTV)
	putUint16(out[2:4], bits)
	return out
}

// ParseKeyLengthAttr decodes exactly one KEY_LENGTH TV attribute.
func ParseKeyLengthAttr(attrs []byte) (uint16, error) {
	if len(attrs) != 4 {
		return 0, fmt.Errorf("invalid key length attribute size %d", len(attrs))
	}
	typ := beUint16(attrs[0:2])
	if typ&wire.TransformAttrFormatTV == 0 {
		return 0, fmt.Errorf("key length must use tv attribute format")
	}
	if typ&^wire.TransformAttrFormatTV != wire.TransformAttrKeyLength {
		return 0, fmt.Errorf("unsupported transform attribute 0x%04x", typ)
	}
	return beUint16(attrs[2:4]), nil
}
