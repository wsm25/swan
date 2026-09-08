package payload

import (
	"fmt"

	"swan/wire"
)

// Delete is the body of a DELETE payload: protocol id, SPI size implied by
// protocol (0 for IKE, 4 for ESP) and the SPI list (empty for IKE).
type Delete struct {
	ProtocolID uint8
	SPIs       []uint32
}

// AppendDelete serializes the DELETE payload body; PRECONDITION: SPIs empty
// for DeleteProtocolIKE, exactly one for the MVP's CHILD_SA delete.
func AppendDelete(dst []byte, d Delete) []byte {
	spiSize := byte(0)
	if d.ProtocolID == wire.DeleteProtocolESP {
		spiSize = 4
	}
	start := len(dst)
	dst = append(dst, d.ProtocolID, spiSize, 0, 0)
	putUint16(dst[start+2:start+4], uint16(len(d.SPIs)))
	for _, spi := range d.SPIs {
		dst = append(dst, 0, 0, 0, 0)
		putUint32(dst[len(dst)-4:], spi)
	}
	return dst
}

// ParseDelete decodes the payload and enforces the IKE/ESP spi-size and
// count rules.
func ParseDelete(b []byte) (Delete, error) {
	if len(b) < DeleteFixedLen {
		return Delete{}, fmt.Errorf("delete payload too short: %d bytes", len(b))
	}
	protocolID := b[0]
	spiSize := int(b[1])
	count := int(beUint16(b[2:4]))

	switch protocolID {
	case wire.DeleteProtocolIKE:
		if spiSize != 0 {
			return Delete{}, fmt.Errorf("ike delete must not carry spi values")
		}
		if count != 0 {
			return Delete{}, fmt.Errorf("ike delete must not carry spi count")
		}
	case wire.DeleteProtocolESP:
		if spiSize != 4 {
			return Delete{}, fmt.Errorf("esp delete must carry 4-byte spis, got size %d", spiSize)
		}
		if count == 0 {
			return Delete{}, fmt.Errorf("esp delete must carry at least one spi")
		}
	default:
		return Delete{}, fmt.Errorf("unsupported delete protocol %d", protocolID)
	}

	expected := DeleteFixedLen + count*spiSize
	if len(b) != expected {
		return Delete{}, fmt.Errorf("invalid delete payload length: declared %d, have %d", expected, len(b))
	}

	d := Delete{ProtocolID: protocolID}
	for off := DeleteFixedLen; off < len(b); off += 4 {
		d.SPIs = append(d.SPIs, beUint32(b[off:off+4]))
	}
	return d, nil
}

var _ = wire.PayloadTypeDelete
