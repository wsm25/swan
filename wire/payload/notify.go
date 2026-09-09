package payload

import (
	"fmt"

	"swan/wire"
)

// Notify is the body of a NOTIFY payload: protocol id, SPI (0/4/8 bytes
// depending on ScopingType and protocol), message type and optional data.
//
// Validation mirrors swan2: notify without SPI must use protocol 0 or IKE;
// notify with SPI must target AH or ESP.
type Notify struct {
	ProtocolID uint8
	SPI        []byte
	Type       wire.NotifyType
	Data       []byte
}

// AppendNotify serializes the NOTIFY payload body from plain fields;
// spiSize is derived from the protocol id and len(SPI). SPI lengths that
// exceed the wire field (255) fail hard (panic).
func AppendNotify(dst []byte, n Notify) []byte {
	if len(n.SPI) > 255 {
		panic(fmt.Sprintf("swan/payload: notify SPI length %d exceeds wire limit 255", len(n.SPI)))
	}
	start := len(dst)
	dst = append(dst, n.ProtocolID, byte(len(n.SPI)), 0, 0)
	putUint16(dst[start+2:start+4], uint16(n.Type))
	dst = append(dst, n.SPI...)
	return append(dst, n.Data...)
}

// ParseNotify decodes the payload, derives the SPI slice from the header's
// spi-size field and validates SPI/protocol scoping.
func ParseNotify(b []byte) (Notify, error) {
	if len(b) < NotifyFixedLen {
		return Notify{}, fmt.Errorf("notify payload too short: %d bytes", len(b))
	}
	spiSize := int(b[1])
	if NotifyFixedLen+spiSize > len(b) {
		return Notify{}, fmt.Errorf("notify payload spi exceeds remaining bytes")
	}
	n := Notify{
		ProtocolID: b[0],
		SPI:        b[NotifyFixedLen : NotifyFixedLen+spiSize],
		Type:       wire.NotifyType(beUint16(b[2:4])),
		Data:       b[NotifyFixedLen+spiSize:],
	}
	if err := checkNotifyScope(n.ProtocolID, len(n.SPI)); err != nil {
		return Notify{}, err
	}
	return n, nil
}

func checkNotifyScope(protocolID uint8, spiLen int) error {
	if spiLen == 0 {
		if protocolID != wire.NotifyProtocolNone && protocolID != wire.DeleteProtocolIKE {
			return fmt.Errorf("notify without spi must use protocol 0 or ike, got %d", protocolID)
		}
		return nil
	}
	if protocolID != wire.DeleteProtocolAH && protocolID != wire.DeleteProtocolESP {
		return fmt.Errorf("notify with spi must target ah or esp, got %d", protocolID)
	}
	return nil
}

var _ = wire.PayloadTypeNotify
