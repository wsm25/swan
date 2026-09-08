package wire

import "fmt"

// decodeErr keeps the error text for a malformed payload chain in one place.
func errPayloadHeader(t PayloadType, remaining int) error {
	return fmt.Errorf("payload type %d too short for its header: %d bytes remaining", t, remaining)
}

func errPayloadLength(t PayloadType, declared int) error {
	return fmt.Errorf("payload type %d length out of bounds: declared %d bytes", t, declared)
}

func errNotTerminal(t PayloadType, trailing int) error {
	return fmt.Errorf("payload type %d must terminate the outer payload chain: %d trailing bytes", t, trailing)
}

func errUnexpectedEncrypted(t PayloadType) error {
	return fmt.Errorf("payload type %d is only valid as a terminal outer payload", t)
}

func errTrailingBytes(n int) error {
	return fmt.Errorf("invalid payload chain: %d trailing bytes after next-payload end", n)
}
