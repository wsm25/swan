package wire

import "fmt"

// Builder assembles the outer prefix of an IKE packet: the 28-byte header
// followed by cleartext payloads with next-payload chaining maintained
// automatically. It is append-style and reuses one pre-sized buffer.
//
// Terminal SK/SKF payloads are deliberately not pushed through the generic
// Push: their length and ICV extend beyond the payload body, so swan/control
// builds them over b.Bytes() (used as the AEAD/ICV AAD prefix) and patches
// the header length itself. See swan/control.protected.
type Builder struct {
	buf      []byte
	first    PayloadType
	firstSet bool
	// lastNextOffset is the offset of the next-payload field to patch when
	// the next payload is pushed: initially the IKE header's next-payload
	// field at offset 16, then each pushed payload's header field.
	lastNextOffset int
	header         Header
}

// NewBuilder allocates a builder seeded with the IKE header.
func NewBuilder(h Header) *Builder {
	return &Builder{
		buf:            h.MarshalTo(nil),
		lastNextOffset: 16,
		header:         h,
	}
}

// Push appends one payload: generic payload header (critical flag, length)
// plus body, and rewires the previous payload's next-payload field to t.
func (b *Builder) Push(t PayloadType, critical bool, body []byte) error {
	if t == PayloadTypeNone {
		return errPayloadNone
	}
	total := PayloadHeaderLen + len(body)
	if total > 0xffff {
		return errPayloadTooLarge(t, total)
	}
	if len(b.buf)+total > 0xffff+HeaderLen {
		return errPacketTooLarge(len(b.buf) + total)
	}

	start := len(b.buf)
	b.buf = append(b.buf, 0, 0, 0, 0)
	b.buf[start] = byte(PayloadTypeNone)
	if critical {
		b.buf[start+1] = 0x80
	} else {
		b.buf[start+1] = 0
	}
	putUint16(b.buf[start+2:start+4], uint16(total))
	if b.lastNextOffset >= 0 {
		b.buf[b.lastNextOffset] = byte(t)
	}
	b.lastNextOffset = start
	b.buf = append(b.buf, body...)

	if !b.firstSet {
		b.first = t
		b.firstSet = true
	}
	return nil
}

// Bytes returns the current buffer. During SK/SKF construction the caller
// uses this as the AAD prefix (IKE header + cleartext payloads); after the
// encrypted tail is appended the caller must PatchLength.
func (b *Builder) Bytes() []byte {
	return b.buf
}

// FirstPayload reports the first payload type of the chain (PayloadTypeNone
// when empty).
func (b *Builder) FirstPayload() PayloadType {
	if !b.firstSet {
		return PayloadTypeNone
	}
	return b.first
}

// PatchLength overwrites the header length field with the current buffer
// size. Needed after SK/SKF tails are appended outside the Builder.
func (b *Builder) PatchLength() {
	putUint32(b.buf[24:28], uint32(len(b.buf)))
}

// Finish finalizes a cleartext packet: stamps the first payload into the
// header, patches the total length and returns the packet bytes. The buffer
// is owned by the returned slice afterwards.
func (b *Builder) Finish() []byte {
	b.buf[16] = byte(b.FirstPayload())
	b.PatchLength()
	return b.buf
}

var (
	errPayloadNone = errPayloadHeaderValue(PayloadTypeNone, "cannot push None as a payload")
)

func errPayloadHeaderValue(t PayloadType, msg string) error {
	return fmt.Errorf("payload type %d: %s", t, msg)
}

func errPayloadTooLarge(t PayloadType, n int) error {
	return fmt.Errorf("payload type %d too long: %d bytes", t, n)
}

func errPacketTooLarge(n int) error {
	return fmt.Errorf("ike packet too long: %d bytes", n)
}
