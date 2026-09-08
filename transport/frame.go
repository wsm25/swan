package transport

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// Frame constants for the stream framing described in the package doc.
const (
	// FrameHeaderSize is the uint16 big-endian length prefix.
	FrameHeaderSize = 2
	// MaxFramePayload is the largest supported frame payload; any larger
	// declared length is rejected as a decode error.
	MaxFramePayload = 65535
	// LogicalNatTPort is the logical NAT-T/IKE port used inside the
	// protocol. NAT-D hashing, keepalives and classification always use
	// this value, never a backend-specific local port.
	LogicalNatTPort = 4500
	// NonESPMarkerLen is the size of the all-zero non-ESP marker that
	// prefixes IKE payloads in NAT-T frames.
	NonESPMarkerLen = 4
)

// Kind is the classification result / frame type of a NAT-T payload.
type Kind uint8

const (
	// KindIKE is an IKEv2 control message. On the wire the payload starts
	// with the 4-byte non-ESP marker; Classify strips it before delivery.
	KindIKE Kind = iota
	// KindESP is a UDP-encapsulated ESP datagram.
	KindESP
	// KindKeepalive is the 1-byte NAT-T keepalive probe (0xff). It is
	// consumed inside the transport layer and never delivered.
	KindKeepalive
)

// Frame is an outbound NAT-T datagram destined for the wire. The producer
// transfers ownership when it sends the Frame through the tx channel.
type Frame struct {
	Kind    Kind
	Payload []byte
}

// Packet is a classified inbound datagram. The payload is exclusive to the
// receiver: the owner is responsible for returning it to the buffer pool
// via Release once parsed (or for retaining a copy when the bytes outlive
// processing). A packet whose release hook is nil owns ordinary GC memory
// and does not need an explicit return.
type Packet struct {
	Kind    Kind
	Payload []byte

	release func()
}

// Release returns a pooled packet buffer to the pool. Call it exactly once
// when the packet bytes are no longer needed; it is a no-op for packets
// that were not carved out of the rx pool. The payload must not be used
// after Release.
func (p *Packet) Release() {
	if p == nil || p.release == nil {
		return
	}
	p.release()
	p.release = nil
	p.Payload = nil
}

// Classify inspects an unframed NAT-T payload and reports its kind.
// It implements the swan2 rules: single 0xff byte is keepalive, a leading
// NonESPMarkerLen bytes of zero is IKE, everything else is ESP.
func Classify(payload []byte) Kind {
	if len(payload) == 1 && payload[0] == 0xff {
		return KindKeepalive
	}
	if len(payload) >= NonESPMarkerLen && zeros(payload[:NonESPMarkerLen]) {
		return KindIKE
	}
	return KindESP
}

func zeros(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// ReadFrame reads exactly one frame from the stream, including the length
// prefix. Callers may pass a scratch buffer to reuse; nil allocates. The
// returned Frame.Payload may alias scratch: the caller owns it and must not
// keep using scratch until the payload is done.
//
// io.EOF is returned only at a clean frame boundary (zero bytes read). A
// truncated frame is reported as io.ErrUnexpectedEOF.
func ReadFrame(r io.Reader, scratch []byte) (Frame, error) {
	var hdr [FrameHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if err == io.EOF {
			return Frame{}, io.EOF
		}
		return Frame{}, fmt.Errorf("swan/transport: read frame header: %w", err)
	}

	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > MaxFramePayload {
		return Frame{}, fmt.Errorf("swan/transport: frame payload %d exceeds limit %d", n, MaxFramePayload)
	}

	payload := grow(scratch, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return Frame{}, fmt.Errorf("swan/transport: read frame payload: %w", err)
	}

	return Frame{Kind: Classify(payload), Payload: payload}, nil
}

func grow(scratch []byte, n int) []byte {
	if cap(scratch) >= n {
		return scratch[:n]
	}
	return make([]byte, n)
}

// WriteFrame writes one frame (length prefix plus payload) in a single
// Write call, iterating until every byte is written. The payload is written
// verbatim: NAT-T marker/keepalive shaping is the caller's (or TxWorker's)
// job.
func WriteFrame(w io.Writer, f Frame) error {
	if len(f.Payload) > MaxFramePayload {
		return fmt.Errorf("swan/transport: frame payload %d exceeds limit %d", len(f.Payload), MaxFramePayload)
	}
	buf := make([]byte, FrameHeaderSize+len(f.Payload))
	binary.BigEndian.PutUint16(buf[:FrameHeaderSize], uint16(len(f.Payload)))
	copy(buf[FrameHeaderSize:], f.Payload)
	return writeAll(w, buf)
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return fmt.Errorf("swan/transport: invalid write count %d", n)
		}
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// LogicalAddr returns the address with its port replaced by the logical
// NAT-T port 4500. IPv6 zones are preserved, IPAddr values (which have no
// port) are returned as-is, and opaque backend addresses pass through
// unchanged. Resolution stays with the backend; this only normalizes the
// port so NAT-D behaves like the MVP profile requires.
func LogicalAddr(a net.Addr) net.Addr {
	if a == nil {
		return nil
	}
	switch v := a.(type) {
	case *net.TCPAddr:
		out := *v
		out.Port = LogicalNatTPort
		return &out
	case *net.UDPAddr:
		out := *v
		out.Port = LogicalNatTPort
		return &out
	default:
		return a
	}
}
