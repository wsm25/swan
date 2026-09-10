package swan

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/wsm25/swan/transport"
)

// FrameConn adapts a net.PacketConn into the byte-stream wire swan expects:
// each UDP datagram becomes one frame [2-byte big-endian length][payload],
// and each framed Write is emitted as exactly one datagram.
//
// The PacketConn should be connected (net.DialUDP / DialContext with a
// fixed peer). Writes use Write when the PacketConn also implements
// io.Writer (all connected net.Conn implementations do); otherwise they
// fall back to WriteTo with a nil destination, which requires the
// connection to carry its peer address.
//
// The caller must keep the same single reader / single writer discipline
// the transport layer applies: at most one goroutine in Read and one in
// Write. Close is safe from any goroutine; it closes the underlying
// PacketConn, which unblocks a pending Read with net.ErrClosed.
//
// Read errors refer to the stream view: a datagram larger than the frame
// limit is a terminal decode error, and EOF / closed returns the underlying
// error. Read may return partial frame bytes across calls; the bytes are
// always a prefix-contiguous copy of the frame.
type FrameConn struct {
	pc net.PacketConn

	// Single-reader state. buf is reused across datagrams and is only
	// touched when frame is empty; frame is the unconsumed suffix of the
	// current datagram (length prefix included).
	buf   []byte
	frame []byte
	// terminal is the error returned after the current frame has drained
	// (read error observed together with data, or a decode failure).
	terminal error

	closeOnce sync.Once
}

// NewFrameConn wraps pc as the swan wire (io.ReadWriteCloser). See
// FrameConn for the contract.
func NewFrameConn(pc net.PacketConn) io.ReadWriteCloser {
	if pc == nil {
		return nil
	}
	return &FrameConn{pc: pc}
}

// Read implements io.Reader over the framed datagram stream.
func (c *FrameConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c == nil {
		return 0, io.EOF
	}
	for {
		if len(c.frame) > 0 {
			n := copy(p, c.frame)
			c.frame = c.frame[n:]
			if len(c.frame) == 0 {
				c.frame = nil // buf is safe to reuse
			}
			return n, nil
		}
		if c.terminal != nil {
			return 0, c.terminal
		}
		if c.buf == nil {
			c.buf = make([]byte, transport.FrameHeaderSize+transport.MaxFramePayload)
		}
		n, _, err := c.pc.ReadFrom(c.buf[transport.FrameHeaderSize:])
		if err != nil {
			if n <= 0 {
				c.terminal = err
				return 0, err
			}
			// Data plus an error: serve the datagram first, then the error.
			c.terminal = err
		}
		if n > transport.MaxFramePayload {
			c.terminal = fmt.Errorf("swan: frame payload length %d exceeds max %d", n, transport.MaxFramePayload)
			return 0, c.terminal
		}
		binary.BigEndian.PutUint16(c.buf[:transport.FrameHeaderSize], uint16(n))
		c.frame = c.buf[:transport.FrameHeaderSize+n]
	}
}

// Write implements io.Writer. p carries one or more complete frames; every
// frame becomes one datagram. A trailing partial header or frame is an
// io.ErrShortWrite, and an oversized declared length is a decode error.
// The returned count is the number of input bytes consumed by complete
// frames; on the first error it may be less than len(p).
func (c *FrameConn) Write(p []byte) (int, error) {
	if c == nil {
		return 0, io.ErrClosedPipe
	}
	consumed := 0
	for len(p) >= transport.FrameHeaderSize {
		n := int(binary.BigEndian.Uint16(p[:transport.FrameHeaderSize]))
		if len(p) < transport.FrameHeaderSize+n {
			return consumed, io.ErrShortWrite
		}
		payload := p[transport.FrameHeaderSize : transport.FrameHeaderSize+n]
		m, err := c.writeDatagram(payload)
		if err != nil {
			return consumed, err
		}
		if m != n {
			return consumed, io.ErrShortWrite
		}
		consumed += transport.FrameHeaderSize + n
		p = p[transport.FrameHeaderSize+n:]
	}
	if len(p) > 0 {
		return consumed, io.ErrShortWrite
	}
	return consumed, nil
}

// Close closes the underlying PacketConn. It is idempotent and safe to call
// concurrently with Read/Write: the blocked Read returns the connection's
// close error and Writes fail with the connection's error.
func (c *FrameConn) Close() error {
	if c == nil {
		return nil
	}
	err := net.ErrClosed
	c.closeOnce.Do(func() {
		err = c.pc.Close()
		if errors.Is(err, io.EOF) {
			err = nil
		}
	})
	return err
}

// writeDatagram sends one payload. Connected sockets (every net.Conn) take
// the Write path; WriteTo with a nil destination is the PacketConn fallback.
func (c *FrameConn) writeDatagram(payload []byte) (int, error) {
	if w, ok := c.pc.(io.Writer); ok {
		return w.Write(payload)
	}
	return c.pc.WriteTo(payload, nil)
}

var _ io.ReadWriteCloser = (*FrameConn)(nil)
