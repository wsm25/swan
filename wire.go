package swan

import (
	"encoding/binary"
	"io"
	"net"
	"sync"

	"github.com/wsm25/swan/transport"
)

// MaxWireDatagram is the largest legal NAT-T wire datagram payload; callers
// size Read/ReadBatch buffers with it.
const MaxWireDatagram = transport.MaxWireDatagram

// NewPacketWire adapts a datagram net.PacketConn into the swan wire
// (io.ReadWriteCloser with datagram Read/Write semantics, exactly like a
// connected *net.UDPConn). When pc already implements io.ReadWriteCloser it
// is returned as-is; otherwise Read/Write bridge through ReadFrom/WriteTo
// (the connection must carry its peer address for WriteTo).
//
// Batch capabilities (e.g. *net.UDPConn.WriteBatch) pass through untouched
// and are discovered by the transport via type assertion.
func NewPacketWire(pc net.PacketConn) io.ReadWriteCloser {
	if pc == nil {
		return nil
	}
	if rwc, ok := pc.(io.ReadWriteCloser); ok {
		return rwc
	}
	return &packetWire{pc: pc}
}

type packetWire struct {
	pc net.PacketConn
}

func (w *packetWire) Read(p []byte) (int, error) {
	n, _, err := w.pc.ReadFrom(p)
	return n, err
}

func (w *packetWire) Write(p []byte) (int, error) {
	return w.pc.WriteTo(p, nil)
}

func (w *packetWire) Close() error { return w.pc.Close() }

// NewFramedWire adapts a byte-stream io.ReadWriteCloser into the swan wire:
// every datagram becomes one [2-byte big-endian length][payload] frame, and
// incoming frames are reconstructed from the stream. This framing is the
// stream adapter's private convention, not part of the swan wire contract;
// only stream-based backends (TCP/TLS/pipes) need it.
//
// Data beyond MaxWireDatagram is rejected as a decode error on Read. Write
// sends exactly one frame per call. The caller keeps the single
// reader/single writer discipline the transport imposes; Close is safe from
// any goroutine and closes the underlying stream.
func NewFramedWire(rw io.ReadWriteCloser) io.ReadWriteCloser {
	if rw == nil {
		return nil
	}
	return &framedWire{rw: rw}
}

type framedWire struct {
	rw io.ReadWriteCloser

	// Single-reader state. acc accumulates stream bytes until one complete
	// frame (length prefix + payload) is available.
	acc []byte
	// rbuf is the reusable per-read scratch for the underlying stream.
	rbuf []byte
	// terminal is the error returned once acc has drained (a read error
	// observed together with data, or a truncation/decode failure).
	terminal error

	closeOnce sync.Once
	closeErr  error
}

// Read blocks until one complete frame is available and returns exactly
// one datagram payload per call (the length prefix is this adapter's
// internal encoding, never exposed). p must hold MaxWireDatagram bytes.
func (w *framedWire) Read(p []byte) (int, error) {
	if w == nil {
		return 0, io.EOF
	}
	for {
		// A truncated frame at stream end is the only err source besides
		// the terminal latch: io.ErrUnexpectedEOF is sticky once acc holds
		// a partial prefix.
		if w.terminal != nil {
			if len(w.acc) == 0 {
				return 0, w.terminal
			}
			if len(w.acc) < 2 {
				w.acc = nil
				return 0, io.ErrUnexpectedEOF
			}
			n := int(binary.BigEndian.Uint16(w.acc[:2]))
			if len(w.acc) < 2+n {
				w.acc = nil
				return 0, io.ErrUnexpectedEOF
			}
		}
		for len(w.acc) < 2 || len(w.acc) < 2+int(binary.BigEndian.Uint16(w.acc[:2])) {
			if w.terminal != nil {
				w.acc = nil
				return 0, io.ErrUnexpectedEOF
			}
			if w.rbuf == nil {
				w.rbuf = make([]byte, 32*1024)
			}
			n, err := w.rw.Read(w.rbuf)
			if n > 0 {
				w.acc = append(w.acc, w.rbuf[:n]...)
			}
			if err != nil {
				if err == io.EOF && n > 0 {
					// Data plus EOF: the next loop pass handles truncation.
					err = nil
				}
				if err != nil {
					w.terminal = err
					if len(w.acc) == 0 {
						return 0, err
					}
					continue
				}
			}
		}
		n := int(binary.BigEndian.Uint16(w.acc[:2]))
		if len(p) < n {
			return 0, io.ErrShortBuffer
		}
		copy(p, w.acc[2:2+n])
		w.acc = w.acc[2+n:]
		return n, nil
	}
}

// Write sends p as one [length][payload] frame over the stream.
func (w *framedWire) Write(p []byte) (int, error) {
	if w == nil {
		return 0, io.ErrClosedPipe
	}
	if len(p) > transport.MaxWireDatagram {
		return 0, io.ErrShortWrite
	}
	frame := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(p)))
	copy(frame[2:], p)
	for written := 0; written < len(frame); {
		n, err := w.rw.Write(frame[written:])
		written += n
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, io.ErrShortWrite
		}
	}
	return len(p), nil
}

// Close closes the underlying stream. It is idempotent and unblocks a
// pending Read with the stream's close error.
func (w *framedWire) Close() error {
	if w == nil {
		return nil
	}
	w.closeOnce.Do(func() { w.closeErr = w.rw.Close() })
	return w.closeErr
}

var _ io.ReadWriteCloser = (*packetWire)(nil)
var _ io.ReadWriteCloser = (*framedWire)(nil)
