// Package wiretest adapts a connected UDP socket into the swan byte-stream
// wire format used by the debug/benchmark clients.
package wiretest

import (
	"fmt"
	"net"
)

// UDPWire adapts a connected UDP socket (*net.UDPConn implements
// Read/Write/Close on datagrams) into the swan byte-stream wire format.
type UDPWire struct {
	conn *net.UDPConn
	hex  *bool

	// writeBuf accumulates the stream until complete frames can be sent.
	writeBuf []byte

	// fetch is the reused socket read buffer; the payload slice it exposes
	// is valid only until the next Read call.
	fetch []byte
	// hdr is the 2-byte length prefix of the frame being served.
	hdr    [2]byte
	hdrOff int
	// payload is the datagram of the frame being served; nil when none.
	payload []byte
	payOff  int
}

// NewUDPWire connects to server and returns a stream-framing adapter. When
// hex is non-nil and true, raw datagrams are dump on stdout for debugging.
func NewUDPWire(server string, hex *bool) (*UDPWire, error) {
	addr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", server, err)
	}
	var laddr *net.UDPAddr
	if addr.IP.IsLoopback() {
		if addr.IP.To4() != nil {
			laddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
		} else {
			laddr = &net.UDPAddr{IP: net.IPv6loopback}
		}
	}
	conn, err := net.DialUDP("udp", laddr, addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", server, err)
	}
	return &UDPWire{conn: conn, hex: hex}, nil
}

// Read serves one stream byte at a time: first the 2-byte frame length,
// then the fetched datagram payload itself. The payload is handed out
// directly from the socket buffer (no per-frame copy); it stays valid only
// until the next Read.
func (w *UDPWire) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if w.hdrOff < 2 {
			n := copy(p, w.hdr[w.hdrOff:])
			w.hdrOff += n
			return n, nil
		}
		if w.payload != nil && w.payOff < len(w.payload) {
			n := copy(p, w.payload[w.payOff:])
			w.payOff += n
			return n, nil
		}
		if cap(w.fetch) < 65535 {
			w.fetch = make([]byte, 65535)
		}
		buf := w.fetch[:65535]
		n, err := w.conn.Read(buf)
		if err != nil {
			return 0, err
		}
		if w.hex != nil && *w.hex {
			fmt.Printf("wire recv %d: %x\n", n, buf[:n])
		}
		w.hdr[0] = byte(n >> 8)
		w.hdr[1] = byte(n)
		w.hdrOff = 0
		w.payload = buf[:n]
		w.payOff = 0
	}
}

// Write buffers stream bytes and emits every complete frame as one UDP
// datagram to the connected peer.
func (w *UDPWire) Write(p []byte) (int, error) {
	w.writeBuf = append(w.writeBuf, p...)
	off := 0
	for len(w.writeBuf)-off >= 2 {
		length := int(w.writeBuf[off])<<8 | int(w.writeBuf[off+1])
		if len(w.writeBuf)-off < 2+length {
			break
		}
		if w.hex != nil && *w.hex {
			fmt.Printf("wire send %d: %x\n", length, w.writeBuf[off+2:off+2+length])
		}
		if _, err := w.conn.Write(w.writeBuf[off+2 : off+2+length]); err != nil {
			return 0, err
		}
		off += 2 + length
	}
	w.writeBuf = append(w.writeBuf[:0], w.writeBuf[off:]...)
	return len(p), nil
}

// Close closes the underlying UDP socket.
func (w *UDPWire) Close() error { return w.conn.Close() }
