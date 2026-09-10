// Package wiretest adapts a connected UDP socket into the swan wire
// contract: one datagram per Read/Write, exactly like *net.UDPConn itself.
// It only adds the optional hex dump used by the debug/benchmark clients.
package wiretest

import (
	"fmt"
	"net"
)

// UDPWire is a connected UDP socket with optional hex logging. It satisfies
// the swan wire contract directly (datagram Read/Write semantics).
type UDPWire struct {
	conn *net.UDPConn
	hex  *bool
}

// NewUDPWire connects to server and returns a wire-ready adapter. When hex
// is non-nil and true, raw datagrams are dumped on stdout for debugging.
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

// Read returns one UDP datagram.
func (w *UDPWire) Read(p []byte) (int, error) {
	n, err := w.conn.Read(p)
	if w.hex != nil && *w.hex && n > 0 {
		fmt.Printf("wire recv %d: %x\n", n, p[:n])
	}
	return n, err
}

// Write sends one UDP datagram.
func (w *UDPWire) Write(p []byte) (int, error) {
	if w.hex != nil && *w.hex && len(p) > 0 {
		fmt.Printf("wire send %d: %x\n", len(p), p)
	}
	return w.conn.Write(p)
}

// Close closes the underlying UDP socket.
func (w *UDPWire) Close() error { return w.conn.Close() }
