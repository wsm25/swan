package swan

import (
	"io"
	"sync"

	"swan/control"
)

// Tunnel is the established data plane, exposed as a raw IP packet
// io.ReadWriteCloser.
//
// Read contract: every call returns data from at most one decrypted IP
// packet; packets are never merged across reads. If the caller's buffer is
// smaller than the packet the remainder of the same packet is returned on
// later calls. The returned bytes are a copy owned by the caller.
//
// Write contract: one call carries exactly one raw IP packet; the packet is
// copied, ESP-encrypted by the outbound worker and written to the wire by
// the transport worker. A full bounded queue blocks the caller
// (backpressure).
type Tunnel struct {
	// Inbound decrypted IP packet stream (reassembled per packet by the esp
	// inbound worker).
	inbound <-chan []byte
	// Outbound queue consumed by the esp outbound worker.
	outbound chan<- []byte

	assigned control.AssignedConfig
	childSA  control.ChildSA

	closed chan struct{}
	done   chan struct{}

	// Remainder of the packet currently being read, when the last Read
	// buffer was smaller than the packet.
	pending []byte

	closeOnce sync.Once
	endOnce   sync.Once
	// closeFn is the session-level graceful shutdown installed by Start.
	closeFn func() error
}

// Read implements io.Reader with one-packet granularity (see Tunnel doc).
// It returns io.EOF once the tunnel is closed and its inbound queue drained.
func (t *Tunnel) Read(p []byte) (int, error) {
	if t == nil {
		return 0, io.EOF
	}
	for {
		if len(t.pending) > 0 {
			n := copy(p, t.pending)
			t.pending = t.pending[n:]
			return n, nil
		}
		select {
		case <-t.closed:
			return 0, io.EOF
		case pkt, ok := <-t.inbound:
			if !ok {
				return 0, io.EOF
			}
			if pkt == nil {
				continue
			}
			n := copy(p, pkt)
			if n < len(pkt) {
				t.pending = append([]byte(nil), pkt[n:]...)
			}
			return n, nil
		}
	}
}

// Write implements io.Writer with one-packet granularity (see Tunnel doc).
// It blocks while the outbound queue is full, providing backpressure toward
// the caller, and returns io.ErrClosedPipe after Close.
func (t *Tunnel) Write(p []byte) (int, error) {
	if t == nil {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 {
		return 0, nil
	}
	// Copy before enqueueing: ownership of the user's slice stays with the
	// caller after Write returns.
	pkt := append([]byte(nil), p...)
	select {
	case <-t.closed:
		return 0, io.ErrClosedPipe
	case t.outbound <- pkt:
		return len(pkt), nil
	}
}

// Close performs the graceful close sequence (CHILD_SA DELETE then IKE_SA
// DELETE) and stops the data plane. It does not close the injected wire.
// Close is idempotent.
func (t *Tunnel) Close() error {
	if t == nil {
		return nil
	}
	var err error
	t.closeOnce.Do(func() {
		if t.closeFn != nil {
			err = t.closeFn()
		}
		t.markEnded()
	})
	return err
}

// Assigned returns the CP-assigned configuration (internal address, DNS).
// Valid after a successful handshake; zero value before that.
func (t *Tunnel) Assigned() control.AssignedConfig {
	if t == nil {
		return control.AssignedConfig{}
	}
	return t.assigned
}

// ChildSA returns the negotiated CHILD_SA identities (SPIs and selectors).
func (t *Tunnel) ChildSA() control.ChildSA {
	if t == nil {
		return control.ChildSA{}
	}
	return t.childSA
}

// Done is closed when the tunnel data plane has terminated.
func (t *Tunnel) Done() <-chan struct{} {
	if t == nil {
		d := make(chan struct{})
		close(d)
		return d
	}
	return t.done
}

// markEnded closes the tunnel termination markers exactly once. It is safe
// to call from both Tunnel.Close and Session.stop.
func (t *Tunnel) markEnded() {
	t.endOnce.Do(func() {
		close(t.closed)
		close(t.done)
	})
}

// Compile-time check: Tunnel is the raw-IP interface.
var _ io.ReadWriteCloser = (*Tunnel)(nil)
