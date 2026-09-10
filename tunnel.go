package swan

import (
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/wsm25/swan/control"
	"github.com/wsm25/swan/esp"
)

// Tunnel is the established data plane, exposed as a raw IP packet
// io.ReadWriteCloser.
//
// Read behavior: every call returns data from at most one decrypted IP
// packet; packets are never merged across reads. If the caller's buffer is
// smaller than the packet the remainder of the same packet is returned on
// later calls. The returned bytes are a copy owned by the caller.
//
// Write behavior: one call carries exactly one raw IP packet; the packet is
// copied, ESP-encrypted by the outbound worker and written to the wire by
// the transport worker. A full bounded queue blocks the caller
// (backpressure).
type Tunnel struct {
	// Inbound decrypted IP packet stream (reassembled per packet by the esp
	// inbound worker). Batches arrive here; Tunnel pops one packet at a
	// time and releases each after its bytes have been copied out of
	// session-owned memory.
	inbound <-chan []esp.InboundPacket
	// Outbound queue consumed by the esp outbound worker.
	outbound chan<- []byte

	// assigned/childSA swap wholesale on control-plane updates (rekey,
	// CFG_SET/CFG_REPLY); accessors return private copies.
	assigned atomic.Pointer[control.AssignedConfig]
	childSA  atomic.Pointer[control.ChildSA]

	closed chan struct{}
	done   chan struct{}

	// closedFlag linearizes Write against markEnded: it flips before the
	// channels close, and Write re-checks it every loop iteration.
	closedFlag atomic.Bool

	// Remainder of the packet currently being read, when the last Read
	// buffer was smaller than the packet.
	pending []byte
	// Current inbound batch not yet fully delivered by Read. The oldest
	// packet is popped per Read call and released after copy; the rest stay
	// here until drained.
	pendingBatch []esp.InboundPacket

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
		if len(t.pendingBatch) > 0 {
			pkt := t.pendingBatch[0]
			t.pendingBatch = t.pendingBatch[1:]
			if len(pkt.IP) == 0 {
				pkt.Release()
				continue
			}
			return deliverPacket(p, pkt, t), nil
		}
		// Draft buffered packets before honoring the closed marker so a
		// Close cannot race a queued packet into an early EOF.
		select {
		case batch, ok := <-t.inbound:
			if !ok {
				return 0, io.EOF
			}
			if len(batch) == 0 {
				continue
			}
			t.pendingBatch = batch
			continue
		default:
		}
		select {
		case <-t.closed:
			// One final drain attempt: packets already queued before the
			// close win over EOF.
			select {
			case batch, ok := <-t.inbound:
				if !ok {
					return 0, io.EOF
				}
				if len(batch) == 0 {
					continue
				}
				t.pendingBatch = batch
				continue
			default:
				return 0, io.EOF
			}
		case batch, ok := <-t.inbound:
			if !ok {
				return 0, io.EOF
			}
			if len(batch) == 0 {
				continue
			}
			t.pendingBatch = batch
			continue
		}
	}
}

// deliverPacket copies one decrypted packet into p, releases the pooled
// inbound backing, and keeps any remainder as t.pending for the next Read.
// The remainder is copied before the release so pending never aliases
// pooled memory.
func deliverPacket(p []byte, pkt esp.InboundPacket, t *Tunnel) int {
	if t == nil || len(pkt.IP) == 0 {
		pkt.Release()
		return 0
	}
	n := copy(p, pkt.IP)
	if n < len(pkt.IP) {
		t.pending = append([]byte(nil), pkt.IP[n:]...)
	}
	pkt.Release()
	return n
}

// Write implements io.Writer with one-packet granularity (see Tunnel doc).
// It blocks while the outbound queue is full, providing backpressure toward
// the caller, and returns io.ErrClosedPipe after Close.
func (t *Tunnel) Write(p []byte) (int, error) {
	if t == nil {
		return 0, io.ErrClosedPipe
	}
	if t.closedFlag.Load() {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 {
		return 0, nil
	}
	// Copy before enqueueing: ownership of the user's slice stays with the
	// caller after Write returns.
	pkt := append([]byte(nil), p...)
	for {
		select {
		case <-t.closed:
			return 0, io.ErrClosedPipe
		default:
		}
		if t.closedFlag.Load() {
			return 0, io.ErrClosedPipe
		}
		select {
		case <-t.closed:
			return 0, io.ErrClosedPipe
		case t.outbound <- pkt:
			// Re-check after the send: markEnded flips the flag BEFORE
			// closing the channels, so a Close that landed concurrently is
			// still observed in the overwhelming majority of schedules.
			if t.closedFlag.Load() {
				return 0, io.ErrClosedPipe
			}
			return len(pkt), nil
		}
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

// Assigned returns a private snapshot of the CP-assigned configuration
// (internal address, DNS). Valid after a successful handshake; zero value
// before that. Control-plane updates replace the snapshot atomically; the
// caller always owns the returned bytes.
func (t *Tunnel) Assigned() control.AssignedConfig {
	if t == nil {
		return control.AssignedConfig{}
	}
	if p := t.assigned.Load(); p != nil {
		return cloneAssigned(*p)
	}
	return control.AssignedConfig{}
}

// ChildSA returns a private snapshot of the negotiated CHILD_SA identities
// (SPIs and selectors). It tracks rekeys the way Assigned tracks CP
// updates.
func (t *Tunnel) ChildSA() control.ChildSA {
	if t == nil {
		return control.ChildSA{}
	}
	if p := t.childSA.Load(); p != nil {
		return cloneChildSA(*p)
	}
	return control.ChildSA{}
}

// setAssigned / setChildSA install a control-plane snapshot. The value is
// cloned before publication, so later control-layer mutation can never
// reach a reader holding an old snapshot.
func (t *Tunnel) setAssigned(a control.AssignedConfig) {
	if t == nil {
		return
	}
	v := cloneAssigned(a)
	t.assigned.Store(&v)
}

func (t *Tunnel) setChildSA(c control.ChildSA) {
	if t == nil {
		return
	}
	v := cloneChildSA(c)
	t.childSA.Store(&v)
}

func cloneAssigned(a control.AssignedConfig) control.AssignedConfig {
	a.InternalIPv4 = append(net.IP(nil), a.InternalIPv4...)
	a.InternalIPv6 = append(net.IP(nil), a.InternalIPv6...)
	a.DNS4 = cloneIPs(a.DNS4)
	a.DNS6 = cloneIPs(a.DNS6)
	return a
}

func cloneChildSA(c control.ChildSA) control.ChildSA {
	c.TSi = append([]byte(nil), c.TSi...)
	c.TSr = append([]byte(nil), c.TSr...)
	return c
}

func cloneIPs(in []net.IP) []net.IP {
	if in == nil {
		return nil
	}
	out := make([]net.IP, len(in))
	for i := range in {
		out[i] = append(net.IP(nil), in[i]...)
	}
	return out
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
// to call from both Tunnel.Close and Session.stop; the atomic flag flips
// first so concurrent Writes fail instead of racing the closed channels.
func (t *Tunnel) markEnded() {
	t.endOnce.Do(func() {
		t.closedFlag.Store(true)
		close(t.closed)
		close(t.done)
	})
}

// Compile-time check: Tunnel is the raw-IP interface.
var _ io.ReadWriteCloser = (*Tunnel)(nil)
