package esp

import (
	"context"
	"sync"

	"swan/transport"
)

// Pipeline runs the two data-plane workers and connects them to the rest of
// the session:
//
//	transport rx ── espIn ──► InboundWorker ── ipOut ──► Tunnel (user)
//	Tunnel (user) ── ipIn ──► OutboundWorker ── tx ─────► transport tx
//
// Run starts both worker goroutines and waits for ctx to end or the input
// channels to close; workers exit after the bounded queues they own drain.
// After Run returns the workers have released the channels handed to them.
//
// Shutdown contract for the facade: cancel ctx (or close espIn/ipIn) first,
// wait on Done, and only then close ipOut/tx. Otherwise a sender could
// observe a closed receiver channel.
type Pipeline struct {
	inbound  *Inbound
	outbound *Outbound

	espIn <-chan *transport.Packet
	ipIn  <-chan []byte
	ipOut chan<- []byte
	tx    chan<- *transport.Frame

	done     chan struct{}
	doneOnce sync.Once
}

// NewPipeline binds the codec pair and the four channels. Channels must be
// bounded; ownership of each message follows the package comment.
func NewPipeline(inbound *Inbound, outbound *Outbound, espIn <-chan *transport.Packet, ipIn <-chan []byte, ipOut chan<- []byte, tx chan<- *transport.Frame) *Pipeline {
	return &Pipeline{
		inbound:  inbound,
		outbound: outbound,
		espIn:    espIn,
		ipIn:     ipIn,
		ipOut:    ipOut,
		tx:       tx,
		done:     make(chan struct{}),
	}
}

// Run starts the inbound and outbound workers, then blocks until ctx is
// canceled or both input channels close and both workers drain/exit.
// Per-packet drop conditions (malformed ESP, bad IP versions) never kill
// the tunnel; ctx cancellation is the only value Run returns as an error.
func (p *Pipeline) Run(ctx context.Context) error {
	defer p.doneOnce.Do(func() { close(p.done) })

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		p.runInbound(ctx)
	}()
	go func() {
		defer wg.Done()
		p.runOutbound(ctx)
	}()
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

// Done is closed once both workers have exited.
func (p *Pipeline) Done() <-chan struct{} {
	if p == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return p.done
}

// runInbound decrypts classified ESP datagrams. Every consumed
// transport.Packet is released exactly once, including on the error/drop
// path. Malformed packets are dropped so a single bad datagram cannot take
// the tunnel down; a canceling ctx ends the loop.
func (p *Pipeline) runInbound(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-p.espIn:
			if !ok {
				return
			}
			if pkt == nil {
				continue
			}

			ip, err := p.processInbound(pkt)
			pkt.Release()
			if err != nil {
				// MVP tolerance: drop malformed ESP without killing the
				// tunnel. A per-packet debug hook can be wired here later.
				continue
			}

			select {
			case p.ipOut <- ip:
			case <-ctx.Done():
				return
			}
		}
	}
}

// processInbound keeps the per-packet logic separate so runInbound stays a
// thin loop; when a debug logger is wired into esp this is the natural
// boundary for one malformed-packet log line.
func (p *Pipeline) processInbound(pkt *transport.Packet) ([]byte, error) {
	return p.inbound.Process(pkt.Payload)
}

// runOutbound pulls raw IP packets from the user queue, encrypts them and
// submits ESP frames into the shared transport write queue. Per-packet
// drops (empty/foreign IP versions) mirror the inbound tolerance.
func (p *Pipeline) runOutbound(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-p.ipIn:
			if !ok {
				return
			}
			if pkt == nil {
				continue
			}

			datagram, err := p.outbound.Process(pkt)
			if err != nil {
				continue
			}

			frame := &transport.Frame{
				Kind:    transport.KindESP,
				Payload: datagram,
			}
			select {
			case p.tx <- frame:
			case <-ctx.Done():
				return
			}
		}
	}
}
