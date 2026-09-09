package esp

import (
	"context"
	"errors"
	"sync"

	"swan/transport"
)

// txBatch is how many additional raw IP packets the outbound worker drains
// after the first one before encrypting and submitting them as one group.
const txBatch = 32

// InboundPacket is one decrypted inner IP packet delivered by the inbound
// worker. IP aliases Inbound-owned pool memory; call Release exactly once
// after the bytes are no longer needed. Release is single-shot and nil-safe.
type InboundPacket struct {
	IP      []byte
	release func()
}

// Release returns the packet's pooled backing to the Inbound pool. It is a
// no-op when called on a nil packet or when it was already released. IP is
// cleared so a use-after-release fails immediately instead of observing
// recycled bytes.
func (p *InboundPacket) Release() {
	if p == nil || p.release == nil {
		return
	}
	p.release()
	p.release = nil
	p.IP = nil
}

// Pipeline runs the two data-plane workers and connects them to the rest of
// the session:
//
//	transport rx ── espIn ──► InboundWorker ── ipOut ──► Tunnel (user)
//	Tunnel (user) ── ipIn ──► OutboundWorker ── tx ─────► transport tx
//
// espIn delivers batches of classified ESP datagrams; ipOut delivers batches
// of decrypted InboundPacket values. The receiver owns each packet in an
// inbound batch and must Release it after consuming the bytes.
//
// Run starts both worker goroutines and waits for ctx to end or the input
// channels to close; workers exit after the bounded queues they own drain.
// After Run returns the workers have released the channels handed to them.
//
// Shutdown order for the Session: cancel ctx (or close espIn/ipIn) first,
// wait on Done, and only then close ipOut/tx. Otherwise a sender could
// observe a closed receiver channel.
type Pipeline struct {
	inbound  *Inbound
	outbound *Outbound

	espIn <-chan []*transport.Packet
	ipIn  <-chan []byte
	ipOut chan<- []InboundPacket
	tx    chan<- *transport.Frame

	// childClosed is closed by the control plane when the peer deletes the
	// active CHILD_SA; both workers stop with it. nil disables the stop.
	childClosed <-chan struct{}
	// fatalOut receives at most one unrecoverable data-plane error (e.g.
	// ESP sequence wrap); the Session turns it into Broken + teardown.
	fatalOut chan<- error

	fatalOnce sync.Once
	done      chan struct{}
	doneOnce  sync.Once
}

// NewPipeline binds the codec pair and the four channels. Channels must be
// bounded; ownership of each message follows the package comment.
func NewPipeline(inbound *Inbound, outbound *Outbound, espIn <-chan []*transport.Packet, ipIn <-chan []byte, ipOut chan<- []InboundPacket, tx chan<- *transport.Frame, childClosed <-chan struct{}, fatalOut chan<- error) *Pipeline {
	return &Pipeline{
		inbound:     inbound,
		outbound:    outbound,
		espIn:       espIn,
		ipIn:        ipIn,
		ipOut:       ipOut,
		tx:          tx,
		childClosed: childClosed,
		fatalOut:    fatalOut,
		done:        make(chan struct{}),
	}
}

// Run starts the inbound and outbound workers, then blocks until ctx is
// canceled, the CHILD_SA is closed, or both input channels close and both
// workers drain/exit. Per-packet drop conditions (malformed ESP, bad IP
// versions) never kill the tunnel.
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

// runInbound decrypts classified ESP datagrams sequentially within each
// received batch. Every consumed transport.Packet is released exactly once,
// including on the error/drop and cancellation paths. Malformed packets are
// dropped so a single bad datagram cannot take the tunnel down; a canceling
// ctx (or a closed childClosed) releases any produced-but-unsent
// InboundPackets and any not-yet-consumed transport.Packets, then ends the
// loop.
func (p *Pipeline) runInbound(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.childClosed:
			return
		case batch, ok := <-p.espIn:
			if !ok {
				return
			}
			if batch == nil {
				continue
			}

			out := make([]InboundPacket, 0, len(batch))
			for i, pkt := range batch {
				if p.stopped(ctx) {
					releaseInbound(out)
					releasePackets(batch[i:])
					return
				}
				if pkt == nil {
					continue
				}

				ip, err := p.processInbound(pkt)
				pkt.Release()
				if err != nil {
					// MVP tolerance: drop malformed ESP without killing
					// the tunnel. A per-packet debug hook can be wired
					// here later.
					continue
				}
				out = append(out, ip)
			}

			if len(out) == 0 {
				continue
			}
			select {
			case p.ipOut <- out:
			case <-ctx.Done():
				releaseInbound(out)
				return
			case <-p.childClosed:
				releaseInbound(out)
				return
			}
		}
	}
}

// stopped reports whether either worker stop signal has fired.
func (p *Pipeline) stopped(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	case <-p.childClosed:
		return true
	default:
		return false
	}
}

// processInbound keeps the per-packet logic separate so runInbound stays a
// thin loop; when a debug logger is wired into esp this is the natural
// boundary for one malformed-packet log line. The returned InboundPacket is
// owned by the caller on success; ProcessPooled recycles its plaintext on
// error, so there is nothing to release when err != nil.
// reportFatal forwards the first unrecoverable data-plane error to the
// public Session exactly once and detaches the outbound worker.
func (p *Pipeline) reportFatal(err error) {
	p.fatalOnce.Do(func() {
		if p.fatalOut != nil {
			select {
			case p.fatalOut <- err:
			default:
			}
		}
	})
}

func (p *Pipeline) processInbound(pkt *transport.Packet) (InboundPacket, error) {
	ip, release, err := p.inbound.ProcessPooled(pkt.Payload)
	if err != nil {
		return InboundPacket{}, err
	}
	return InboundPacket{IP: ip, release: release}, nil
}

// runOutbound pulls raw IP packets from the user queue in small groups,
// encrypts them in order and submits the resulting ESP frames into the
// shared transport write queue in the same order. Per-packet drops
// (empty/foreign IP versions) mirror the inbound tolerance.
func (p *Pipeline) runOutbound(ctx context.Context) {
	for {
		var first []byte
		select {
		case <-ctx.Done():
			return
		case <-p.childClosed:
			return
		case pkt, ok := <-p.ipIn:
			if !ok {
				return
			}
			if pkt == nil {
				continue
			}
			first = pkt
		}

		packets := make([][]byte, 0, txBatch+1)
		packets = append(packets, first)
		for i := 0; i < txBatch; i++ {
			select {
			case pkt, ok := <-p.ipIn:
				if !ok {
					goto encrypt
				}
				if pkt == nil {
					continue
				}
				packets = append(packets, pkt)
			default:
				goto encrypt
			}
		}

	encrypt:
		frames := make([]*transport.Frame, 0, len(packets))
		for _, pkt := range packets {
			datagram, release, err := p.outbound.process(pkt, true)
			if err != nil {
				if errors.Is(err, ErrSeqWrapped) {
					p.reportFatal(err)
					return
				}
				continue
			}

			frame := &transport.Frame{
				Kind:    transport.KindESP,
				Payload: datagram,
			}
			if release != nil {
				frame.SetRelease(release)
			}
			frames = append(frames, frame)
		}

		for i, frame := range frames {
			select {
			case p.tx <- frame:
			case <-ctx.Done():
				releaseFrames(frames[i:])
				return
			case <-p.childClosed:
				releaseFrames(frames[i:])
				return
			}
		}
	}
}

func releaseInbound(batch []InboundPacket) {
	for i := range batch {
		batch[i].Release()
	}
}

func releasePackets(batch []*transport.Packet) {
	for _, pkt := range batch {
		pkt.Release()
	}
}

func releaseFrames(frames []*transport.Frame) {
	for _, f := range frames {
		f.Release()
	}
}
