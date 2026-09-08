package transport

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// rxPoolBufSize is the pooled receive buffer class. Frames larger than this
// still work: ReadFrame allocates a bigger backing array on demand and the
// release hook recycles that larger array instead of the pool class.
const rxPoolBufSize = 4096

// RxWorker owns all reads from the injected stream wire. It accumulates
// frames, classifies payloads, strips the non-ESP marker from IKE and
// forwards each packet (with ownership transfer) to exactly one of:
//
//	ctl: control-plane IKE packets   (collected by the control demux worker)
//	esp: ENC/ESP datagrams           (collected by the esp inbound worker)
//
// Keepalives are consumed (counted) here and never delivered. Pooled packet
// buffers return to the pool via (*Packet).Release; packets are delivered
// with a release hook attached.
//
// Close is graceful: it never closes the underlying wire (the caller owns
// it). It stops the loop whenever the wire next yields control. Blocking
// reads are therefore expected to be deadline-managed by the injected
// stream; a fully non-returning Read cannot be unblocked without closing
// the wire.
type RxWorker struct {
	wire io.Reader
	ctl  chan<- *Packet
	esp  chan<- *Packet

	pool *sync.Pool

	keepalives uint64

	closed    chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// NewRxWorker binds the stream side of the wire and the two delivery
// channels. Channels must be bounded (backpressure) and are drained by
// control/esp workers.
func NewRxWorker(wire io.Reader, ctl, esp chan<- *Packet) *RxWorker {
	w := &RxWorker{
		wire:   wire,
		ctl:    ctl,
		esp:    esp,
		closed: make(chan struct{}),
		done:   make(chan struct{}),
	}
	w.pool = &sync.Pool{New: func() any { return make([]byte, rxPoolBufSize) }}
	return w
}

// Run blocks on the wire until Close or a read failure. It must never be
// called concurrently by two goroutines. A requested Close returns nil; a
// stream EOF or IO error returns the read error.
func (w *RxWorker) Run() error {
	defer close(w.done)

	for {
		if w.requestedClose() {
			return nil
		}

		buf := w.pool.Get().([]byte)
		frame, err := ReadFrame(w.wire, buf)
		if err != nil {
			w.pool.Put(buf)
			if err == io.EOF && w.requestedClose() {
				return nil
			}
			return err
		}

		// frame.Payload aliases buf when it fitted the pool class, or a
		// fresh larger array otherwise. Reconstruct the full backing slice
		// before any marker stripping so Release returns the whole buffer.
		backing := frame.Payload[:cap(frame.Payload)]

		switch frame.Kind {
		case KindKeepalive:
			w.keepalives++
			w.pool.Put(backing)
			continue
		case KindIKE:
			// Classify guarantees at least NonESPMarkerLen marker bytes.
			payload := frame.Payload[NonESPMarkerLen:]
			pkt := &Packet{
				Kind:    KindIKE,
				Payload: payload,
				release: func() { w.pool.Put(backing) },
			}
			if !w.deliver(w.ctl, pkt) {
				pkt.Release()
				return nil
			}
		case KindESP:
			pkt := &Packet{
				Kind:    KindESP,
				Payload: frame.Payload,
				release: func() { w.pool.Put(backing) },
			}
			if !w.deliver(w.esp, pkt) {
				pkt.Release()
				return nil
			}
		}
	}
}

func (w *RxWorker) requestedClose() bool {
	select {
	case <-w.closed:
		return true
	default:
		return false
	}
}

func (w *RxWorker) deliver(ch chan<- *Packet, pkt *Packet) bool {
	select {
	case ch <- pkt:
		return true
	case <-w.closed:
		return false
	}
}

// Close requests a stop and returns immediately. It is idempotent and never
// blocks on the wire; Run observes it the next time the stream Read yields
// control. Wait on Done for full exit.
func (w *RxWorker) Close() error {
	w.closeOnce.Do(func() { close(w.closed) })
	return nil
}

// Done is closed when Run has fully exited.
func (w *RxWorker) Done() <-chan struct{} {
	return w.done
}

// TxWorker is the single writer of the injected stream wire. Control-plane
// frames (handshake requests, retransmits, keepalive INFORMATIONALs,
// DELETEs) and the esp outbound worker all submit *Frame values on the
// frames channel; serializing them here removes any need for write-side
// locking on the underlying io.WriteCloser.
type TxWorker struct {
	wire io.Writer
	// frames receives outbound frames; ownership of each Frame (including
	// the backing payload) transfers to the worker at send time.
	frames <-chan *Frame

	closed    chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// NewTxWorker binds the stream side of the wire and the shared outbound
// queue. The queue must be bounded.
func NewTxWorker(wire io.Writer, frames <-chan *Frame) *TxWorker {
	return &TxWorker{
		wire:   wire,
		frames: frames,
		closed: make(chan struct{}),
		done:   make(chan struct{}),
	}
}

// Run writes each frame until Close, a channel close, or a write failure.
// On Close it drains the frames already queued (without blocking for more)
// and exits; producers stop sending after Close is called.
func (w *TxWorker) Run() error {
	defer close(w.done)

	for {
		select {
		case f, ok := <-w.frames:
			if !ok {
				return nil
			}
			if f == nil {
				continue
			}
			if err := w.writeFrame(f); err != nil {
				return err
			}
		case <-w.closed:
			for {
				select {
				case f, ok := <-w.frames:
					if !ok {
						return nil
					}
					if f == nil {
						continue
					}
					if err := w.writeFrame(f); err != nil {
						return err
					}
				default:
					return nil
				}
			}
		}
	}
}

func (w *TxWorker) writeFrame(f *Frame) error {
	body, err := shapedPayload(f)
	if err != nil {
		return err
	}
	buf := make([]byte, FrameHeaderSize+len(body))
	binary.BigEndian.PutUint16(buf[:FrameHeaderSize], uint16(len(body)))
	copy(buf[FrameHeaderSize:], body)
	return writeAll(w.wire, buf)
}

// shapedPayload applies NAT-T framing per kind: keepalive is the single
// 0xff byte, IKE gets the 4-byte non-ESP marker, ESP passes through raw.
func shapedPayload(f *Frame) ([]byte, error) {
	switch f.Kind {
	case KindKeepalive:
		return []byte{0xff}, nil
	case KindIKE:
		total := NonESPMarkerLen + len(f.Payload)
		if total > MaxFramePayload {
			return nil, fmt.Errorf("swan/transport: ike frame payload %d exceeds limit %d", total, MaxFramePayload)
		}
		body := make([]byte, total)
		copy(body[NonESPMarkerLen:], f.Payload)
		return body, nil
	default:
		body := f.Payload
		if len(body) > MaxFramePayload {
			return nil, fmt.Errorf("swan/transport: esp frame payload %d exceeds limit %d", len(body), MaxFramePayload)
		}
		return body, nil
	}
}

// Close requests a stop and returns immediately. The worker exits at the
// next queue observation; wait on Done for full exit.
func (w *TxWorker) Close() error {
	w.closeOnce.Do(func() { close(w.closed) })
	return nil
}

// Done is closed when Run has fully exited.
func (w *TxWorker) Done() <-chan struct{} {
	return w.done
}
