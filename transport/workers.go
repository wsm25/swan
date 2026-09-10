package transport

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// Batching constants for the data plane. Control-plane deliveries stay
// single-frame: they are latency-sensitive and keep the existing
// one-frame-at-a-time channel behavior.
const (
	// rxBatch is the maximum number of ESP packets RxWorker accumulates
	// before delivering one slice to the esp pipeline.
	rxBatch = 32
	// rxBatchFlush bounds how long a partially filled ESP batch waits for
	// more packets before it is delivered.
	rxBatchFlush = 200 * time.Microsecond
	// writeBatch is how many frames TxWorker drains and hands to a
	// batchWriter in one call when the wire supports it.
	writeBatch = 32
)

// rxPoolBufSize is the pooled receive buffer class: MaxWireDatagram so
// one datagram Read can never run out of buffer for legal traffic.
const rxPoolBufSize = 1 << 16

// RxWorker owns all reads from the injected wire (io.ReadWriteCloser with
// datagram Read/Write semantics, same as *net.UDPConn). It classifies
// datagrams, strips the non-ESP marker from IKE and forwards each packet
// (with ownership transfer) to exactly one of:
//
//	ctl: control-plane IKE packets   (collected by the control demux worker)
//	esp: ENC/ESP datagrams           (collected by the esp inbound worker)
//
// Control packets are delivered singly as they arrive. ESP packets are
// delivered to esp in batches of up to rxBatch packets: a reader goroutine
// owns the blocking wire Read calls and feeds classified ESP packets to the
// Run loop, which flushes a batch either when it fills or after rxBatchFlush
// of quiescence. Keepalives are consumed (counted) here and never delivered.
// Pooled packet buffers return to the pool via (*Packet).Release; packets
// are delivered with a release hook attached, and partial batches are
// released (never delivered) when Run stops.
//
// Close is graceful: it never closes the underlying wire (the caller owns
// it). Run observes the requested close from its select loop, releases any
// partial ESP batch, and then waits for the reader goroutine to finish (the
// next time the wire read yields control). A fully non-returning Read can
// only be unblocked by closing the wire.
type RxWorker struct {
	wire io.Reader
	ctl  chan<- *Packet
	esp  chan<- []*Packet

	pool *sync.Pool

	keepalives uint64

	closed    chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// NewRxWorker binds the stream side of the wire and the two delivery
// channels. Channels must be bounded (backpressure) and are drained by
// control/esp workers.
func NewRxWorker(wire io.Reader, ctl chan<- *Packet, esp chan<- []*Packet) *RxWorker {
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

// Run blocks until Close or a read failure. It must never be called
// concurrently by two goroutines. A requested Close returns nil once the
// reader goroutine has exited; a stream EOF or IO error returns the read
// error.
func (w *RxWorker) Run() error {
	packets := make(chan *Packet)
	readErr := make(chan error, 1)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		w.read(packets, readErr)
	}()
	// Done keeps its historical meaning: Run has fully exited and the
	// reader goroutine has finished. Close still cannot interrupt a fully
	// blocking wire Read, so Run may wait for the next read yield exactly
	// like the pre-batch version; the partial ESP batch is released as
	// soon as Close is observed.
	defer func() {
		<-readerDone
		close(w.done)
	}()

	batch := make([]*Packet, 0, rxBatch)
	ticker := time.NewTicker(rxBatchFlush)
	defer ticker.Stop()
	// fastOK admits one immediate single-packet delivery after an idle
	// gap (pre-batch latency); the following arrivals coalesce again.
	fastOK := true

	for {
		select {
		case <-w.closed:
			w.releaseBatch(batch)
			return nil
		case err := <-readErr:
			w.releaseBatch(batch)
			if err == io.EOF && w.requestedClose() {
				return nil
			}
			return err
		case pkt := <-packets:
			if pkt == nil {
				continue
			}
			batch = append(batch, pkt)
			if len(batch) >= rxBatch {
				if !w.deliverBatch(batch) {
					w.releaseBatch(batch)
					return nil
				}
				// Ownership of the slice transferred to the receiver; start
				// a fresh backing array for the next batch.
				batch = make([]*Packet, 0, rxBatch)
				fastOK = true
			} else if fastOK {
				// Low-load fast path: the first packet after an idle gap
				// goes out immediately; sustained traffic coalesces until
				// a ticker flush or a full batch.
				if !w.deliverBatch(batch) {
					w.releaseBatch(batch)
					return nil
				}
				batch = make([]*Packet, 0, rxBatch)
				fastOK = false
			}
		case <-ticker.C:
			if len(batch) == 0 {
				continue
			}
			if !w.deliverBatch(batch) {
				w.releaseBatch(batch)
				return nil
			}
			batch = make([]*Packet, 0, rxBatch)
			fastOK = true
		}
	}
}

// read is the single reader goroutine. All blocking wire Read calls happen
// here so Run's select can keep flushing batches on the ticker. A wire
// implementing batchReader takes the batch path; both exit when Close is
// requested (observed before a read or after the read yields), when the
// wire ends, or when a read fails.
func (w *RxWorker) read(packets chan<- *Packet, readErr chan<- error) {
	if br, ok := w.wire.(batchReader); ok {
		w.readBatched(br, packets, readErr)
		return
	}
	for {
		if w.requestedClose() {
			return
		}
		buf := w.pool.Get().([]byte)
		n, err := w.wire.Read(buf)
		if err != nil {
			w.pool.Put(buf)
			if err == io.EOF && w.requestedClose() {
				return
			}
			select {
			case readErr <- err:
			case <-w.closed:
			}
			return
		}
		if !w.classifyAndDeliver(buf[:n], buf, packets) {
			return
		}
	}
}

// readBatched is the batchReader fast path: fill all pooled buffers with
// one ReadBatch call, classify each datagram in order, and reuse the single
// read path semantics for keepalives, ctl delivery, and the ESP batch
// pipeline.
func (w *RxWorker) readBatched(br batchReader, packets chan<- *Packet, readErr chan<- error) {
	bufs := make([][]byte, rxBatch)
	sizes := make([]int, rxBatch)
	// returnUnfilled hands back every slot from from on: slots the current
	// batch never filled AND slots skipped after a mid-batch abort.
	returnUnfilled := func(from int) {
		for j := from; j < len(bufs); j++ {
			if bufs[j] != nil {
				w.pool.Put(bufs[j])
				bufs[j] = nil
			}
		}
	}
	for {
		if w.requestedClose() {
			return
		}
		for i := range bufs {
			bufs[i] = w.pool.Get().([]byte)
		}
		n, err := br.ReadBatch(bufs, sizes)
		// recvmmsg-style semantics: datagrams [0,n) are valid even when an
		// error accompanies them. Classify them first, then surface err.
		for i := 0; i < n; i++ {
			backing := bufs[i]
			bufs[i] = nil // consumed below or released inside on close
			if !w.classifyAndDeliver(backing[:sizes[i]], backing, packets) {
				returnUnfilled(i + 1)
				return
			}
		}
		returnUnfilled(n)
		if err != nil {
			if err == io.EOF && w.requestedClose() {
				return
			}
			select {
			case readErr <- err:
			case <-w.closed:
			}
			return
		}
	}
}

// classifyAndDeliver runs the single-datagram pipeline: keepalives are
// consumed, IKE goes to ctl one at a time, ESP goes to the batch channel.
// It returns false once the worker is closed and the caller must stop.
func (w *RxWorker) classifyAndDeliver(payload, backing []byte, packets chan<- *Packet) bool {
	switch Classify(payload) {
	case KindKeepalive:
		w.keepalives++
		w.pool.Put(backing)
		return true
	case KindIKE:
		// Classify guarantees at least NonESPMarkerLen marker bytes.
		body := payload[NonESPMarkerLen:]
		pkt := &Packet{
			Kind:    KindIKE,
			Payload: body,
			release: func() { w.pool.Put(backing) },
		}
		if !w.deliver(w.ctl, pkt) {
			pkt.Release()
			return false
		}
		return true
	case KindESP:
		pkt := &Packet{
			Kind:    KindESP,
			Payload: payload,
			release: func() { w.pool.Put(backing) },
		}
		select {
		case packets <- pkt:
			return true
		case <-w.closed:
			pkt.Release()
			return false
		}
	default:
		w.pool.Put(backing)
		return true
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

func (w *RxWorker) deliverBatch(batch []*Packet) bool {
	select {
	case w.esp <- batch:
		return true
	case <-w.closed:
		return false
	}
}

// releaseBatch returns every packet of a batch to the pool.
func (w *RxWorker) releaseBatch(batch []*Packet) {
	for _, pkt := range batch {
		pkt.Release()
	}
}

// Close requests a stop and returns immediately. It is idempotent and never
// blocks on the wire; Run observes it the next time the stream Read yields
// control. Wait on Done for the reader's full exit.
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

// NewTxWorker binds the wire (datagram Write semantics) and the shared
// outbound queue. The queue must be bounded.
func NewTxWorker(wire io.Writer, frames <-chan *Frame) *TxWorker {
	return &TxWorker{
		wire:   wire,
		frames: frames,
		closed: make(chan struct{}),
		done:   make(chan struct{}),
	}
}

// Run writes frames until Close, a channel close, or a write failure.
// Every frame is one datagram Write; when the wire implements batchWriter
// the worker drains up to writeBatch frames per FIFO burst and hands them
// to WriteBatch as a list. On Close it drains the frames already queued one
// at a time (without blocking for more) and exits; producers stop sending
// after Close is called.
func (w *TxWorker) Run() error {
	defer close(w.done)

	bw, batched := w.wire.(batchWriter)

	for {
		select {
		case f, ok := <-w.frames:
			if !ok {
				return nil
			}
			if f == nil {
				continue
			}
			frames := make([]*Frame, 0, writeBatch+1)
			frames = append(frames, f)
			for i := 0; i < writeBatch; i++ {
				select {
				case f2, ok := <-w.frames:
					if !ok {
						goto write
					}
					if f2 == nil {
						continue
					}
					frames = append(frames, f2)
				default:
					goto write
				}
			}
		write:
			if batched {
				if err := w.writeBatch(frames, bw); err != nil {
					return err
				}
			} else {
				for _, frame := range frames {
					if err := w.writeFrame(frame); err != nil {
						return err
					}
				}
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

// writeFrame writes one shaped datagram and releases the frame. It is the
// Close-drain path and the per-frame fallback.
func (w *TxWorker) writeFrame(f *Frame) error {
	defer f.Release()

	body, err := shapedPayload(f)
	if err != nil {
		return err
	}
	return writeAll(w.wire, body)
}

// writeAll iterates until every byte is written.
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return fmt.Errorf("github.com/wsm25/swan/transport: invalid write count %d", n)
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

// writeBatch shapes a FIFO frame group, releases every frame exactly once
// (writes may legally be partial), and hands the datagrams to the wire's
// WriteBatch until all are accepted.
func (w *TxWorker) writeBatch(frames []*Frame, bw batchWriter) error {
	defer func() {
		for _, f := range frames {
			f.Release()
		}
	}()

	bodies := make([][]byte, 0, len(frames))
	for _, f := range frames {
		body, err := shapedPayload(f)
		if err != nil {
			return err
		}
		bodies = append(bodies, body)
	}
	written := 0
	for written < len(bodies) {
		n, err := bw.WriteBatch(bodies[written:])
		if n < 0 || n > len(bodies)-written {
			return fmt.Errorf("github.com/wsm25/swan/transport: invalid batch write count %d", n)
		}
		written += n
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// shapedPayload applies NAT-T framing per kind: keepalive is the single
// 0xff byte, IKE gets the 4-byte non-ESP marker, ESP passes through raw.
func shapedPayload(f *Frame) ([]byte, error) {
	switch f.Kind {
	case KindKeepalive:
		return []byte{0xff}, nil
	case KindIKE:
		total := NonESPMarkerLen + len(f.Payload)
		if total > MaxWireDatagram {
			return nil, fmt.Errorf("github.com/wsm25/swan/transport: ike frame payload %d exceeds limit %d", total, MaxWireDatagram)
		}
		body := make([]byte, total)
		copy(body[NonESPMarkerLen:], f.Payload)
		return body, nil
	default:
		body := f.Payload
		if len(body) > MaxWireDatagram {
			return nil, fmt.Errorf("github.com/wsm25/swan/transport: esp frame payload %d exceeds limit %d", len(body), MaxWireDatagram)
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
