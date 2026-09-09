// Package transport adapts the injected stream wire into framed, classified
// NAT-T datagrams and hands them to the control and ESP layers.
//
// # Stream framing
//
// The wire is an io.ReadWriteCloser, i.e. a byte stream without datagram
// boundaries. The library defines the frame format:
//
//	frame   := <length: uint16 big-endian> <payload: length bytes>
//	payload := the exact bytes that would appear on a UDP socket, i.e.:
//	           - NAT-T keepalive: 0xff
//	           - IKE:  4-byte non-ESP marker (all zero) followed by the IKE message
//	           - ESP:  the raw ESP datagram (UDP-encapsulated, no marker)
//
// MaxFramePayload bounds a frame payload. The reader must stream-accumulate
// until the declared length arrives; partial or oversized frames are decode
// errors.
//
// # NAT-T classification
//
// Classify mirrors swan2's udp classification exactly: keepalive, IKE
// (marker stripped before delivery), ESP. The local/peer logical port is
// always LogicalNatTPort (4500) regardless of any real backend port.
//
// # Workers
//
//   - RxWorker: one blocking reader goroutine that owns the read buffers.
//     Classified ctl packets are handed to the ctl channel singly; ESP
//     packets are accumulated into batches and handed to the esp channel
//     as one slice per batch. Ownership transfers to the consumer
//     (consumer releases pooled buffers).
//   - TxWorker: the single writer of the session. All producers (control
//     handshake/running, esp outbound) submit *Frame values; the worker
//     adds framing, may apply the non-ESP marker for IKE, and coalesces
//     consecutive queued frames into one stream Write while preserving
//     FIFO order.
//
// Only these two workers touch the wire.
package transport
