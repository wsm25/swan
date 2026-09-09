// Package transport adapts the injected stream wire into framed, classified
// NAT-T datagrams and hands them to the control and ESP layers.
//
// # Stream framing
//
// The wire is an io.ReadWriteCloser, a byte stream without datagram
// boundaries. The library defines this frame format:
//
//	frame   := <length: uint16 big-endian> <payload: length bytes>
//	payload := the exact bytes that would appear on a UDP socket:
//	           - NAT-T keepalive: 0xff
//	           - IKE:  4-byte non-ESP marker (all zero) followed by the IKE
//	                   message
//	           - ESP:  the raw ESP datagram (UDP-encapsulated, no marker)
//
// MaxFramePayload bounds a frame payload. The reader accumulates a stream
// until the declared length arrives; a truncated frame is
// io.ErrUnexpectedEOF and an oversized declared length is a decode error.
//
// # NAT-T classification
//
// Classify follows swan2's UDP classification: a single 0xff byte is
// keepalive, a leading four-byte all-zero marker is IKE (marker stripped
// before delivery), everything else is ESP. The logical local/peer port is
// always LogicalNatTPort (4500), regardless of the real backend port.
//
// # Workers and batching
//
//   - RxWorker: one blocking reader goroutine owns all read buffers.
//     Classified IKE packets are delivered to the ctl channel one at a
//     time. ESP packets are accumulated into batches of up to 32 and
//     flushed to the esp channel after 200us of quiet or when a batch is
//     full; the first packet after an idle gap goes out immediately as a
//     single-packet batch so low traffic keeps its latency. Keepalives are
//     consumed here and never delivered. Pooled packet buffers are returned
//     via (*Packet).Release.
//   - TxWorker: the single writer of the session. Every producer (control
//     handshake/running, ESP outbound) submits *Frame values; the worker
//     adds framing, applies the non-ESP marker for IKE, and coalesces up to
//     32 additional queued frames after the first into one stream Write
//     without reordering them.
//
// Only these two workers touch the wire. Close asks a worker to stop but
// never closes the injected stream; a fully blocking wire Read can only be
// unblocked by the caller closing the wire.
package transport
