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
//   - RxWorker: one blocking reader that owns the read buffers.
//     Classified packets are handed to the ctl and esp channels with
//     ownership transfer (consumer releases pooled buffers).
//   - TxWorker: the single writer of the session. All producers (control
//     handshake/running, esp outbound) submit *Frame values; the worker
//     adds framing and may apply the non-ESP marker for IKE.
//
// Only these two workers touch the wire.
package transport
