// Package transport consumes the injected datagram wire (one NAT-T
// datagram per Read/Write), classifies payloads, and hands them to the
// control and ESP layers.
//
// # Wire contract
//
// The wire is an io.ReadWriteCloser with datagram semantics, exactly like a
// connected *net.UDPConn: one Read returns one complete datagram, one Write
// sends one complete datagram. The payload of a datagram is the exact bytes
// that would appear on a UDP socket:
//
//   - NAT-T keepalive: 0xff
//   - IKE:  4-byte non-ESP marker (all zero) followed by the IKE message
//   - ESP:  the raw ESP datagram (UDP-encapsulated, no marker)
//
// MaxWireDatagram bounds a legal payload. Stream-based backends are the
// caller's responsibility: swan.NewFramedWire converts a byte stream into
// this contract with a [2-byte length][payload] frame convention of its
// own (that framing is not part of the swan wire; only stream adapters
// speak it).
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
//     shapes payloads (non-ESP marker for IKE, 0xff keepalive) and sends
//     each as one datagram Write in FIFO order; wires implementing
//     batchWriter get up to 32 frames per WriteBatch call.
//
// Only these two workers touch the wire. Close asks a worker to stop but
// never closes the injected stream; a fully blocking wire Read can only be
// unblocked by the caller closing the wire.
package transport
