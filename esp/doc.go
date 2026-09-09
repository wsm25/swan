// Package esp implements the MVP data plane: ESP-only transport for raw IP
// packets plus replay protection.
//
// # Workers
//
//   - InboundWorker: consumes batches of classified ESP datagrams from the
//     transport layer, verifies SPI + replay window, decrypts/authenticates,
//     strips padding and emits batches of raw IP packets to the Tunnel
//     queue. Datagrams inside a batch are processed strictly in order.
//   - OutboundWorker: consumes raw IP packets from the Tunnel, appends
//     ESP padding/trailer, encrypts with the negotiated keys and submits
//     UDP-encapsulated ESP frames to the shared transport writer queue in
//     order.
//
// The two workers run independently and share only read-only state
// (selection, keys, SPIs); outbound seq lives on Outbound, replay window on
// Inbound: no lock on the hot path.
//
// Packet ownership: ipOut delivers one []InboundPacket per batch; each
// InboundPacket in the batch is owned by the receiver, which must Release it
// after copying the bytes out of the pooled plaintext. Bytes received from
// ipIn are consumed by the outbound worker (do not reuse).
package esp
