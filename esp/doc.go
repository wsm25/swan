// Package esp implements the MVP data plane: ESP-only transport for raw IP
// packets plus replay protection.
//
// # Workers
//
//   - InboundWorker: consumes classified ESP datagrams from the transport
//     layer, verifies SPI + replay window, decrypts/authenticates, strips
//     padding and emits one raw IP packet per datagram to the Tunnel queue.
//   - OutboundWorker: consumes raw IP packets from the Tunnel, appends
//     ESP padding/trailer, encrypts with the negotiated keys and submits
//     UDP-encapsulated ESP frames to the shared transport writer queue.
//
// The two workers run independently and share only read-only state
// (selection, keys, SPIs); outbound seq lives on Outbound, replay window on
// Inbound: no lock on the hot path.
//
// Packet ownership: bytes sent to ipOut are owned by the receiver; bytes
// received from ipIn are consumed by the outbound worker (do not reuse).
package esp
