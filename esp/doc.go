// Package esp implements the ESP-only data plane: it encrypts raw IP
// packets outbound, decrypts UDP-encapsulated ESP inbound, and checks the
// replay window.
//
// # Workers
//
//   - InboundWorker: consumes batches of classified ESP datagrams from the
//     transport layer, filters by SPI, authenticates/decrypts, strips the
//     ESP padding/trailer, checks the replay window, and emits batches of
//     raw IP packets to the Tunnel queue. Datagrams inside a batch are
//     processed in order.
//   - OutboundWorker: consumes raw IP packets from the Tunnel, adds ESP
//     padding/trailer/IV, encrypts with the negotiated keys, and submits
//     UDP-encapsulated ESP frames to the shared transport writer queue in
//     order.
//
// Inbound and outbound run independently and share only read-only state
// (selection, keys, SPIs). The outbound sequence number lives on Outbound,
// the replay window on Inbound: no lock on the per-packet path.
//
// # Pooling
//
// Inbound decrypts into pooled plaintext. InboundPacket.IP aliases that
// pool memory; the receiver must call InboundPacket.Release exactly once
// after copying the bytes. Tunnel.Read does that for the public API.
// Outbound can allocate ESP datagrams from its own pool when driven by the
// pipeline; those frames carry a release hook for the transport writer.
//
// # Hard failures
//
// Malformed or foreign packets are dropped independently. One condition is
// fatal: outbound sequence wrap after 2^32-1 packets returns ErrSeqWrapped
// and the sender stops using the SA. The pipeline reports that error to the
// session, which emits Broken and shuts down.
package esp
