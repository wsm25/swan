// Package eap implements the EAP peer stack:
//
//   - eap.go: EAP packet codec, the Method interface, and the shared Config;
//   - worker.go: eap.Worker, a goroutine that owns one Method instance and
//     processes Round requests from a mailbox in order;
//   - methods/: method registry (peap / mschapv2) used by control;
//   - peap/: PEAPv0 peer (TLS tunnel + inner MSCHAPv2, fragmentation/ACK,
//     MS-AVP inner packet framing, uTLS engine over net.Pipe);
//   - mschapv2/: outer (non-PEAP) MSCHAPv2 peer method, MD4/DES based.
//
// # Concurrency and lifecycle
//
// The eap worker owns exactly one Method instance for the session and never
// runs two Rounds concurrently. Requests are processed in mailbox order.
// Pure methods run inline inside the worker. PEAP also runs its TLS engine
// because the TLS implementation drives a bidirectional record stream.
//
// The Method interface includes Close. eap.Worker calls Close as soon as the
// method reports ActionComplete, and control's private EAP worker calls it
// on every exit path (completion, failure, context cancellation, closed
// mailbox). PEAP's Close releases the TLS relay goroutine and pipe ends, and
// leaves the method terminal until the next Initialize.
//
// # Logging
//
// Human-friendly EAP debugging stays in the centralized formatters in
// swan/debug; this package carries raw bytes and leaves formatting to the
// layers above.
package eap
