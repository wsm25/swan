// Package eap implements the EAP peer stack of the MVP:
//
//   - eap.go: EAP packet codec, Method interface and shared Configuration;
//   - worker.go: the method FSM driver goroutine, fed by the control layer
//     through a mailbox channel; one Round per inbound EAP request;
//   - methods/: method registry (peap / mschapv2) used by control;
//   - peap/:   PEAPv0 peer (TLS tunnel + inner MSCHAPv2, fragmentation/ACK,
//     MS-AVP inner packet framing, TLS engine over crypto/tls);
//   - mschapv2/: outer (non-PEAP) MSCHAPv2 peer method, MD4/DES based.
//
// # Concurrency
//
// The eap worker owns exactly one Method instance for the session and never
// runs two Rounds concurrently: requests are processed in mailbox order.
// Pure methods (mschapv2) run inline; PEAP additionally runs its TLS engine
// worker because crypto/tls drives a bidirectional record stream.
//
// # Logging
//
// Human-friendly EAP debugging keeps to the centralized formatters in
// swan/debug; this package emits raw bytes and leaves formatting to layers
// above.
package eap
