// Package peap implements the PEAPv0 peer (EAP-PEAP) used by swan4:
//
//	phases: outer identity -> TLS tunnel -> inner MSCHAPv2 ->
//	        awaiting outer success/failure -> completed or failed
//
// # TLS engine
//
// tls.go runs a Go-mimicking uTLS client (utls.HelloGolang) bridged over
// net.Pipe. The engine pumps handshake/application records between the pipe
// and the EAP fragment buffers, so the PEAP layer sees TLS bytes as raw
// records and owns fragmentation/ACK. TLS 1.2 and TLS 1.3 are enabled. The
// EAP MSK comes from the TLS exporter; see ExportMSK and the tls.go comment
// for the exact TLS 1.2 / TLS 1.3 / strongSwan-compatible labels and
// lengths.
//
// # Fragmentation
//
// fragment.go implements the PEAP L/M/S flags, the optional 4-byte TLS
// length field, empty ACK packets, ACK pacing (one outbound fragment per
// server ACK), and bounded inbound reassembly.
//
// # Inner EAP
//
// avp.go frames inner EAP packets inside the tunnel the same way strongSwan
// does: tunneled requests without EAP headers are completed, Identity
// requests pass through, and server MS-AVP success/failure becomes
// synthetic inner Success/Failure packets. in peap.go the inner method is
// always MSCHAPv2 in this profile.
package peap
