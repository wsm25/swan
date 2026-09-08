// Package peap implements the PEAPv0 peer (EAP-PEAP, RFC 5216 draft-final
// style), aligned with the strongSwan PEAP tls path:
//
//	phases: outer identity -> TLS tunnel -> inner MSCHAPv2 ->
//	        awaiting outer success/failure -> completed
//
// The TLS engine (tls.go) is a standard crypto/tls client bridged over
// net.Pipe: the engine pumps handshake/application records between the
// pipe and the EAP fragment buffers, so crypto/tls stays the single TLS
// implementation. TLS 1.2 and TLS 1.3 are enabled; the EAP MSK derives from
// the TLS exporter as strongSwan does (see ExportMSK).
//
// Fragmentation (fragment.go) implements the PEAP L/M/S flags, optional
// 4-byte TLS length field, empty ACK packets and bounded reassembly.
//
// avp.go frames inner EAP packets inside the tunnel exactly like
// strongSwan: inner requests without headers are completed, Identity
// requests pass through, and server MS-AVP success/failure is mapped to
// synthetic inner Success/Failure packets.
package peap
