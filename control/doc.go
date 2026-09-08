// Package control owns the IKEv2 control plane as a small actor system.
//
// # Workers
//
//   - demux (assembled in Control.Run): reads every classified IKE packet
//     from the transport layer and routes it to the current SA owner. During
//     the handshake the owner is the Handshake worker; after the handshake
//     handoff it is the Running worker. The switch is a single atomic point,
//     so no packet can be observed by two workers.
//   - Handshake worker: the strictly linear initiator flow
//     IKE_SA_INIT (COOKIE/INVALID_KE retries) -> IKE key derivation ->
//     bootstrap IKE_AUTH -> EAP loop (via swan/eap worker) ->
//     final IKE_AUTH/CHILD_SA -> handoff to Running.
//   - Running worker: 20s keepalive INFORMATIONALs (skipped while a request
//     is outstanding), inbound DELETE processing and duplicate-response
//     replay history (last 4), and the graceful close sequence
//     CHILD_SA DELETE -> IKE_SA DELETE.
//
// Message-id, retransmission (initial RTO *2, capped attempts) and
// duplicate/stale classification are implemented by the exchange helpers in
// this package and mirror swan2's routine semantics.
//
// # Channels
//
//	in  <-chan *transport.Packet  (IKE packets, ownership transferred)
//	tx  chan<- *transport.Frame   (built IKE packets/retransmits/ESP-0? no:
//	                               control submits IKE frames only)
//	est chan<- *Established       (handshake result delivered once)
//
// The control plane never touches the injected wire directly.
package control
