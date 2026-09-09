// Package control owns the IKEv2 control plane as a small actor system.
//
// # Workers
//
//   - demux (started by Control.Run): reads every classified IKE packet from
//     the transport layer and routes it to one fixed control mailbox. During
//     the handshake the owner of that mailbox is the Handshake worker; after
//     the handshake it is the Running worker. The mailbox does not move, so
//     no packet can be observed by two workers or stranded by a handoff.
//   - Handshake worker: the linear initiator flow
//     IKE_SA_INIT (COOKIE/INVALID_KE retries) -> IKE key derivation ->
//     bootstrap IKE_AUTH -> EAP loop -> final IKE_AUTH/CHILD_SA -> handoff
//     to Running.
//   - Running worker: post-handshake keepalives and long-run policy. It sends
//     an empty protected INFORMATIONAL every 20s (skipped while a request is
//     outstanding), retransmits it on an RTO ladder that doubles up to
//     MaxRTO, and resets the ladder to InitialRTO on every accepted
//     response. It rejects cleartext packets, replays the last 4 cached
//     responses for duplicate peer requests, answers IKE/ESP DELETEs, and
//     refuses CREATE_CHILD_SA with NO_ADDITIONAL_SAS.
//
// Message-id allocation, retransmission, and duplicate/stale classification
// live in the exchange helpers in this package and mirror swan2's routine
// behavior.
//
// # Ownership
//
// State has exactly one owner at a time: Handshake during the handshake,
// Running afterwards, then the close path after Running has exited. Only
// the current owner mutates State.
//
// # Channels
//
//	in  <-chan *transport.Packet  (IKE packets; ownership moves to control)
//	tx  chan<- *transport.Frame   (built IKE packets, retransmits, DELETEs;
//	                               control submits IKE frames only)
//	est chan<- *Established       (handshake result delivered once)
//
// The control plane never touches the injected wire directly.
package control
