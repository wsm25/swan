// Package swan is the public API of a userspace, initiator-only IKEv2
// (NAT-T) library.
//
// The caller injects an io.ReadWriteCloser that carries length-prefixed
// NAT-T datagrams and receives a Tunnel whose Read and Write carry one raw
// IP packet per call. The library never opens sockets and never owns a TUN
// device.
//
// # Layers
//
// The implementation is split into layers. The IO/state layers run a fixed
// set of workers connected by bounded channels; the syntax (github.com/wsm25/swan/wire) and
// crypto (github.com/wsm25/swan/xcrypto) packages run no goroutines of their own and execute
// inside whatever worker calls them.
//
//	github.com/wsm25/swan (public API)
//	  ├── .../control ── .../eap ── .../eap/{methods,peap,mschapv2}
//	  │        └─────── .../wire, .../xcrypto, .../transport, .../events
//	  ├── .../esp ───── .../xcrypto, .../transport
//	  └── .../debug ─── .../wire, .../transport, .../events
//
// # Worker topology (per session)
//
//	wire (io.ReadWriteCloser in)
//	  └─ transport.RxWorker ──ESP──► esp InboundWorker ──► Tunnel
//	                  └───────IKE──► control demux ─► handshake → running
//	handshake/running/esp OutboundWorker ─► transport.TxWorker ─► wire
//	eap.Worker (method FSM) and the PEAP TLS engine sit beside control.
//
// # Raw packet interface
//
// Tunnel.Read returns data from at most one decrypted IP packet per call;
// packets are never merged across reads. Tunnel.Write consumes one packet
// per call. Both calls copy bytes so the caller keeps ownership of its
// slices.
//
// # Events
//
// This package re-exports Event, EventStream, and Stage so the common
// cases need only the github.com/wsm25/swan import. Values returned by Tunnel.Assigned and
// Tunnel.ChildSA are named in github.com/wsm25/swan/control.
package swan
