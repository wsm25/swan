// Package swan is the public facade of a userspace, initiator-only IKEv2
// (NAT-T) library.
//
// # Layered architecture
//
// The implementation is split into layers; every IO/state layer runs a fixed
// set of workers connected by bounded channels. Message ownership is
// transferred with the send: a producer must not touch a value after handing
// it to a channel, and the consumer is responsible for returning any pooled
// buffer. Pure syntax (swan/wire) and crypto (swan/xcrypto) layers have no
// goroutines of their own; they execute inside the worker that calls them.
//
//	swan (facade)
//	  ├── swan/control  ── swan/eap ── swan/eap/{methods,peap,mschapv2}
//	  │        └──────── swan/wire, swan/xcrypto, swan/transport, swan/events
//	  ├── swan/esp ───── swan/xcrypto, swan/transport
//	  └── swan/debug ─── swan/wire, swan/transport, swan/events
//
// # Worker topology (per session)
//
//	wire (io.ReadWriteCloser in)
//	  └─ transport.RxWorker  ──ESP──► esp InboundWorker ──► Tunnel.Read
//	                    └─────IKE──► control demux ─► handshake → running
//	handshake/running/esp OutboundWorker ─► transport.TxWorker ─► wire
//	eap.Worker (method FSM) and peap.Engine (TLS bridge) sit beside control.
//
// # The raw interface
//
// The tunnel is exposed as io.ReadWriteCloser. Read never merges two
// decrypted IP packets into one call, and Write consumes one packet per call.
//
// # Aliases
//
// This package re-exports the small set of value types users need
// (Event, EventStream, AssignedConfig, ChildSA) so that a typical program
// only imports "swan".
package swan
