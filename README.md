# swan4

A userspace, initiator-only IKEv2 (NAT-T) client library, written in Go.
It never opens sockets and never owns a TUN device. The caller gives it an
`io.ReadWriteCloser` as the wire; the library runs the IKEv2 handshake over
that stream and returns an `io.ReadWriteCloser` that carries raw IP packets.

## Supported profile

- Initiator-only IKEv2 with NAT-T. The logical NAT-T/IKE port inside the
  protocol is always 4500. The real local UDP socket port may be anything;
  the destination UDP port stays 4500.
- Local auth is EAP-PEAP with inner MSCHAPv2. The EAP MSK is used for the
  IKEv2 AUTH payload.
- Responder auth is a signed public-key AUTH (RSA or ECDSA), normally with
  the responder identity set in `RightID` (for example `@stu.vpn.sjtu.edu.cn`).
- Windows RRAS IKEv2 servers express the tunnel's inner IPv6 endpoint as a
  link-local TSi (`fe80::IID`) while CP assigns the global `INTERNAL_IP6_ADDRESS`
  with the same interface identifier. Such a TSi is accepted (the CP global
  address is still used as the local traffic source); any other TSi/CP
  mismatch remains a hard failure.
- `AAAIdentity` is the PEAP/TLS server name. It may differ from `RightID`.
- CP-driven address and DNS assignment. `left=%config` /
  `leftsourceip=%config4,%config6` is the intended responder profile.
- `rightsendcert=never`: the initiator does not send its own certificate
  chain.
- IKE/ESP proposal strings such as `aes256gcm16-prfsha512-curve25519`.
  AES-GCM, AES-CCM, AES-CBC, HMAC-SHA1/SHA2-256/384/512, and X25519 are
  implemented.
- ESP transport for raw IP packets with replay protection.

## Wire contract

The injected wire is an `io.ReadWriteCloser` with datagram semantics, exactly
like a connected `*net.UDPConn`: one `Read` returns one complete datagram,
one `Write` sends one complete datagram. `payload` is exactly the bytes that
would appear in one UDP datagram after NAT-T framing:

- one `0xff` byte for a NAT-T keepalive (consumed inside the library);
- four zero bytes (non-ESP marker) followed by an IKE message;
- a raw ESP datagram (UDP-encapsulated, no marker).

Datagram backends (UDP) are already this contract; `NewPacketWire` adapts a
`net.PacketConn` when it does not implement `io.ReadWriteCloser` on its own.
Stream-based backends (TCP/TLS/pipes) must convert their own strip/packet
boundaries: `NewFramedWire` adapts a byte stream into this contract with a
private `[2-byte big-endian length][payload]` frame convention of its own
(that framing is not part of the swan wire; only stream adapters speak it).


## Packages

| package | what it does |
| --- | --- |
| `swan` | public API: `Config`, `Session`, `Tunnel`, events |
| `github.com/wsm25/swan/transport` | datagram NAT-T classification, batching workers |
| `github.com/wsm25/swan/wire` | IKEv2 header and payload encode/decode |
| `github.com/wsm25/swan/xcrypto` | DH, PRF, hashing, ciphers, x509, key scheduling |
| `github.com/wsm25/swan/control` | handshake state machine, retransmission, keepalives, close |
| `github.com/wsm25/swan/eap` + subpackages | EAP codec and worker, PEAP, MSCHAPv2 |
| `github.com/wsm25/swan/esp` | ESP encrypt/decrypt, padding, replay window |
| `github.com/wsm25/swan/events` | event hub for control-plane transitions |
| `github.com/wsm25/swan/debug` | human-readable packet/payload logging |

## Usage

This example uses the real API: `DefaultConfig` already sets
`EAP.Method = "peap"`, so the example only fills the identity, password,
and server name.

```go
package main

import (
	"context"
	"log"
	"net"

	swan "github.com/wsm25/swan"
)

func main() {
	conn, err := net.Dial("udp", "vpn.example:4500")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	// A connected UDP conn already has the wire's datagram semantics;
	// NewPacketWire is the bridge for PacketConn-only backends.
	wire := swan.NewPacketWire(conn.(net.PacketConn))

	cfg := swan.DefaultConfig(net.ParseIP("1.2.3.4"))
	ike, esp, err := swan.ParseStrongswanProposals(
		"aes256gcm16-prfsha512-curve25519",
		"aes256gcm16-prfsha512-curve25519",
	)
	if err != nil {
		log.Fatal(err)
	}
	cfg.IKEProposals = ike
	cfg.ESPProposals = esp
	cfg.IDI = "%config"
	cfg.RightID = "@vpn.example"
	cfg.AAAIdentity = "@radius.example"
	cfg.EAP.Identity = "user"
	cfg.EAP.Password = "pass"
	cfg.EAP.ServerName = "@radius.example"

	session, err := swan.NewSession(wire, &cfg)
	if err != nil {
		log.Fatal(err)
	}
	tunnel, err := session.Start(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer tunnel.Close() // CHILD_SA DELETE then IKE_SA DELETE, best effort

	buf := make([]byte, 65535)
	n, err := tunnel.Read(buf) // one raw IP packet
	if err != nil {
		log.Fatal(err)
	}
	if _, err := tunnel.Write(buf[:n]); err != nil { // one raw IP packet
		log.Fatal(err)
	}
}
```

## Behavior notes

- `Session.Start` blocks until the tunnel is established, the context is
  canceled, or the handshake fails. The `Start` context is also the session
  lifetime: canceling it later tears the running session down the same way
  `Session.Stop` does.
- `Session.Stop` is idempotent. When the tunnel is active it first marks the
  tunnel ended, then sends the DELETE sequence without waiting for replies
  (CHILD_SA DELETE, then IKE_SA DELETE), stops the workers, waits on the
  bounded queues, emits `Stopped`, closes `Session.Done`, and closes the
  event hub. It never closes the injected wire.
- `Session` emits `Broken` and tears down when the injected transport read
  or write worker fails while the session is running. A normal `Stop` does
  not emit `Broken`.
- A peer IKE_SA DELETE is answered, then the session shuts down cleanly
  without `Broken`.
- A peer CHILD_SA DELETE is answered, the ESP pipeline stops, and the
  tunnel surface ends: `Tunnel.Read` returns `io.EOF` after buffered packets
  drain and `Tunnel.Write` returns `io.ErrClosedPipe`, while the IKE SA and
  its keepalive cadence keep running.
- Idle keepalives: the running control plane sends an empty protected
  INFORMATIONAL on a `Timeouts.Keepalive` cadence (default 20 seconds),
  unless a request is already outstanding.
  An unanswered keepalive retransmits on the RTO ladder: it starts at
  `Timeouts.InitialRTO`, doubles on each retry up to `Timeouts.MaxRTO`, and
  after `Timeouts.MaxRetries` retransmits the session fails with `Broken`.
  Every accepted response resets the RTO back to `InitialRTO`.
- DNS from the CP reply is reported through `Tunnel.Assigned()` as
  `DNS4` and `DNS6`, alongside `InternalIPv4` and `InternalIPv6`.
  `Assigned().AddressExpirySeconds` is populated when the responder sends an
  `INTERNAL_ADDRESS_EXPIRY` attribute. Lease renewal runs at 80% of that
  value (INFORMATIONAL + CFG_REQUEST); a failed renewal retries and a hard
  expiry is treated as a session failure.
- Rekey:
  - initiator CHILD_SA rekey (soft lifetime, optional PFS KE, byte/packet
    thresholds, and an emergency near-wraparound trigger); during the
    handoff the old inbound SA still decrypts until the old CHILD_SA is
    deleted
  - initiator IKE_SA rekey (new SPI pair, fresh DH/nonces, SKEYSEED rederive)
    with message-id reset for the new IKE SA
  - peer-initiated CHILD_SA and IKE_SA rekeys are accepted (role flip for
    peer-initiated IKE rekey included)
- Event ordering on success is
  `Starting -> HandshakeStarted -> HandshakeCompleted -> ConfigAssigned -> Started`,
  with stage, EAP, and negotiated-algorithm events in between. Peer-pushed
  CFG_SET or renewal CFG_REPLY changes while running emit
  `AssignedUpdated` with the new snapshot. After a running session starts
  shutting down the terminal order is `Stopping -> Stopped`; fatal runtime
  failures emit `Broken` first. Emitting never blocks the protocol workers
  (see `github.com/wsm25/swan/events`).

## Limitations

- Simultaneous rekey collision (RFC 7296 2.8.1/2.8.2): the two in-flight
  exchange nonces are compared bytewise; the smaller nonce loses. When we
  lose we abandon our rekey and accept the peer's rekey; when we win (or
  the nonces are equal) we answer `TEMPORARY_FAILURE` and the peer
  concludes. A real on-wire collision was not observed in local tests;
  coverage for the decision paths is unit-level.
- The old inbound CHILD_SA context is dropped when the peer acknowledges the
  old child deletion (strongSwan sends it); there is no additional hard time
  bound if a peer stays silent after a rekey.
- `Rekey.IKE.Bytes` and `Rekey.IKE.Packets` are parsed but not enforced
  (IKE-side flow counters are not tracked); IKE rekey is time-driven.
  CHILD_SA byte/packet thresholds are enforced on the outbound path.
- The outbound ESP sequence number still stops at `2^32-1`; with the
  near-wraparound emergency rekey this should be unreachable in practice.
  Reaching it reports `swan/esp: ESP sequence number wrapped after 2^32-1
  packets` and the session converts it into `Broken` and shutdown.
- MOBIKE is not implemented and the IKE_AUTH request no longer advertises
  `MOBIKE_SUPPORTED`; address-change handling does not exist. Changing
  networks drains the keepalive ladder and ends the session as `Broken`.
- Dynamic configuration from the peer arrives as the lease-renewal
  CFG_REPLY (DNS, expiry and address may change) or as a peer-pushed
  CFG_SET, which the library applies and answers with CFG_ACK.
- Local pubkey AUTH is not exercised; local auth is EAP-PEAP only.
- The test path is the containerized strongSwan/FreeRADIUS setup in
  `tests/README.md`. The handshake and ping flow work against that
  responder; the code remains under test rather than a hardened production
  stack.
## License

MIT; see [LICENSE](LICENSE).
