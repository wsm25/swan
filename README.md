# swan

A userspace IKEv2 client (initiator only), written in Go. It does not open
sockets and does not know about TUN devices: you hand it an
`io.ReadWriteCloser` as the wire, it runs the IKEv2 handshake over that
stream, and it hands you back an `io.ReadWriteCloser` that carries raw IP
packets.

## What it supports

- Initiator-only IKEv2 with NAT-T (logical port 4500)
- Client auth: EAP-PEAP with inner MSCHAPv2 (RFC 5216 MSK incl. legacy
  TLS 1.2 servers without Extended Master Secret)
- Responder auth: certificates (RSA/ECDSA signatures, chain + identity checks)
- CP-based address and DNS assignment
- CHILD_SA negotiation and an ESP data plane with replay protection
- Algorithms: AES-GCM, AES-CCM, AES-CBC; HMAC-SHA1/SHA2-256/384/512;
  X25519
- Graceful close (CHILD_SA DELETE, then IKE_SA DELETE)

## Packages

```
swan            public facade: Config, Session, Tunnel, events
swan/transport  stream framing ([u16 len][payload]) + NAT-T classification
swan/wire       IKEv2 header and payload encoding/decoding
swan/xcrypto    primitives: DH, PRF, ciphers, x509, key scheduling
swan/control    handshake state machine, retransmission, keepalives, close
swan/eap        EAP, PEAP, MSCHAPv2
swan/esp        ESP encrypt/decrypt and replay window
swan/events     deterministic event hub (slow subscribers tolerated)
swan/debug      human-readable packet/payload logging
```

## Usage

```go
wire, _ := net.Dial("udp", "vpn.example:4500") // any io.ReadWriteCloser

cfg := swan.DefaultConfig(net.ParseIP("1.2.3.4"))
ike, esp, _ := swan.ParseStrongswanProposals(
    "aes256gcm16-prfsha512-curve25519",
    "aes256gcm16-prfsha512-curve25519",
)
cfg.IKEProposals, cfg.ESPProposals = ike, esp
cfg.IDI = "%config"
cfg.RightID = "@vpn.example"
cfg.EAP = eap.Config{
    Method:     "peap",
    Identity:   "user",
    Password:   "pass",
    ServerName: "radius.example",
}

session, err := swan.NewSession(wire, &cfg)
tunnel, err := session.Start(context.Background())

buf := make([]byte, 65535)
n, _ := tunnel.Read(buf)  // one raw IP packet
tunnel.Write(pkt)         // one raw IP packet
tunnel.Close()            // IKE DELETE exchange
```

Wire contract: the injected stream carries frames of `[2-byte big-endian
length][payload]`, where the payload is exactly the bytes that would appear
on a UDP socket (NAT-T non-ESP marker + IKE, raw ESP, or a 0xff keepalive).

## Tests

`tests/` contains a Podman/Docker responder (Debian strongSwan with GCM
plugins + FreeRADIUS doing EAP-PEAP) and a debug client with a real UDP
adapter. It runs the full handshake, then pings the assigned IP through the
ESP tunnel. See `tests/README.md`.