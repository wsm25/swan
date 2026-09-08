# swan4 integration tests

A small self-contained harness to run swan4 against a **real strongSwan
server container**. The library itself stays backend-free: the UDP socket and
the stream framing needed for the injected `io.ReadWriteCloser` live only in
this test client.

## Layout

```
tests/
├── docker/           all-in-one e2e responder (Debian strongSwan + FreeRADIUS)
│   ├── Dockerfile           strongSwan (GCM/AESNI/OpenSSL plugins) + radiusd
│   ├── entrypoint.sh        radiusd in background, charon in foreground
│   ├── ipsec.conf           MVP profile: aes256gcm16-prfsha512-curve25519, eap-radius
│   ├── ipsec.secrets        RSA server key
│   ├── strongswan.conf      charon config (debug levels, eap-radius 127.0.0.1)
│   ├── gen-certs.sh         one-shot CA + server cert generation (openssl)
│   └── freeradius/raddb/    FreeRADIUS eap-peap/mschapv2 configs
└── client/           Go debug client (real UDP + NAT-T framing + swan import)
    ├── go.mod            module swan4-tests (replace swan => ../..)
    └── main.go           handshake runner + ICMP echo responder
```

The server profile intentionally mirrors the fixed swan4 MVP deployment so a
client config close to the production one works unchanged:

| knob | value |
| --- | --- |
| IKE/ESP | `aes256gcm16-prfsha512-curve25519` |
| responder auth | `leftauth=pubkey`, `leftid=@stu.vpn.sjtu.edu.cn`, sends cert |
| initiator auth | `rightauth=eap-peap` (inner MSCHAPv2) |
| PEAP TLS server identity | `radius.net.sjtu.edu.cn` (in the server cert SAN) |
| CP | `rightsourceip=10.31.0.0/24` (INTERNAL_IP4_ADDRESS) |
| ports | 500/udp + 4500/udp, NAT-T framing |

## 1) Start the responder (single container)

```bash
cd tests/docker
./gen-certs.sh                     # writes certs/{caCert,serverCert,serverKey}.pem
podman build -t swan4-e2e .
podman run --rm --name swan4-ss --cap-add NET_ADMIN --cap-add NET_RAW \
  -p 4500:4500/udp swan4-e2e
```

The Debian-based image ships the GCM/AESNI/OpenSSL strongSwan plugins, so the
local responder negotiates the production MVP cipher profile
(`aes256gcm16-prfsha512-curve25519`). charon forwards inner EAP to the
built-in FreeRADIUS on `127.0.0.1:1812` (secret `radius.rocks`); OpenSSL's
TLS stack negotiates EMS on TLS 1.2, which the standard `crypto/tls`
exporter needs to derive the RFC 5216 EAP MSK.

`NET_ADMIN` lets charon install the negotiated CHILD_SA (xfrm) in the
container namespace; `NET_RAW` lets `ping` exercise the ESP data plane.

## 2) Run the Go debug client

The client owns a real UDP socket and wraps datagrams into the swan stream
framing (`[u16 len][payload]`) before handing the `io.ReadWriteCloser` to the
library:

```bash
cd tests/client
SSL_CERT_FILE=../docker/certs/caCert.pem \
  go run . -server 127.0.0.1:4500
```

Extra flags: `-eap-user`, `-eap-pass`, `-event-log` (log IKE/EAP events to
stderr). Successful output shows the negotiated algorithms, assigned
internal address and the live ESP packet flow:

```
event: Starting
event: HandshakeStarted
...
negotiated: ike aes256gcm16 aes256gcm16(-) prfsha512 curve25519
tunnel up: internal_ipv4=10.31.0.1 dns4=...
```

## 3) ESP data-plane ping test

With the client running, ping the assigned virtual IP from inside the
strongSwan container:

```bash
podman exec swan4-ss ping -c 3 10.31.0.1
```

The debug client answers IPv4 ICMP Echo Requests through the tunnel
(ESP decrypt -> raw IP -> Echo Reply -> ESP encrypt), so `0% packet loss`
proves both data-plane directions, the replay window and the padding path
end to end. The responder container runs with `NET_ADMIN` (xfrm install)
and `NET_RAW` (ping socket).

## Debug notes

- `SSL_CERT_FILE` must point at the generated test CA **before** the process
  starts (Go's `x509.SystemCertPool` honors it at load time) — otherwise PEAP
  and responder-cert chain verification reject the self-signed test chain.
- charon logs to stdout (`charondebug` value in `strongswan.conf`); raise the
  level to `ike 4, enc 4, net 4` when diffing against swan4's debug logs
  (`swan/debug` renders the IKE/EAP payload chain in the same protocol shape).
- FreeRADIUS logs to `/var/log/freeradius.log` inside the container
  (`podman exec swan4-ss tail -f /var/log/freeradius.log`).
- `podman exec swan4-ss radtest testuser testpassword 127.0.0.1 10 radius.rocks`
  verifies credentials without IKE.