# swan4 integration tests

A small self-contained harness that runs swan4 against a real strongSwan
server container. The library itself stays backend-free: the UDP socket and
the stream framing for the injected `io.ReadWriteCloser` live only in the
test clients under `tests/client`.

## Layout

```text
tests/
├── docker/           all-in-one E2E responder (Debian strongSwan + FreeRADIUS)
│   ├── Dockerfile           strongSwan (GCM/AESNI/OpenSSL plugins) + radiusd
│   ├── entrypoint.sh        radiusd in background, charon in foreground
│   ├── ipsec.conf           aes256gcm16-prfsha512-curve25519, eap-radius
│   ├── ipsec.secrets        RSA server key
│   ├── strongswan.conf      charon config, attr plugin DNS fixture
│   ├── gen-certs.sh         one-shot CA + server cert generation (openssl)
│   └── freeradius/raddb/    FreeRADIUS eap-peap/mschapv2 configs
├── udpsink/          responder-side UDP benchmark counter/pump (Go)
└── client/           Go debug client and tunnel benchmarks
    ├── go.mod            module swan4-tests (replace swan => ../..)
    ├── wiretest/         UDP socket -> swan stream framing adapter
    ├── main.go           handshake runner + ICMP echo responder (debug client)
    └── udpbench/         ESP tunnel UDP throughput benchmark
```

The server profile intentionally mirrors the fixed swan4 deployment:

| knob | value |
| --- | --- |
| IKE/ESP | `aes256gcm16-prfsha512-curve25519` |
| responder auth | `leftauth=pubkey`, `leftid=@stu.vpn.sjtu.edu.cn`, sends cert |
| initiator auth | `rightauth=eap-peap` (inner MSCHAPv2) |
| PEAP TLS server identity | `radius.net.sjtu.edu.cn` (in the server cert SAN) |
| CP | `rightsourceip=10.31.0.0/24` (INTERNAL_IP4_ADDRESS) |
| ports | 500/udp exposed, 4500/udp published; NAT-T framing on 4500 |

## Prereqs

- Podman (rootless works).
- Go 1.24 or newer (the test module and root module both request Go 1.24).

## 1) Build and start the responder

```bash
cd tests/docker
./gen-certs.sh                     # writes certs/{caCert,serverCert,serverKey}.pem
podman build -t localhost/swan4-e2e .
podman run --rm --name swan4-ss --cap-add NET_ADMIN --cap-add NET_RAW \
  -p 4500:4500/udp localhost/swan4-e2e
```

This shape is the one that works in this environment: rootless Podman, no
host networking, the container is named `swan4-ss`, and the image is
`localhost/swan4-e2e`. `NET_ADMIN` lets charon install the negotiated xfrm
CHILD_SA in the container namespace; `NET_RAW` lets `ping` exercise the ESP
data plane.

The Debian image ships the GCM/AESNI/OpenSSL strongSwan plugins, so the
local responder negotiates `aes256gcm16-prfsha512-curve25519`. charon
forwards inner EAP to the built-in FreeRADIUS on `127.0.0.1:1812` (secret
`radius.rocks`).

FreeRADIUS credentials are `testuser` / `testpassword`. The test CA and
server cert are written under `tests/docker/certs` by `gen-certs.sh`.
The client must trust that CA:

```bash
SSL_CERT_FILE=../docker/certs/caCert.pem
```

## 2) Run the Go debug client

The debug client owns a real UDP socket and wraps datagrams into the swan
stream framing (`[u16 len][payload]`) before handing the
`io.ReadWriteCloser` to the library:

```bash
cd tests/client
SSL_CERT_FILE=../docker/certs/caCert.pem \
  go run . -server 127.0.0.1:4500 -event-log=false
```

Extra flags: `-eap-user`, `-eap-pass`, `-event-log`, `-hex-dump`,
`-ike-spec`, `-esp-spec`. Rekey lives at test scale via
`-ike-lifetime` and `-child-lifetime` (for example `-child-lifetime=8s`
forces many CHILD_SA rekeys per minute: the responder charon log shows the
corresponding CREATE_CHILD_SA/delete rotation and pings keep succeeding
across each rekey). With `-event-log=false` the client prints only the
handshake result plus the assigned address:

```text
tunnel up: ipv4=10.31.0.1 ipv6=<nil> dns4=[9.9.9.9 8.8.4.4] dns6=[]
```

The `strongswan.conf` attr plugin supplies the DNS fixture
`dns = 9.9.9.9, 8.8.4.4` for any IKE_AUTH that requests
INTERNAL_IP4_DNS.

To test peer-initiated rekey acceptance, temporarily add
`keylife=15s` + `rekeyfuzz=0%` to the `swan4test` connection in
`tests/docker/ipsec.conf`, copy it into the container, and `podman restart
swan4-ss` (never `ipsec restart` inside the container: charon is PID 1).
The client accepts the inbound CREATE_CHILD_SA rekeys and keeps pinging.
Restore the committed config afterwards.

## 3) ESP data-plane ping test

With the client running, ping the assigned virtual IP from inside the
strongSwan container:

```bash
podman exec swan4-ss ping -c 3 10.31.0.1
```

The debug client answers IPv4 ICMP Echo Requests through the tunnel
(ESP decrypt -> raw IP -> Echo Reply -> ESP encrypt), so `0% packet loss`
shows both data-plane directions, the replay window, and the padding path
end to end.

## 4) UDP throughput tools

There are two small benchmark programs that share a private UDP packet
format:

```text
DATA: [u32 "SWAN"][u32 seq][zeros to -size]
END:  [u32 "ENDS"][u32 count]
STAT: [u32 "STAT"][u32 packets][u64 bytes][u32 gaps][u32 maxseq]
```

`-size` is the UDP payload size (minimum 12). The real tunnel packets are
slightly larger because they include IPv4/UDP headers and ESP overhead.

### tests/udpsink (runs inside the responder container)

Build it once, copy it into the running container, and start it:

```bash
cd tests/udpsink
go build -o udpsink .
podman cp udpsink swan4-ss:/udpsink

# count DATA packets coming from the client (upstream)
podman exec swan4-ss /udpsink -mode up -size 1400

# or pump DATA packets toward the client tunnel (downstream)
podman exec swan4-ss /udpsink -mode down -dst 10.31.0.1:55555 \
  -size 1400 -rate 0 -dur 30s
```

udpsink flags:

- `-mode` `up` (bind and count) or `down` (pump).
  Default `up`.
- `-port` UDP port for up mode. Default `55555`.
- `-dst` destination `host:port` for down mode. Default `10.31.0.1:55555`.
- `-size` DATA payload size. Default `1400`, minimum 12.
- `-dur` pump duration for down mode. Default `30s`, capped at `60s`.
- `-rate` target DATA packets/sec for down mode. Default `180000`;
  `0` pumps as fast as the socket allows.

In `up` mode it counts until it receives an END packet or gets
SIGINT/SIGTERM; it then drains in-flight DATA for 500 ms and sends the
STAT reply three times. In `down` mode it pumps DATA for `-dur` and then
sends STAT three times with its own sent counters.

Cleanup:

```bash
podman exec swan4-ss pgrep -f /udpsink
podman exec swan4-ss pkill -f /udpsink || true
```

### tests/client/udpbench (runs on the host, drives the tunnel)

```bash
cd tests/client
SSL_CERT_FILE=../docker/certs/caCert.pem \
  go run ./udpbench -mode up -size 1400 -rate 180000 -cpuprofile cpu-up.prof
```

Flags:

- `-mode` `up` (client pumps raw IPv4/UDP into the tunnel) or `down`
  (client counts tunneled UDP from the responder). Default `up`.
- `-server` strongSwan address. Default `127.0.0.1:4500`.
- `-peer` inner destination IP for upstream DATA. Default `10.12.23.50`.
- `-size` UDP payload size. Default `1400`, minimum 12.
- `-dur` measurement duration. Default `30s`, capped at `10m`.
- `-port` benchmark UDP destination port. Default `55555`.
- `-writers` concurrent pump goroutines in up mode. Default `2`.
- `-rate` target DATA packets/sec in up mode. Default `180000`;
  `0` pumps as fast as possible.
- `-cpuprofile` write a CPU profile to this path.
- `-memprofile` write a heap profile to this path.
- `-eap-user` / `-eap-pass` EAP credentials (defaults match FreeRADIUS).
- `-event-log`, `-hex-dump`, `-ike-spec`, `-esp-spec`.

Typical results in this environment:

- Upstream at `-size 1400 -rate 180000` reaches roughly **170k pps** and
  **~2 Gbit/s** through the tunnel.
- The responder-side socket wall in `udpsink -mode up` is roughly
  **208k pps** when the client pumps unpaced (`-rate 0`). The tunnel path
  and the client usually cap below that, so loss is expected there.
- These numbers depend on the host, the container limits, and the
  client/responder CPU; treat them as a local baseline, not a guarantee.

### Reading STAT/loss numbers

`udpsink -mode up` prints:

```text
STAT up pkts=<received DATA> bytes=<sum of UDP payload sizes> gaps=<sequence anomalies> maxseq=<highest seq>
```

`udpbench -mode up` prints how many packets it sent, then the STAT echo and
a computed loss percentage:

```text
up sent=... bytes=... pps=... mbps=...
up stat pkts=... bytes=... gaps=... maxseq=... loss=...%
```

- `pkts` from the sink is the number of DATA datagrams the sink counted.
- `gaps` is a sequence-anomaly counter: a datagram whose sequence is less
  than or equal to `maxseq`, or (after the first datagram) jumps forward by
  more than one. It detects reordering/duplicates and large drops, but it
  is not a precise 1:1 loss counter.
- The `loss` percentage is `(sent - received) / sent`, clamped so a
  duplicated or duplicated STAT count cannot show negative loss.
- In `down` mode the roles swap: `udpsink` sends and reports its own
  counters, `udpbench` reports what it received and computes
  `(sender pkts - received) / sender pkts`, clamped to 0.

## Container sysctl limitation

This environment runs the responder in a rootless Podman container. The
container cannot raise `net.core.rmem_max` from inside, and the local host
value may be the effective cap. `udpsink` requests a 16 MiB socket read
buffer, but the kernel may grant much less; under high upstream rates this
shows up as UDP drops and a loss percentage above zero even when the swan4
tunnel itself is keeping up.

## Debug notes

- `SSL_CERT_FILE` must point at the generated test CA before the process
  starts: Go's `x509.SystemCertPool` honors it at load time. Otherwise PEAP
  and responder-cert chain verification reject the self-signed test chain.
- charon logs to stdout (`charondebug` in `strongswan.conf`); raise it to
  `ike 4, enc 4, net 4` when diffing against swan4's debug logs.
  `swan/debug` renders the IKE/EAP payload chain in the same protocol shape.
- FreeRADIUS logs to `/var/log/freeradius.log` inside the container:
  `podman exec swan4-ss tail -f /var/log/freeradius.log`.
- Verify credentials without IKE:
  `podman exec swan4-ss radtest testuser testpassword 127.0.0.1 10 radius.rocks`.