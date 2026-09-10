# swan4 parity notes (swan2)

This file tracks which swan2 behaviors the swan4 Go implementation
reproduces and where it deliberately differs. The current repository is the
tested baseline: the checklists below describe what the code does now, not
aspirations.

## Build checks before changing anything

```bash
cd /home/wsm/workspace/swan/swan4
gofmt -l .          # must print nothing
go build ./...      # must succeed
go vet ./...        # must succeed
```

The test module lives under `tests/client` and is built separately.

## FIXED INVARIANTS (keep)

- **msgid**: after IKE_SA_INIT establishes, `State.NextRequestMessageID = 1`
  (IKE_SA_INIT used id 0; IKE_AUTH starts at 1).
- **integrity ids**: AUTH_HMAC_SHA2_256_128 = **12**,
  AUTH_HMAC_SHA2_384_192 = **13**, AUTH_HMAC_SHA2_512_256 = **14**
  (RFC 7296 IANA transforms).
- **ICV truncation**: sha1-96 => tag 12 / key 20; sha2_256_128 => 16/32;
  sha2_384_192 => 24/48 (sha512.New384); sha2_512_256 => 32/64.
- **CBC outbound**: payload-length and packet-length fields are patched
  BEFORE the outer ICV is computed, then the ICV is appended (the ICV
  covers the final length fields).
- **cipher names**: AES-GCM12/GCM16 => `aes128gcm12`/`aes128gcm16`/
  `aes256gcm12`/`aes256gcm16`; CCM8/12/16 analog; CBC =>
  `aes128`/`aes256`.
- **event ownership**: control emits `StageChanged`, `NegotiatedAlgorithm`,
  and `EapProcess`; the handshake also emits `Broken`/`Stopped` on failure.
  The root `swan` package emits `Starting`, `HandshakeStarted`,
  `HandshakeCompleted`, `ConfigAssigned`, `Started`, and the shutdown
  events `Stopping`/`Stopped`/runtime `Broken`.
- **SKF inbound**: a fragment whose `total_fragments` is SMALLER than the
  stored reassembly's slot count is IGNORED (swan2 `handle_skf` semantics).

## Module map

| swan2 (ikev2/src) | swan4 |
| --- | --- |
| payload.rs | wire/{header,message,builder}.go (syntax), control/protected.go (SK/SKF) |
| consts.rs | wire/consts.go (numbers), debug/names.go (names) |
| config.rs | xcrypto/suite.go (proposal strings/selection) |
| cipher/{ke,prf,hash,hmac,integrity,symm,rand} | xcrypto/{dh,prf,hash,hmac,cipher,rand}.go |
| cipher/tls | eap/peap/tls.go (uTLS in Go-mimicking mode over net.Pipe) |
| routine/sa_init*.rs | control/sa_init.go (+ exchange helpers) |
| routine/exchange_io.rs | control/exchange.go |
| routine/auth_bootstrap.rs, auth_shared.rs | control/auth.go |
| routine/peer_auth.rs | control/auth.go + xcrypto/x509.go |
| routine/ids.rs | control/identity.go |
| routine/child_sa.rs | control/child_sa.go |
| routine/eap.rs | control/eap_peer.go |
| routine/mod.rs (linear flow) | control/session.go + control/handshake.go |
| routine/control.rs (running) | control/running.go |
| routine/delete_exchange.rs | control/close.go |
| dataplane.rs (ESP) | esp/{inflow,outflow,replay}.go |
| eap/peap/* | eap/peap/{peap,fragment,avp,tls}.go |
| eap/mschapv2/* | eap/mschapv2/* |
| debug_fmt.rs | debug/{names,fmt}.go |
| lib.rs EventHub / public module | root package + events/hub.go |

---

## AREA 1 — SA_INIT + exchange engine (implemented)

**Files**: `control/sa_init.go`, `control/exchange.go`
**swan2 reference**: routine/{sa_init.rs,sa_init_shared.rs,exchange_io.rs,packet_io.rs}

Current behavior:

1.1 `buildSAInitRequest`:
- order: [COOKIE?] SA KE NONCE NAT-D-SRC NAT-D-DST FRAG SIG_HASH.
- SA uses the local `cfg.IKE` proposals; KEY_LENGTH attr is the transform
  key size in bits; AEAD suites omit INTEG transforms; non-AEAD suites
  include them.
- KE is a fresh X25519 keypair per attempt; the local private side is
  consumed once after DH and zeroized (`LocalDH = nil`).
- NONCE is 32 bytes generated once and reused across retries.
- NAT-D uses logical port 4500, src = `cfg.LocalIP` or `0.0.0.0`, dst =
  `cfg.PeerIP`, responder SPI 0 at request-build time.
- FRAGMENTATION_SUPPORTED is empty; SIGNATURE_HASH_ALGORITHMS is
  `00 02 00 03 00 04`.
- SPIi is generated once (non-zero) and reused across retries.
- The exact request bytes are stored in `State.SAInitRequest`.

1.2 `applySAInitResponse`:
- zero responder SPI => first payload must be NOTIFY; COOKIE/INVALID_KE
  retry outcomes must carry no SA/KE/Nonce.
- COOKIE: no SPI, non-empty data. INVALID_KE: exactly one 2-byte group.
- NO_PROPOSAL_CHOSEN and error notifies (<16384) hard-fail.
- captures remote NAT-D hashes, FRAGMENTATION_SUPPORTED, and
  SIGNATURE_HASH_ALGORITHMS.
- established: SA + Nr + KE required, selected proposal number must index
  `cfg.IKE` (1-based), transform ids/keylen-bits/integrity-presence/PRF/DH
  are verified exactly, and ESN in the IKE proposal is rejected.
- NAT detection: a missing remote hash is treated as equal on that side;
  present hashes are compared. Any present mismatch sets `Detected`.
- stores ResponderSPI/Nr/KE/SelectedIKE.

1.3 exchange engine:
- `beginRequest` claims `NextRequestMessageID`, marks it expected, then
  increments `NextRequestMessageID` (saturating at max uint32).
- `sendRequest` stores `Checkpoint{msgID, frames}` and pushes them to `tx`.
- `waitResponse`/`waitResponseRaw` use one reusable timer: start at
  `InitialRTO`; timeout resends the checkpoint, resets inbound fragments,
  doubles RTO up to `MaxRTO`, and stops after `MaxRetries` with a timeout
  error.
- classification: SPIi mismatch => ignore; known non-zero responder SPI
  mismatch => ignore; envelope checks version 0x20, RESPONSE set,
  INITIATOR clear, SPIs match, exchange and msgid match. Zero-responder-SPI
  IKE_SA_INIT must start with NOTIFY.
- msgid > expected => future error; msgid < expected &&
  msgid <= LastCompletedResponseMessageID => duplicate/stale (keep
  waiting); older otherwise => stale error.
- accepted responses clear the expected-response marker/checkpoint/fragment
  state and set `LastCompletedResponseMessageID`.
- `FirstIKEAuthSeen` is set only for IKE_AUTH responses.
- every received `*transport.Packet` is `Release()`d exactly once; parsed
  messages that outlive a packet are copied first.

---

## AREA 2 — xcrypto registry + keying (implemented)

**Files**: `xcrypto/*.go`
**swan2 reference**: cipher/{mod,prf,ke,hash,hmac,integrity,symm,rand}.rs, config.rs

Current behavior:

2.1 proposal strings:
- enc: aes/aes128 => id 12 / 16B key; aes256 => id 12 / 32B key.
  CCM 8/12/16 => ids 14/15/16; GCM 12/16 => ids 19/20.
- integ: sha1=>2, sha256/sha2_256=>12, sha384/sha2_384=>13,
  sha512/sha2_512=>14.
- prf: prfsha1=>2, prfsha256/prfsha2_256=>5, prfsha512/prfsha2_512=>7.
- dh: curve25519/x25519=>31.
- AEAD proposals must not include integrity tokens; non-AEAD proposals must;
  mixed AEAD|CBC in one proposal is rejected. PRF defaults from integrity,
  but a PRF-less sha384 integrity is rejected (no swan2 default).
- selection is local-preference top-down; AEAD selections have no
  integrity on either side; CBC selections share a common integrity and a
  matching PRF family.

2.2 ciphers:
- CBC: 16/32B key, IV 16, block 16; padding is the caller's job, and
  plaintext/ciphertext must be a multiple of 16 here.
- CCM8/12/16: transform key + 3B salt, IV 8, nonce = salt||IV (11 bytes),
  L=4, tag 8/12/16.
- GCM12/16: transform key + 4B salt, IV 8, tag 12/16, nonce = salt||IV.

2.3 PRF: HMAC-SHA1/256/512, output 20/32/64. PRF+ uses a one-byte counter
  and truncates.

2.4 keying splits: IKE seed Ni|Nr|SPIi|SPIr, order
  SKd(prflen) SKai SKar SKei SKer SKpi SKpr; integrity keys are empty for
  AEAD. CHILD seed Ni|Nr against SKd, order SKei SKai SKer SKar.

2.5 NAT-D = SHA1(SPIi|SPIr|ip(4/16B)|port u16).

2.6 AuthMAC = prf(prf(secret, "Key Pad for IKEv2"), octets).

2.7 x509: chain verification uses the Go stdlib
  (`crypto/x509`, `crypto/rsa` or `crypto/ecdsa`). The exact accepted
  AlgorithmIdentifiers and identity rules are the same six RSA/ECDSA x
  SHA256/384/512 combos as swan2's peer_auth constants.

2.8 `PreparedEncryption` / `PreparedIntegrity` prebuild keyed cipher/HMAC
  state once per SA; they are single-goroutine objects. ESP hands one to
  each direction, so there is no lock on the per-packet path.

---

## AREA 3 — bootstrap AUTH, peer auth, CHILD_SA, rightid (implemented)

**Files**: `control/auth.go`, `control/child_sa.go`, `control/identity.go`
**swan2 reference**: routine/{auth_bootstrap.rs,auth_shared.rs,peer_auth.rs,ids.rs,child_sa.rs,eap.rs}

Current behavior:

3.1 bootstrap inner chain: IDi | INITIAL_CONTACT | IDr-request (only when
  rightid is set) | CP-request | child-SA (fresh SPI) | TSi dual-stack any |
  TSr strongswan-default (v4 full, v6 2000::/3) | MOBIKE_SUPPORTED |
  NO_ADDITIONAL_ADDRESSES | MULTIPLE_AUTH_SUPPORTED |
  EAP_ONLY_AUTHENTICATION. **The request does NOT advertise
  IKEV2_MESSAGE_ID_SYNC_SUPPORTED.**

3.2 response handling: EAP/AUTH/IDr/CERT/notify collection; NOTIFY with
  nonzero SPI is rejected during EAP progression; CERT encodings other than
  X.509 signature are rejected; first response requires AUTH xor EAP, and
  an EAP-only response without the peer capability is rejected.
  `recordPeerIdentity` runs the `RightIDMatches` check.
  `validateAuthNotifies` accepts the known capability/child-failure
  notifies, turns AUTHENTICATION_FAILED into a suppressed echo failure, and
  hard-fails on error codes. A real `IKEV2_MESSAGE_ID_SYNC` notify is
  rejected as unsupported.

3.3 local AUTH method 2: secret = MSK if set, else SKpi; MACedID over the
  IDi bytes; signed octets = SAInitRequest | Nr | MACedID. Peer verify
  method 2 uses MSK if set, else SKpr; MACedID over IDr; octets =
  SAInitResponse | Ni | MACedID. Compare in constant time.

3.4 final AUTH/CHILD: response may not contain EAP and must contain AUTH.
  SA/TSi/TSr/CP are required unless a child-failure notify explains the
  rejection. SPI-scoped notify rules are enforced. The child proposal is
  decoded against the offered variants, including the strongswan-compat
  AEAD variant that omits the NO_EXT_SEQ transform. ESN is accepted when
  absent or when NO_EXT_SEQ (0). CP decodes attributes 1 (INTERNAL_IP4_ADDRESS),
  3 (INTERNAL_IP4_DNS), 5 (INTERNAL_ADDRESS_EXPIRY), 8
  (INTERNAL_IP6_ADDRESS, 17 bytes with prefix), and 10 (INTERNAL_IP6_DNS).
  At least one internal address is required. TSi must narrow exactly to the
  assigned address. `ActiveChild{inbound SPI, peer SPI, raw TSi/TSr}` and
  `Assigned` (with `AddressExpirySeconds`) are stored.

3.5 rightid: type 0 is wildcard; expected/received types must match;
  FQDN/RFC822 use case-insensitive `*`/`?` glob over bytes; other types use
  byte equality.

---

## AREA 4 — linear flow, EAP bridge, running, close (implemented)

**Files**: `control/session.go`, `control/eap_peer.go`, `control/running.go`,
`control/close.go`
**swan2 reference**: routine/{mod.rs,eap.rs,control.rs,delete_exchange.rs,packet_io.rs}

Current behavior:

4.1 Control.Run phases: Starting -> SAInit* -> AuthBootstrap ->
  AuthEAPInProgress -> ChildInstalling -> Running. SA_INIT retry budget is
  3 attempts. After SA_INIT: derive IKE keys, emit
  `NegotiatedAlgorithm(ike)`, set `NextRequestMessageID = 1`, emit
  `StageChanged(IKEAuth)`, send bootstrap. The EAP bridge owns every
  IKE_AUTH reply of the EAP phase (including the bootstrap response) with
  the one-time `firstResponse` policy. Then final AUTH, CHILD_SA decode,
  CP+TS validation, derive child keys, require Assigned, set Phase=Running,
  emit `StageChanged(StageRunning)`, and return the `Established` bundle.
  The running actor is started only after the public success events
  (`HandshakeCompleted`/`ConfigAssigned`/`Started`) are emitted, so its
  terminal events cannot reorder before them.

4.2 failure path: attempts to send a protected AUTHENTICATION_FAILED notify when
  keys exist and `SuppressAuthFailedNotify` is false (choosing IKE_AUTH
  vs INFORMATIONAL by phase); `ClearSession`; Phase=Stopped; emit `Broken`
  then `Stopped`; stop the demux.

4.3 eap_peer: method built once; worker mailbox carries
  `Round{packet,id,reply}`. `recv` waits for the protected IKE_AUTH
  response for the expected msgid and strips the EAP body; `send` wraps the
  EAP response as one protected payload and sends it as a new IKE_AUTH
  request. Completion stores `LocalEAPMSK` and emits EapProcess started /
  request / response / completed markers. The round cap is 64. Worker
  shutdown closes the mailbox and waits on `Done` with a small timeout.

4.4 running:
- keepalive every 20s, skipped while a request is outstanding.
- keepalive retransmission has its own RTO timer. Each retry doubles RTO up
  to `MaxRTO`; after `MaxRetries` unanswered, `Run` returns that error and
  the public layer emits `Broken`.
- every accepted response disarms the timer, resets retries, and resets RTO
  back to `InitialRTO`.
- inbound replay history holds at most 4 cached responses; a repeated peer
  request gets the same bytes back.
- cleartext INFORMATIONALs are rejected in the running state.
- expired SKF reassembly is cleared lazily when the next fragment arrives
  and also on the keepalive tick.
- empty INFORMATIONAL requests get an empty protected response.
- DELETE IKE (no SPIs) is answered, `ClearSession` runs, Phase becomes
  Stopped, and `Run` returns nil for a clean peer shutdown (no `Broken`).
- DELETE ESP (exactly one 4-byte SPI) must equal `ActiveChild.OutboundSPI`:
  the child is cleared, `childClosed` is closed, and the ESP pipeline ends
  the tunnel surface while IKE keeps running. Unknown SPIs are dropped.
- CREATE_CHILD_SA rekeys (CHILD and IKE, peer-initiated) are accepted.
  Simultaneous rekey collision: bytewise nonce comparison, smaller nonce
  loses — loser abandons and accepts the peer rekey; winner (and the
  infeasible equal-nonce case) answers `TEMPORARY_FAILURE`.
- every packet is released exactly once.

4.5 close:
- `Control.CloseExchange` performs the full request/reply sequence:
  CHILD_SA ESP DELETE (outbound SPI) first, then IKE DELETE (no SPIs),
  each with the shared retransmission timer budget; then `ClearSession` and
  Phase=Stopped.
- `Control.Close` is the "send only" variant used by `Session.Stop` after
  the running actor has exited and no one is consuming the inbound channel:
  it sends the deletes best effort, then `ClearSession` and Phase=Stopped
  without waiting for DELETE replies.
- Both are no-ops (`CloseAlreadyClosed`) when `ResponderSPI == 0` or
  `Phase == PhaseStopped`.

---

## AREA 5 — eap tree (implemented)

**Files**: `eap/**/*.go`
**swan2 reference**: eap/{mod.rs,payload.rs,mschapv2/mod.rs,mschapv2/core.rs,
mschapv2/md4.rs,peap/mod.rs,peap/avp.rs,peap/tls.rs}

Current behavior:

5.1 eap codec: strict code/length/type-byte rules; Request must have a
  type byte; Success/Failure keep trailing bytes as observability data but
  carry no type byte.

5.2 mschapv2: NT hash = MD4(UTF-16LE(password)); challenge 16B; challenge
  hash = SHA1(peer-challenge | id | username); 3x 7-byte DES key expansion
  with odd parity; NT response 24B; auth response is the 40-char hex "S="
  string; MSK 64B via RFC 3079 constants and 40-byte pads; success token is
  the 2-byte 0x01; identity/NAK handling present.

5.3 peap FSM: phases Idle/OuterIdentity/TLSTunnel/InnerMethod/
  AwaitingOuterSuccess/AwaitingOuterFailure/Completed/Failed. Empty ACK is
  a flags byte 0 with no TLS payload. Outbound fragmentation uses L/M/S
  flags and ACK pacing (one chunk per server ACK). Inbound reassembly
  requires L on the first fragment, forbids L on continuations, and enforces
  an exact total. Message-count cap applies. The TLS-ready transition
  verifies identity and initializes the inner method before emitting the
  same outbound record batch. `avp.go` does inner EAP packet framing as in
  swan2.

5.4 peap TLS engine: uTLS in Go-mimicking mode (`utls.HelloGolang`) over a
  net.Pipe bridge, with standard-library helpers for identity/cert checks.
  TLS 1.2 and TLS 1.3 are enabled. ServerName is stripped of a leading `@`
  and a `:port` suffix. RootCAs or SystemCertPool is used; even when
  `InsecureSkipVerify` is set, `VerifyServerIdentity` still runs. EAP MSK
  export: TLS <= 1.2 uses the RFC 5216 "client EAP encryption" derivation
  directly; TLS 1.3 RFC mode uses exporter
  `EXPORTER_EAP_TLS_Key_Material` with context `{0x19}` and takes the first
  64 bytes; TLS 1.3 strongswan-compat uses `client EAP encryption` with no
  context and takes the first 64 bytes.

---

## AREA 6 — dataplane ESP (implemented)

**Files**: `esp/*.go`
**swan2 reference**: dataplane.rs

Current behavior:

6.1 inbound: 8-byte ESP header peek; SPI filter before touching replay
  state; minimum header + IV + ICV length; sequence 0 rejected. Decrypt and
  authenticate BEFORE the replay window moves. AEAD AAD = datagram[:8];
  CBC ICV is verified over the packet up to (but not including) the ICV,
  then CBC decrypt. Trailer gives padLen + nextHeader (4 or 41 only) with
  strict bounds. `Process` returns a fresh copy; `ProcessPooled` returns a
  slice into inbound pool memory that the caller releases.

6.2 outbound: IPv4 -> next 4, IPv6 -> 41, other versions rejected. Padding
  is 1..padLen + padLen + nextHeader aligned to the cipher block (16 for
  CBC, 1 for AEAD). Fresh IV per packet; sequence starts at 1 and increments;
  on wrap it returns `ErrSeqWrapped` and never sends on that SA again (the
  pipeline reports it as fatal for the session). AEAD Seal AAD is the 8-byte
  ESP header prefix; CBC encrypts first, then HMACs over the whole datagram.
  Outbound frames are submitted to the shared transport writer in order.

---

## AREA 7 — protected SK/SKF crypto (implemented)

**Files**: `control/protected.go`
**swan2 reference**: payload.rs (`PayloadParser::decrypt_protected_payload`,
`handle_skf`, `IkeMessageBuilder::push_encrypt`) and
routine/auth_shared.rs (`build_protected_message_packets`,
IKE_FRAGMENT_PLAINTEXT_LIMIT)

Current behavior:

7.1 outbound seal: SK payload header next-payload = first inner payload type
  for fragment 1, NONE for non-first fragments; critical bit clear; payload
  length covers 4 (+4 SKF) + IV + ciphertext + ICV. For CBC the outer
  packet-length field is patched BEFORE the ICV is computed. AEAD AAD is
  everything from byte 0 through the SK/SKF header, excluding the IV. The
  SKF fragment header (4 bytes: u16 fragment_number, u16 total_fragments,
  1-based) sits before the IV, is not encrypted, and does not participate in
  padding. Padding is 1..padLen then padLen byte; AEAD block is 1.

7.2 CBC outbound: CBC encrypts the padded plaintext with no AAD; ICV =
  Integrity(SKai).Sign(whole packet including final length fields,
  excluding the ICV bytes), truncated to OutputLen.

7.3 inbound unwrap: AEAD Open AAD = raw packet prefix through SK(F) header;
  CBC verifies the ICV over the packet up to the ICV then CBC decrypts the
  middle; trailing padLen byte strips strictly; SK plaintext must be
  non-empty; SKF may return (nil, nil) while incomplete.

7.4 SKF reassembly: lock to (exchange, message_id); expiry refreshed per
  fragment (default 15s); a larger total resets the stored set; a smaller
  total than the stored slot count is ignored; fragment 1 records the inner
  first-payload and others must be NONE; completed fragments join in order
  and parse with the recorded first payload. Expired state is also cleared
  on the running keepalive tick.

---

## Long-run hardening notes

- ESP sequence wrap is fatal: outbound reaches `2^32-1`, the next attempt
  returns `ErrSeqWrapped`, the ESP pipeline reports it once, and the public
  session emits `Broken` and shuts down.
- Peer CHILD_SA DELETE ends only the data plane: the control plane clears
  `ActiveChild`, the ESP workers stop, `Tunnel.Read` drains then returns
  `io.EOF`, and `Tunnel.Write` returns `io.ErrClosedPipe`.
- RTO reset: any accepted keepalive/response resets the retransmission
  ladder to `InitialRTO`.
- No MESSAGE_ID_SYNC advertisement: the bootstrap request does not send
  `IKEV2_MESSAGE_ID_SYNC_SUPPORTED`; receiving a real
  `IKEV2_MESSAGE_ID_SYNC` notify is an error.
- `ClearSession` wipes keys, nonces, checkpoints, history, fragments,
  assigned config, child state, and EAP MSK on both failure and close.
- `AddressExpirySeconds` is parsed from CP attribute 5; at 80% of the lease
  the running actor renews via INFORMATIONAL + CFG_REQUEST, retries on
  failure, and treats hard expiry as a session failure.
- The running actor rejects cleartext INFORMATIONALs and enforces request
  message-id ordering with the 4-entry response replay cache.

## Batching design

- transport RxWorker: IKE packets are delivered one at a time. ESP packets
  are collected into batches of up to 32, flushed after 200us of quiet.
  After an idle gap the first packet is delivered immediately as a
  single-packet batch (low-load fast path).
- transport TxWorker: coalesces up to 32 additional queued frames after the
  first into one wire `Write`, preserving FIFO order.
- ESP OutboundWorker: drains up to 32 additional raw IP packets after the
  first before encrypting them as a group.
- Pooling: transport rx buffers start at 4 KiB, ESP inbound plaintext at
  2 KiB, ESP outbound datagrams at 4 KiB; larger packets allocate and
  recycle their larger backings.

## Rekey support (implemented)

- Initiator CHILD_SA rekey: CREATE_CHILD_SA with ESP SA + Nr [+KEi if PFS]
  + TSi/TSr; the new SA is installed atomically (old inbound still
  decrypts), outbound switches to the new SPI, then the old CHILD_SA is
  DELETE-ed. Triggers: soft lifetime, outbound byte/packet thresholds, and
  a near-sequence-wrap emergency threshold.
- Initiator IKE_SA rekey: CREATE_CHILD_SA with IKE SA + Nr + KEi, fresh
  SKEYSEED/keymat from the new nonces/DH, SPI/SK swap, message-id reset to
  0 on the new IKE SA, old context retained until the old IKE SA delete
  acknowledges.
- Peer-initiated rekey is accepted for both families; a peer-initiated IKE
  rekey flips `IsOriginalInitiator` so header flags and outbound/inbound
  key halves follow the new role. REKEY_SA target SPI accepts both the old
  inbound and old outbound spelling because real strongSwan sends its
  inbound SPI on the wire.
- Config surface: `swan.Config.Rekey` with IKE/Child `Lifetime{Time,Bytes,
  Packets}`, `ChildPFS`, `RandTime`, `RetryInterval`, `NearWrapThreshold`.
  Defaults: IKE 4h / CHILD 1h soft, PFS on, 90% near-wrap, 30s retry.
  IKE Bytes/Packets are parsed but not enforced (time-driven only).
- Lease renewal per the long-run note above.

## Local test fixtures

- `tests/docker`: all-in-one strongSwan + FreeRADIUS responder image
  `localhost/swan4-e2e`, run as container `swan4-ss` without host
  networking (`-p 4500:4500/udp --cap-add NET_ADMIN --cap-add NET_RAW`).
- DNS fixture: strongSwan `attr` plugin is configured with
  `dns = 9.9.9.9, 8.8.4.4`.
- `tests/udpsink`: responder-side UDP counter (`-mode up`) and pump
  (`-mode down`) used with the private DATA/END/STAT benchmark protocol.
- `tests/client/udpbench`: drives the ESP tunnel from the host; at
  `-size 1400 -rate 180000` upstream this environment sees roughly
  170k pps / ~2 Gbit through the tunnel, and the responder-side unpaced
  wall is roughly 208k pps. Results are environment-specific; rootless
  containers here cannot raise `net.core.rmem_max`, which caps socket
  receive buffering during floods.