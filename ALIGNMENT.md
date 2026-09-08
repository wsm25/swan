# swan4 ↔ swan2 alignment spec

This file is the single authoritative contract for alignment subagents.
Every alignment lane executes exactly one AREA below, then runs the GATES.

## Global rules for every lane

1. Edit ONLY the files listed in your AREA. Report (do not fix) issues elsewhere.
2. Reference = swan2 intent & byte semantics. Implement standard, idiomatic Go.
3. Do not regress the FIXED INVARIANTS section (already validated against e2e).
4. AGENTS.md rules: no git, stdlib only, temporary tests must be deleted before
   finishing, no go.mod/go.sum edits.
5. Files must stay gofmt-clean; build/vet errors inside YOUR files are yours
   to fix; errors in other lanes' files are transient (they run in parallel).
6. `*transport.Packet` must be `Release()`d exactly once per packet consumed.
7. All wire fields are big-endian; no allocations on parse hot paths unless
   a checkpoint copy is explicitly required.

## FIXED INVARIANTS (never regress)

- **msgid**: after IKE_SA_INIT establishes, `State.NextRequestMessageID = 1`
  (IKE_SA_INIT used id 0; IKE_AUTH starts at 1).
- **integrity ids**: AUTH_HMAC_SHA2_256_128 = **12**, AUTH_HMAC_SHA2_384_192 = **13**,
  AUTH_HMAC_SHA2_512_256 = **14** (see RFC 7296 iana transforms).
- **ICV truncation**: sha1-96 => tag 12 / key 20; sha2_256_128 => 16/32;
  sha2_384_192 => 24/48 (sha512.New384); sha2_512_256 => 32/64.
- **CBC outbound**: payload-length and packet-length fields are patched BEFORE
  the outer ICV is computed, then the ICV is appended (ICV covers final lens).
- **cipher names**: AES-GCM12/GCM16 => `aes128gcm12`/`aes128gcm16`/
  `aes256gcm12`/`aes256gcm16`; CCM8/12/16 analog; CBC => `aes128`/`aes256`.
- **event ownership**: control emits only StageChanged / NegotiatedAlgorithm /
  EapProcess (+Broken/Stopped on failure). Facade emits Starting,
  HandshakeStarted, HandshakeCompleted, ConfigAssigned, Started.
- **SKF inbound**: a fragment whose total_fragments is SMALLER than a stored
  reassembly with more slots is IGNORED (swan2 `handle_skf` semantics).

## Module map

| swan2 (ikev2/src) | swan4 |
| --- | --- |
| payload.rs | wire/{header,message,builder}.go (syntax), control/protected.go (SK/SKF) |
| consts.rs | wire/consts.go (numbers), debug/names.go (names) |
| config.rs | xcrypto/suite.go (proposal strings/selection) |
| cipher/{ke,prf,hash,hmac,integrity,symm,rand} | xcrypto/{dh,prf,hash,hmac,cipher,rand}.go |
| cipher/tls | eap/peap/tls.go (crypto/tls over net.Pipe) |
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
| lib.rs facade/EventHub | root package + events/hub.go |

---

## AREA 1 — SA_INIT + exchange engine

**Files**: `control/sa_init.go`, `control/exchange.go`
**Refs**: swan2 routine/{sa_init.rs,sa_init_shared.rs,exchange_io.rs,packet_io.rs}

Checklist:

1.1 `buildSAInitRequest`:
- order: [COOKIE?] SA KE NONCE NAT-D-SRC NAT-D-DST FRAG SIG_HASH.
- SA via payload builders from `cfg.IKE`: KEY_LENGTH attr = TV (0x8000|14) + bits,
  AEAD suites omit INTEG transforms, chain flags per swan2 `append_sa_proposals`.
- KE: u16 group + fresh X25519 pub each attempt; DH keypair regenerated per attempt.
- NONCE: 32B generated ONCE (kept across retries).
- NAT-D: xcrypto.NatDetectionHash with logical port 4500; src = cfg.LocalIP (or
  0.0.0.0), dst = cfg.PeerIP. Store both local hashes.
- FRAGMENTATION_SUPPORTED: empty data. SIGNATURE_HASH_ALGORITHMS: 00 02 00 03 00 04.
- SPIi generated once (non-zero), kept across retries.
- Store the exact request bytes in State.SAInitRequest.

1.2 `applySAInitResponse` (swan2 `apply_sa_init_response`):
- zero responder SPI => header next must be NOTIFY; retry outcomes must carry no
  SA/KE/Nonce; COOKIE notify: no SPI, non-empty data; INVALID_KE: 2-byte group;
  NO_PROPOSAL_CHOSEN and error notifies (<16384) hard-fail.
- capture remote NAT-D hashes, FRAGMENTATION_SUPPORTED, SIGNATURE_HASH_ALGORITHMS.
- established: SA + Nr + KE required; proposal number must index cfg.IKE
  (1-based); verify transform ids/keylen-bits/integrity-presence/PRF/DH exactly;
  ESN in IKE proposal rejected; store ResponderSPI/Nr/KE/SelectedIKE.
- NAT detected: remote_src != local_src || remote_dst != local_dst.

1.3 exchange engine (swan2 `exchange_io.rs`):
- beginRequest: claim `NextRequestMessageID`, increment it, set
  `ExpectedResponseMessageID` + `HasExpectedResponse`.
- sendRequest: store `Checkpoint{msgID, frames}`, push frames to tx.
- waitResponse loop with ONE reusable timer: start `cfg.Timeouts.InitialRTO`;
  timeout => resend checkpoint (reset InboundFragments), RTO *= 2 capped
  `MaxRTO`, stop after `MaxRetries` with "timed out waiting for <step> after N
  retransmits".
- classify: SPIi mismatch => Ignore; known non-zero responder SPI mismatch =>
  Ignore; envelope: version 0x20, RESPONSE set/INITIATOR clear, SPIs match,
  exchange == waited, msgid == waited; IKE_SA_INIT zero-responder-SPI must start
  with NOTIFY.
- msgid > expected => error future; < expected && <= lastCompleted =>
  DuplicateOrStale (keep waiting); < expected otherwise => stale error.
- Expected: set LastCompletedResponseMessageID + flags, clear Expected response +
  OutboundRequest + InboundFragments; FirstIKEAuthSeen when exchange==IKE_AUTH;
  return a message that does NOT alias pooled buffers (copy before Release).
- every received `*transport.Packet` is Release()d exactly once.

---

## AREA 2 — xcrypto registry + keying

**Files**: `xcrypto/*.go`
**Refs**: swan2 cipher/{mod,prf,ke,hash,hmac,integrity,symm,rand}.rs, config.rs

Checklist:

2.1 proposal strings (swan2 config.rs tables):
- enc: aes/aes128 => id12/16B; aes256 => id12/32B; aes128|256ccm8|12|16 =>
  ids 14/15/16 with 16/32B keys; aes128|256gcm12|16 => ids 19/20.
- integ: sha1=>2, sha2_256|sha256=>12, sha2_384|sha384=>13, sha2_512|sha512=>14.
- prf: prfsha1=>2, prfsha256=>5, prfsha512=>7. dh: curve25519=>31.
- AEAD proposals MUST NOT carry integrity tokens (error); non-AEAD MUST;
  mixed AEAD|CBC rejected; PRF default from integrity (sha1->2, sha256->5,
  sha512->7; sha384 default unsupported in swan2 => reject PRF-less sha384).
- Select: strict local preference top-down; AEAD => both sides integrity-less;
  CBC => common integrity + its matching PRF.

2.2 ciphers:
- CBC: 16/32B key, IV 16, block 16, no padding inside xcrypto, multiple-of-16.
- CCM8/12/16: transform key + 3B salt, IV 8, nonce = salt||IV = 11 bytes,
  length field L=4 (standard RFC 4309/5282 for IKE/ESP CCM; note swan2's
  U13/n=11 mix was never executable - standard wins), tag 8/12/16,
  RFC 3610/4309 CBC-MAC + CTR.
- GCM12/16: transform key + 4B salt, IV 8, tag 12/16, nonce=salt||iv.

2.3 PRF: HMAC-SHA1/256/512 out 20/32/64. PRF+: T1=prf(S,seed|0x01),
Tn=prf(S,T(n-1)|seed|n) one counter byte, truncate.

2.4 keying splits (swan2 sa_init.rs / child_sa.rs): IKE seed Ni|Nr|SPIi|SPIr,
order SKd(prflen) SKai SKar SKei SKer SKpi SKpr with integ keys EMPTY when AEAD
and enc lengths = xcrypto KeyLen. CHILD seed Ni|Nr against SKd: SKei SKai SKer
SKar.

2.5 NAT-D = SHA1(SPIi|SPIr|ip(4/16B)|port u16).

2.6 AuthMAC = prf(prf(secret,"Key Pad for IKEv2"), octets).

2.7 x509: six AlgorithmIdentifiers (rsa/ecdsa x sha256/384/512, swan2
peer_auth.rs constants); chain verify serverAuth; FQDN/IP SAN identity;
RFC822/KEY_ID error; RSA PKCS1v15 / ECDSA ASN.1 verify.

---

## AREA 3 — bootstrap AUTH, peer auth, CHILD_SA, rightid

**Files**: `control/auth.go`, `control/child_sa.go`, `control/identity.go`
**Refs**: swan2 routine/{auth_bootstrap.rs,auth_shared.rs,peer_auth.rs,ids.rs,child_sa.rs,eap.rs}

Checklist:

3.1 bootstrap inner chain [swan2 auth_bootstrap.rs]: IDi | INITIAL_CONTACT |
IDr-request(if rightid) | CP-request | child-SA(SPI fresh, strongswan-compat
AEAD variants omit ESN) | TSi dual-stack any | TSr strongswan-default
(v4 full, v6 2000::/3) | MOBIKE | NO_ADDITIONAL_ADDRESSES |
MULTIPLE_AUTH_SUPPORTED | EAP_ONLY_AUTHENTICATION | IKEV2_MESSAGE_ID_SYNC_SUPPORTED.

3.2 response handling [swan2 eap.rs + peer_auth.rs]: EAP/AUTH/IDr/CERT/notify
collection; NOTIFY zero-SPI during EAP progression; CERT encodings 4 only;
first response AUTH xor EAP; EAP-only capability enforcement; recordPeerIdentity
via RightIDMatches; validateAuthNotifies allowed/error lists (IKEV2_MESSAGE_ID_SYNC
unsupported; AUTHENTICATION_FAILED => broken + suppress echo; <16384 errors fail).

3.3 local AUTH method 2 [peer_auth.rs]: secret = MSK if set else SKpi;
MACedID = prf(secret, IDi bytes); octets = SAInitRequest | Nr | MACedID;
AuthMAC(secret, octets). Peer verify method 2: secret = MSK else SKpr; MACedID
over IDr; octets = SAInitResponse | Ni | MACedID.

3.4 final AUTH / CHILD [swan2 child_sa.rs]: request [IDr?]|IDi|AUTH; response:
EAP forbidden, AUTH required, SA/TSi/TSr/CP required unless child-failure notify;
SPI-scoped notify rules; child proposal decode vs OFFERED variant list (incl.
strongswan-compat ESN-omission variants); ESN absent or 0; CP decode attrs
1(4B)/3(4B)/8(17B)/10(16B) and require an internal address; TSi must narrow to
assigned address exactly; deriveChildKeys; ActiveChild{inbound SPIi, outbound
peer SPI, raw TSi/TSr}.

3.5 rightid [ids.rs]: expected type 0 wildcard; type equality; FQDN/RFC822
case-insensitive `*`/`?` glob over bytes; others bytes.Equal.

---

## AREA 4 — linear flow, EAP bridge, running, close

**Files**: `control/session.go`, `control/eap_peer.go`, `control/running.go`,
`control/close.go`
**Refs**: swan2 routine/{mod.rs,eap.rs,control.rs,delete_exchange.rs,packet_io.rs}

Checklist:

4.1 Control.Run linear flow [swan2 mod.rs]: phases Starting -> SAInit* ->
AuthBootstrap -> AuthEAPInProgress -> ChildInstalling -> Running; SA_INIT retry
budget MaxSAInitAttempts; after established: derive IKE keys, emit
NegotiatedAlgorithm(ike), NextRequestMessageID=1, emit StageChanged(IKEAuth);
bootstrap send; EAP bridge owns ALL IKE_AUTH replies of the EAP phase (incl.
bootstrap response) with the one-time firstResponse policy; final auth;
ProcessFinalAuth + deriveChildKeys; require Assigned; Phase=Running; demux
handoff to runningMailbox exactly once; go Running.Run; emit
StageChanged(StageRunning); return Established bundle.

4.2 failure path [swan2 lib.rs finalize/get]: best-effort protected
AUTHENTICATION_FAILED notify when ResponderSPI!=0 && IKEKeys exist &&
!SuppressAuthFailedNotify (IKE_AUTH exchange during bootstrap/EAP/child phases,
else INFORMATIONAL); ClearSession; emit Broken then Stopped; stop demux.

4.3 eap_peer [swan2 routine/eap.rs]: method built once (methods.New); worker
mailbox Round{packet,msgid,reply}; recv = protected IKE_AUTH response for the
expected msgid, processed via handleAuthResponse(firstResponse), EAP body
extracted; send = wrap EAP bytes as single protected payload (generic header
next=None, crit=0, u16 len 4+len) in IKE_AUTH for beginRequest; complete =>
store LocalEAPMSK; emit EapProcess started/response/completed markers; round
cap (64); clean worker shutdown (close mailbox, wait Done small timeout).

4.4 running [swan2 control.rs]: keepalive 20s SKIP when HasExpectedResponse;
inbound: check replay cache (<=4 history, drop oldest, resend identical bytes);
empty INFORMATIONAL ok => empty response; DELETE IKE (no spis) => respond,
ClearSession+Stopped, exit (peer shutdown); DELETE ESP (exactly one 4B spi)
must equal ActiveChild.OutboundSPI => clear child + respond; unknown => drop.
All packets Release exactly once.

4.5 close [swan2 delete_exchange.rs]: AlreadyClosed when ResponderSPI==0 or
Phase==Stopped; else CHILD ESP DELETE (outbound SPI) first, then IKE DELETE
(no spis); each round trips with the same retry timer budget, then
ClearSession + Phase=Stopped; return Closed.

---

## AREA 5 — eap tree

**Files**: `eap/**/*.go`
**Refs**: swan2 eap/{mod.rs,payload.rs,mschapv2/mod.rs,mschapv2/core.rs,
mschapv2/md4.rs,peap/mod.rs,peap/avp.rs,peap/tls.rs}

Checklist:

5.1 eap codec: strict code/length/type-byte rules already implemented; verify
only divergences vs swan2 payload.rs.

5.2 mschapv2: NT hash = MD4(UTF-16LE(password)); CHALLENGE 16B; VALUE_SIZE 49;
ChallengeHash = SHA1(peer-challenge | id | username); 3x 7-byte DES key
expansion with odd parity per RFC 2759; NT response 24B; auth response hex 40
chars S= with magic constants; MSK 64B via RFC 3079 constants + 0x00/0xF2
40-byte pads; opcode 1..4; success token 2 bytes 0x01; identity/NAK handling;
expectingSuccess transitions per swan2 mschapv2/mod.rs + core.rs.

5.3 peap FSM: phases Idle/OuterIdentity/TlsTunnel/InnerMethod/
AwaitingOuterSuccess/AwaitingOuterFailure/Completed/Failed; ACK packet =
L|M|S all zero + empty tls payload; outbound fragmentation L/S/M flags and
ACK pacing one chunk per server ACK; inbound collector first-frag L required,
continuations no-L, exact total; message-count cap; on_tls_step ordering
(verify identity + initialize inner BEFORE sending the same outbound
record batch when tunnel became ready); inner EAP via avp.go
(complete packets passthrough; identity passthrough; MS-AVP success/failure
mapping; else synthetic Request with outer id) — swan2 peap/mod.rs + avp.rs.

5.4 peap tls engine: crypto/tls over net.Pipe bridge; TLS 1.2 + 1.3; ServerName
stripped of @ and :port; RootCAs or SystemCertPool; InsecureSkipVerify still
runs VerifyServerIdentity afterwards; feed/collect record semantics with no
goroutine leaks; exporter trinity: TLS1.2 label "client EAP encryption" ctx
nil len 64; TLS1.3 RFC label "EXPORTER_EAP_TLS_Key_Material" ctx {0x19} len
128 -> first 64; TLS1.3 strongswan-compat label "client EAP encryption" nil
len 128 -> first 64.

---

## AREA 6 — dataplane ESP

**Files**: `esp/*.go`
**Refs**: swan2 dataplane.rs

Checklist:

6.1 inbound: SPI u32be peek; require >= 8B header + IV + ICV; replay window
(seed first, >=64 forward jump resets, bitmask dup check, seq 0 rejected);
AEAD AAD = datagram[:8] with responder keys (SKer; SKar for CBC ICV); CBC
ICV over datagram[:-icv] constant-time then CBC Open of ct; ESP trailer
padLen + nextHeader 4/41 with strict bounds; return a COPY (no aliasing).

6.2 outbound: IPv4 => next 4, IPv6 => 41; pad 1..padLen + padLen + nextHeader
aligned to block (CBC 16, AEAD 1); fresh IV; seq from 1 with wrap check;
AEAD Seal AAD = 8B header prefix with SKei; CBC encrypt SKei then HMAC SKai
over full datagram; frame KindESP.

---

## AREA 7 — protected SK/SKF crypto (control/protected.go)

**Files**: `control/protected.go`
**Refs**: swan2 payload.rs (`PayloadParser::decrypt_protected_payload`, `handle_skf`,
`IkeMessageBuilder::push_encrypt`) and routine/auth_shared.rs
(`build_protected_message_packets`, IKE_FRAGMENT_PLAINTEXT_LIMIT)

Checklist:

7.1 outbound seal: IKE header fields/offsets; SK payload header next-payload =
inner first payload type (fragment 1) or None (non-first fragments); critical
bit cleared; payload length = 4 (+4 SKF) + IV + ct + ICV; packet length field
patched BEFORE ICV for CBC (see FIXED INVARIANTS); AAD for AEAD = everything
from byte 0 through the SK/SKF header, excluding IV; SKF fragment header
(4B, u16 fragment_number, u16 total_fragments, 1-based) sits before the IV,
is NOT encrypted and does NOT participate in plaintext padding; padding
bytes = 1..padLen then padLen byte, padLen chosen for
(plaintext+1+padLen) % block == 0 (AEAD block 1).

7.2 CBC outbound: Seal CBC with NO aad over padded plaintext; ICV =
Integrity(SKai).Sign(whole packet incl. final length fields, excluding the ICV
bytes), truncated to OutputLen; SK(F) header | IV | ct | ICV layout.

7.3 inbound unwrap: AEAD Open with aad = raw packet prefix through SK(F)
header; CBC Integrity(SKar).Verify over packet-up-to-ICV then CBC Open of the
middle; trailing padLen byte strips strictly (padLen < plaintext len); plaintext
non-empty for SK; SKF fragments may produce (nil, nil) while incomplete.

7.4 SKF reassembly (swan2 handle_skf): lock to (exchange, message_id); 15s
expiry refreshed per fragment; a fragment whose total_fragments is LARGER
than the current stored array size RESETS reassembly; a fragment whose total
is SMALLER than a stored array with more slots is IGNORED; fragment 1
records the inner first-payload (others must be None); join in order when
complete and parse the inner chain with ParsePayloads(joined, first, false).

## GATES (run before reporting)

```bash
cd /home/wsm/workspace/swan/swan4
gofmt -l <your files>            # must print nothing
go build ./...                   # errors in YOUR files must be fixed
go vet ./...                     # same rule
```

Report format: (1) divergences found vs swan2, with swan2 file/line evidence;
(2) fixes applied; (3) deliberate Go-idiomatic deltas that keep byte semantics;
(4) gate outputs; (5) anything still inconsistent + recommendation.