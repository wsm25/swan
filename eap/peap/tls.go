package peap

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	tls "crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
)

// TLS engine for PEAP, aligned with the strongSwan PEAP tls path.
//
// A TLS 1.2 + TLS 1.3 client (uTLS in Go-mimicking mode) driven through a
// net.Pipe bridge: the TLS connection consumes a net.Conn, PEAP consumes
// TLS records, so one relay goroutine pumps between the two with no other
// backend. All TLS bytes leave this engine as raw records; the PEAP FSM
// owns fragmentation/ACK.
//
// EAP MSK export mirrors strongSwan:
//   - TLS <= 1.2:  PRF(master_secret, "client EAP encryption",
//     client_random || server_random, 64) computed directly from the
//     handshake state. Go's crypto/tls refuses the exporter for legacy
//     sessions without EMS (strongSwan 5.9 negotiates no EMS), so the
//     RFC 5705/5216 derivation runs here instead.
//   - TLS 1.3 RFC mode:  exporter("EXPORTER_EAP_TLS_Key_Material",
//     context=[0x19], 128) -> first 64 bytes
//   - TLS 1.3 strongswan-compat: exporter("client EAP encryption",
//     no context, 128) -> first 64 bytes
//
// Certificate behavior: the engine verifies the server against the given
// trust pool during the handshake; with InsecureSkipVerify the FSM still
// verifies identity (VerifyServerIdentity) after the tunnel is ready.

// Settling timers for the in-memory relay. The pipe is local, so any TLS
// outbound bytes produced by a feed complete within microseconds under
// normal scheduling; the quiet windows are only a scheduling tolerance,
// never a protocol wait on the network.
const (
	relayPollInterval = 2 * time.Millisecond
	collectFirstWait  = 20 * time.Millisecond
	collectQuiet      = 2 * time.Millisecond
	startFirstWait    = 5 * time.Second
)

// Step describes the result of feeding one inbound TLS record.
type Step uint8

const (
	StepNeedMoreData Step = iota
	StepOutbound
	StepEstablished
)

// Engine is one TLS tunnel session. One instance per PEAP Initialize.
type Engine struct {
	serverName string
	opts       Options
	roots      *x509.CertPool

	// client is the TLS client side of the pipe bridge.
	client *utls.UConn
	// peer is the PEAP-facing side of the pipe; the relay mirrors bytes
	// between the two directions.
	peer net.Conn

	// inbound carries TLS records from Feed to the relay (to be written
	// into the peer side for the TLS stack to read).
	inbound chan []byte
	// outbound carries TLS records produced by the TLS stack (read from the
	// peer side by the relay) back to Start/Feed/Protect callers.
	outbound chan []byte

	stop chan struct{}
	done chan struct{}

	startOnce     sync.Once
	closeOnce     sync.Once
	wg            sync.WaitGroup
	startErr      error
	started       bool
	handshakeDone chan error
	established   atomic.Bool
}

// NewEngine validates the server name and builds the TLS config
// (TLS 1.2/1.3, root pool and manual certificate verification, no client
// auth). No handshake bytes flow yet.
func NewEngine(serverName string, opts Options, roots *x509.CertPool) (*Engine, error) {
	clean := normalizeServerName(serverName)
	if clean == "" {
		return nil, errors.New("swan/eap/peap: empty PEAP TLS server name")
	}
	pool := roots
	if pool == nil && !opts.InsecureSkipVerify {
		var err error
		pool, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("swan/eap/peap: load system cert pool: %w", err)
		}
	}
	cfg := &utls.Config{
		ServerName:         clean,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		RootCAs:            pool,
		InsecureSkipVerify: false, // verification is explicit below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if opts.InsecureSkipVerify {
				return nil // chain checked nowhere; FSM verifies identity later
			}
			certs := make([]*x509.Certificate, 0, len(rawCerts))
			for _, raw := range rawCerts {
				cert, err := x509.ParseCertificate(raw)
				if err != nil {
					return fmt.Errorf("swan/eap/peap: parse server certificate: %w", err)
				}
				certs = append(certs, cert)
			}
			if len(certs) == 0 {
				return errors.New("swan/eap/peap: server sent no certificate")
			}
			intermediates := x509.NewCertPool()
			for _, cert := range certs[1:] {
				intermediates.AddCert(cert)
			}
			leaf := certs[0]
			opts := x509.VerifyOptions{
				Roots:         pool,
				Intermediates: intermediates,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			if _, err := leaf.Verify(opts); err != nil {
				return fmt.Errorf("swan/eap/peap: verify server certificate chain: %w", err)
			}
			if err := leaf.VerifyHostname(clean); err != nil {
				return fmt.Errorf("swan/eap/peap: server certificate identity %q: %w", clean, err)
			}
			return nil
		},
	}
	clientSide, peerSide := net.Pipe()
	return &Engine{
		serverName: clean,
		opts:       opts,
		roots:      pool,
		client:     utls.UClient(clientSide, cfg, utls.HelloGolang),
		peer:       peerSide,
		inbound:    make(chan []byte, 16),
		outbound:   make(chan []byte, 32),
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}, nil
}

// Start runs the relay worker and returns the initial outbound records
// (ClientHello). The engine must be Started exactly once.
func (e *Engine) Start() ([]byte, error) {
	e.startOnce.Do(func() { e.startErr = e.launch() })
	if e.startErr != nil {
		return nil, e.startErr
	}
	out, _, got, err := e.collect(startFirstWait)
	if err != nil {
		return nil, err
	}
	if !got {
		return nil, fmt.Errorf("swan/eap/peap: TLS handshake produced no ClientHello: %w", err)
	}
	return out, nil
}

// Feed delivers one inbound TLS record (unfragmented, from the PEAP
// collector) and returns outbound records plus the new step.
func (e *Engine) Feed(record []byte) (outbound []byte, step Step, err error) {
	if !e.started {
		return nil, StepNeedMoreData, errors.New("swan/eap/peap: TLS engine not started")
	}
	if e.established.Load() {
		return nil, StepEstablished, errors.New("swan/eap/peap: TLS handshake already established; use Unprotect")
	}
	if len(record) == 0 {
		return nil, StepNeedMoreData, nil
	}
	select {
	case e.inbound <- append([]byte(nil), record...):
	case <-e.stop:
		return nil, StepNeedMoreData, errors.New("swan/eap/peap: TLS engine closed")
	}
	out, est, _, colErr := e.collect(collectFirstWait)
	if colErr != nil {
		return nil, StepNeedMoreData, colErr
	}
	if len(out) > 0 {
		return out, StepOutbound, nil
	}
	if est {
		return nil, StepEstablished, nil
	}
	return nil, StepNeedMoreData, nil
}

// Established reports whether the TLS handshake is complete.
func (e *Engine) Established() bool {
	return e.established.Load()
}

// VerifyServerIdentity checks the peer certificate against the expected
// server name (SAN), used after the tunnel is ready — also in the insecure
// mode where only chain checks were skipped.
func (e *Engine) VerifyServerIdentity(name string) error {
	clean := normalizeServerName(name)
	if clean == "" {
		return errors.New("swan/eap/peap: empty TLS server identity")
	}
	state := e.client.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return errors.New("swan/eap/peap: missing TLS peer certificate")
	}
	cert := state.PeerCertificates[0]
	if err := cert.VerifyHostname(clean); err != nil {
		return fmt.Errorf("swan/eap/peap: TLS server identity %q: %w", clean, err)
	}
	return nil
}

// Protect encrypts one chunk of tunneled application plaintext and returns
// the TLS record bytes.
func (e *Engine) Protect(plain []byte) ([]byte, error) {
	if !e.established.Load() {
		return nil, errors.New("swan/eap/peap: TLS tunnel is not ready")
	}
	n, err := e.client.Write(plain)
	if err != nil {
		return nil, fmt.Errorf("swan/eap/peap: TLS protect: %w", err)
	}
	if n != len(plain) {
		return nil, io.ErrShortWrite
	}
	return e.drainOutbound(collectQuiet)
}

// Unprotect decrypts one inbound application-data record (may yield
// multiple complete plaintext chunks).
func (e *Engine) Unprotect(record []byte) ([]byte, error) {
	if !e.established.Load() {
		return nil, errors.New("swan/eap/peap: TLS tunnel is not ready")
	}
	select {
	case e.inbound <- append([]byte(nil), record...):
	case <-e.stop:
		return nil, errors.New("swan/eap/peap: TLS engine closed")
	}
	return e.readApplication()
}

// ExportMSK exports the 64-byte EAP MSK as described in the package
// comment; it returns an error before Established.
func (e *Engine) ExportMSK() ([]byte, error) {
	if !e.established.Load() {
		return nil, errors.New("swan/eap/peap: TLS tunnel is not ready")
	}
	state := e.client.ConnectionState()
	if state.Version >= tls.VersionTLS13 {
		label, context, length := ExportLabelRFC, []byte{ExportContextPEAP}, 128
		if e.opts.StrongswanCompatible {
			label, context, length = ExportLabelCompat, nil, 128
		}
		keymat, err := state.ExportKeyingMaterial(label, context, length)
		if err != nil {
			return nil, fmt.Errorf("swan/eap/peap: export EAP MSK: %w", err)
		}
		if len(keymat) < MSKLen {
			return nil, fmt.Errorf("swan/eap/peap: exporter returned %d bytes, need %d", len(keymat), MSKLen)
		}
		return keymat[:MSKLen], nil
	}

	// TLS <= 1.2: RFC 5705/5216 derivation straight from the handshake
	// state. This path also covers legacy sessions without EMS, where the
	// standard ConnectionState exporter refuses to run.
	hs := e.client.HandshakeState
	if len(hs.MasterSecret) == 0 || hs.Hello == nil || hs.ServerHello == nil {
		return nil, errors.New("swan/eap/peap: TLS 1.2 handshake state unavailable for MSK export")
	}
	seed := make([]byte, 0, len(hs.Hello.Random)+len(hs.ServerHello.Random))
	seed = append(seed, hs.Hello.Random...)
	seed = append(seed, hs.ServerHello.Random...)
	keymat := e.tls12PRF(hs.MasterSecret, ExportLabelCompat, seed, MSKLen)
	if len(keymat) < MSKLen {
		return nil, fmt.Errorf("swan/eap/peap: TLS 1.2 PRF produced %d bytes, need %d", len(keymat), MSKLen)
	}
	return keymat[:MSKLen], nil
}

// tls12PRF implements RFC 5246 PRF(SHA-256 or SHA-384 per suite):
// P_hash(master_secret, label || seed)[0:length]. strongSwan's TLS stack
// derives the PEAP MSK through its negotiated-suite PRF, which maps onto
// SHA-256 for all TLS 1.2 suites except the SHA-384 family.
func (e *Engine) tls12PRF(secret []byte, label string, seed []byte, length int) []byte {
	newHash := func() hash.Hash { return sha256.New() }
	if name := tls.CipherSuiteName(e.client.HandshakeState.ServerHello.CipherSuite); strings.Contains(name, "SHA384") {
		newHash = func() hash.Hash { return sha512.New384() }
	}
	seedWithLabel := make([]byte, 0, len(label)+len(seed))
	seedWithLabel = append(seedWithLabel, label...)
	seedWithLabel = append(seedWithLabel, seed...)

	out := make([]byte, 0, length)
	a := hmac.New(newHash, secret)
	a.Write(seedWithLabel) // A(1) = HMAC(secret, seed)
	for len(out) < length {
		sumA := a.Sum(nil)
		block := hmac.New(newHash, secret)
		block.Write(sumA)
		block.Write(seedWithLabel) // HMAC(secret, A(i) || seed)
		out = append(out, block.Sum(nil)...)
		a = hmac.New(newHash, secret)
		a.Write(sumA) // A(i+1) = HMAC(secret, A(i))
	}
	return out[:length]
}

// Close stops the relay worker and releases the TLS session.
func (e *Engine) Close() error {
	e.closeOnce.Do(func() {
		close(e.stop)
		_ = e.client.Close()
		_ = e.peer.Close()
		select {
		case <-e.done:
		case <-time.After(500 * time.Millisecond):
		}
		e.wg.Wait()
	})
	return nil
}

// launch starts the relay and drives the TLS handshake in one goroutine.
// The handshake goroutine's writes are mirrored by the relay; its reads are
// satisfied by Feed.
func (e *Engine) launch() error {
	e.handshakeDone = make(chan error, 1)
	e.started = true
	e.wg.Add(2)
	go e.relay()
	go func() {
		err := e.client.Handshake()
		if err == nil {
			e.established.Store(e.client.ConnectionState().HandshakeComplete)
		}
		e.handshakeDone <- err
	}()
	return nil
}

// relay pumps bytes between the TLS stack and the PEAP FSM:
//
//	client writes (peer end reads)  -> outbound queue -> Start/Feed/Protect
//	Feed inbound queue              -> peer end writes -> client reads
//
// net.Pipe is unbuffered, so without the relay the TLS client deadlocks on
// its first handshake write.
func (e *Engine) relay() {
	defer close(e.done)
	var pending [][]byte
	buf := make([]byte, 32*1024)
	for {
		// Prefer inbound delivery: a record waiting in the feed queue must
		// reach the TLS stack before new outbound is queued, otherwise the
		// client can stall in Read while its own writes fill the outbound
		// channel.
		for {
			select {
			case rec := <-e.inbound:
				if _, err := e.peer.Write(rec); err != nil {
					return
				}
				continue
			case <-e.stop:
				return
			default:
			}
			break
		}

		// Flush previously produced outbound when the FSM drains it.
		for len(pending) > 0 {
			select {
			case e.outbound <- pending[0]:
				pending = pending[1:]
			case <-e.stop:
				return
			default:
				goto readPeer
			}
		}

	readPeer:
		_ = e.peer.SetReadDeadline(time.Now().Add(relayPollInterval))
		n, err := e.peer.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			select {
			case e.outbound <- chunk:
			case <-e.stop:
				return
			default:
				if len(pending) >= 8 {
					select {
					case e.outbound <- chunk:
					case <-e.stop:
						return
					}
				} else {
					pending = append(pending, chunk)
				}
			}
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
	}
}

// collect waits for the first outbound TLS record (within waitFirst), then
// keeps draining with a short quiet window. It also observes handshake
// completion: a finished handshake ends collection immediately and reports
// the established flag and handshake error.
func (e *Engine) collect(waitFirst time.Duration) (out []byte, established bool, got bool, err error) {
	timer := time.NewTimer(waitFirst)
	defer timer.Stop()
	for {
		select {
		case chunk, ok := <-e.outbound:
			if !ok {
				err = io.ErrUnexpectedEOF
				return
			}
			out = append(out, chunk...)
			got = true
			resetTimer(timer, collectQuiet)
		case herr := <-e.handshakeDone:
			// Drains whatever the client's final flight produced.
			for {
				select {
				case chunk := <-e.outbound:
					out = append(out, chunk...)
					got = true
				default:
					if herr == nil {
						established = true
					}
					err = herr
					return
				}
			}
		case <-timer.C:
			select {
			case herr := <-e.handshakeDone:
				for {
					select {
					case chunk := <-e.outbound:
						out = append(out, chunk...)
						got = true
					default:
						if herr == nil {
							established = true
						}
						err = herr
						return
					}
				}
			default:
			}
			established = e.established.Load()
			return
		}
	}
}

// drainOutbound collects outbound TLS records until the queue stays quiet
// for the given settle duration. Used after Protect (application-data
// writes are plain writes; the TLS stack emits records immediately).
func (e *Engine) drainOutbound(settle time.Duration) ([]byte, error) {
	var out []byte
	timer := time.NewTimer(settle)
	defer timer.Stop()
	for {
		select {
		case chunk, ok := <-e.outbound:
			if !ok {
				return out, io.ErrUnexpectedEOF
			}
			out = append(out, chunk...)
			resetTimer(timer, settle)
		case <-timer.C:
			return out, nil
		}
	}
}

// readApplication reads all plaintext currently available from the
// established TLS session, using a short read deadline as the idle probe.
func (e *Engine) readApplication() ([]byte, error) {
	var plain []byte
	buf := make([]byte, 4096)
	first := true
	for {
		// The first read may have to wait for the relay to forward the record
		// fed by the caller; every later read only probes for more data.
		deadline := collectQuiet
		if first {
			deadline = time.Second
		}
		if err := e.client.SetReadDeadline(time.Now().Add(deadline)); err != nil {
			return plain, fmt.Errorf("swan/eap/peap: TLS read deadline: %w", err)
		}
		n, err := e.client.Read(buf)
		if n > 0 {
			plain = append(plain, buf[:n]...)
			first = false
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				_ = e.client.SetReadDeadline(time.Time{})
				return plain, nil
			}
			_ = e.client.SetReadDeadline(time.Time{})
			if err == io.EOF {
				return plain, nil
			}
			return plain, fmt.Errorf("swan/eap/peap: TLS unprotect: %w", err)
		}
	}
}

// normalizeServerName shapes an aaa_identity value into a TLS ServerName:
// trim whitespace, drop a leading '@', strip an optional ':port', and drop
// a trailing dot.
func normalizeServerName(name string) string {
	name = strings.TrimSpace(name)
	// swan2 uses trim_start_matches('@'): drop every leading '@', not just
	// one.
	name = strings.TrimLeft(name, "@")
	if host, _, err := net.SplitHostPort(name); err == nil && host != "" {
		name = host
	}
	name = strings.TrimSuffix(name, ".")
	return name
}

func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

// Exporter labels/context shared with debug output and tests.
const (
	ExportLabelRFC    = "EXPORTER_EAP_TLS_Key_Material"
	ExportLabelCompat = "client EAP encryption"
	ExportContextPEAP = 0x19 // eap method type, RFC 9190
	MSKLen            = 64
)
