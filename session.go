package swan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"swan/control"
	"swan/esp"
	"swan/events"
	"swan/transport"
	"swan/wire/payload"
	"swan/xcrypto"
)

// Session assembles all layers around one injected stream wire and drives
// one IKEv2 initiator handshake plus the subsequent running state.
//
// The library never opens sockets and never closes the supplied wire:
// shutdown only stops workers and stops reading/writing it; ownership stays
// with the caller.
//
// Lifecycle guarantees:
//
//   - Start's ctx is the session lifetime: canceling it tears the running
//     session down exactly like Stop does.
//   - Any transport failure (read error, writer error) while the session
//     is running emits Broken and tears the session down; the caller wakes
//     on Done and Tunnel.Done.
//   - A peer-initiated IKE_SA delete tears the session down cleanly without
//     a Broken event; a peer CHILD_SA delete stops the ESP data plane.
type Session struct {
	wire io.ReadWriteCloser
	cfg  Config
	opts options

	// Dual-role identity atoms, normalized once in NewSession.
	idi     payload.ID
	rightID payload.ID

	// Channels between layers, created once so a failed Start can retry on
	// the same hub. They are never closed by the facade; workers exit on
	// the session context instead.
	ctlIn    chan *transport.Packet
	espIn    chan []*transport.Packet
	txFrames chan *transport.Frame
	pktIn    chan []byte
	pktOut   chan []esp.InboundPacket

	// Layer actors. rx/tx are created per Start; control and hub are
	// created in NewSession.
	rx     *transport.RxWorker
	tx     *transport.TxWorker
	ctrl   *control.Control
	esp    *esp.Pipeline
	events *events.Hub

	// runCtx is the session-scoped context carried by every worker: it is
	// derived from Start's ctx, and canceled once by Stop. It is the
	// single teardown switch for control, running and ESP workers.
	runCtx    context.Context
	cancelRun context.CancelFunc

	// runningDone closes when the control Running actor has exited. Stop
	// waits on it before the sole remaining State owner (the close
	// sequence) mutates the shared state.
	runningDone chan struct{}

	mu       sync.Mutex
	started  bool
	starting bool
	stopping bool
	tunnel   *Tunnel

	done       chan struct{}
	stopOnce   sync.Once
	stopErr    error
	brokenOnce sync.Once
}

// NewSession validates cfg, builds the inter-layer channels and the
// control-plane actors, but performs no IO until Start.
func NewSession(wire io.ReadWriteCloser, cfg *Config, opts ...Option) (*Session, error) {
	if wire == nil {
		return nil, fmt.Errorf("swan: nil wire")
	}
	if cfg == nil {
		return nil, fmt.Errorf("swan: nil config")
	}

	o := options{}
	for _, apply := range opts {
		if apply == nil {
			continue
		}
		if err := apply(&o); err != nil {
			return nil, err
		}
	}

	c := *cfg
	if o.queueSizes != nil {
		c.Queue = *o.queueSizes
	}
	if o.timeouts != nil {
		c.Timeouts = *o.timeouts
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}

	idi, err := payload.ClassifyID(c.IDI)
	if err != nil {
		return nil, fmt.Errorf("swan: classify IDI %q: %w", c.IDI, err)
	}

	right := c.RightID
	if right == "%any" || right == "*" {
		right = ""
	}
	var rightID payload.ID
	if right != "" {
		rightID, err = payload.ClassifyID(right)
		if err != nil {
			return nil, fmt.Errorf("swan: classify RightID %q: %w", c.RightID, err)
		}
	}

	hub := events.NewHub(c.Queue.Events, events.DefaultReplayHistory)
	s := &Session{
		wire:     wire,
		cfg:      c,
		opts:     o,
		idi:      idi,
		rightID:  rightID,
		events:   hub,
		ctlIn:    make(chan *transport.Packet, c.Queue.Ctl),
		espIn:    make(chan []*transport.Packet, c.Queue.Esp),
		txFrames: make(chan *transport.Frame, c.Queue.Data),
		pktIn:    make(chan []byte, c.Queue.Data),
		pktOut:   make(chan []esp.InboundPacket, c.Queue.Data),
		done:     make(chan struct{}),
	}

	ctrlCfg := s.controlConfig()
	s.ctrl, err = control.New(ctrlCfg, hub)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// controlConfig decomposes the public Config into the control-layer config.
func (s *Session) controlConfig() *control.Config {
	c := s.cfg
	eapCfg := c.EAP
	if eapCfg.ServerName == "" && c.AAAIdentity != "" {
		eapCfg.ServerName = c.AAAIdentity
	}
	if c.InsecureSkipPeerCertVerify {
		eapCfg.InsecureSkipVerify = true
	}
	return &control.Config{
		PeerIP:                     append(net.IP(nil), c.PeerIP...),
		LocalIP:                    append(net.IP(nil), c.LocalIP...),
		IKE:                        append([]xcrypto.Proposal(nil), c.IKEProposals...),
		ESP:                        append([]xcrypto.Proposal(nil), c.ESPProposals...),
		IDI:                        s.idi,
		RightID:                    s.rightID,
		AAAIdentity:                firstNonEmpty(c.AAAIdentity, eapCfg.ServerName),
		EAP:                        eapCfg,
		InsecureSkipPeerCertVerify: c.InsecureSkipPeerCertVerify,
		StrongswanCompatible:       eapCfg.StrongswanCompatible,
		Timeouts: control.Timeouts{
			InitialRTO:           c.Timeouts.InitialRTO,
			MaxRTO:               c.Timeouts.MaxRTO,
			MaxRetries:           c.Timeouts.MaxRetries,
			SkfReassemblyTimeout: c.Timeouts.SkfReassemblyTimeout,
		},
		FragmentPlaintextLimit: 1024,
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Start drives the initiator flow to completion:
//
//	IKE_SA_INIT (cookie/invalid-KE retries) -> IKE key derivation ->
//	bootstrap IKE_AUTH -> EAP loop -> final IKE_AUTH/CHILD_SA -> Running
//
// It blocks until the tunnel is established, the context is canceled, or the
// handshake fails. The supplied ctx becomes the session lifetime: canceling
// it later tears the running session down like Stop. On success the running
// workers stay alive and the caller receives the raw-IP io.ReadWriteCloser
// via the returned Tunnel.
func (s *Session) Start(ctx context.Context) (*Tunnel, error) {
	if s == nil {
		return nil, fmt.Errorf("swan: nil session")
	}
	s.mu.Lock()
	if s.started || s.starting {
		s.mu.Unlock()
		return nil, fmt.Errorf("swan: session already started")
	}
	if s.stopping {
		s.mu.Unlock()
		return nil, fmt.Errorf("swan: session is stopping")
	}
	s.starting = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.starting = false
		s.mu.Unlock()
	}()

	s.emit(events.Event{Kind: events.EventStarting})
	s.emit(events.Event{Kind: events.EventHandshakeStarted})

	// Install the pre-handshake actors under the mutex so a concurrent
	// Stop can neither miss them (leaked workers) nor observe them half-
	// initialized.
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return nil, fmt.Errorf("swan: session is stopping")
	}
	runCtx, cancel := context.WithCancel(ctx)
	rx := transport.NewRxWorker(s.wire, s.ctlIn, s.espIn)
	tx := transport.NewTxWorker(s.wire, s.txFrames)
	s.runCtx = runCtx
	s.cancelRun = cancel
	s.rx = rx
	s.tx = tx
	s.mu.Unlock()

	go rx.Run()
	go tx.Run()
	go s.monitorTransport(rx, tx)

	est, err := s.ctrl.Run(runCtx, s.ctlIn, s.txFrames)
	if err != nil {
		cancel()
		_ = rx.Close()
		_ = tx.Close()
		waitDone(rx.Done(), 2*time.Second)
		waitDone(tx.Done(), 2*time.Second)
		return nil, err
	}

	// A concurrent Stop may have arrived during the handshake: it snapped
	// the pre-handshake actors, canceled the context (ctrl.Run failing with
	// ctx.Err above normally), and it owns the teardown. Refuse to commit
	// any post-handshake state in that case.
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		cancel()
		_ = rx.Close()
		_ = tx.Close()
		waitDone(rx.Done(), 2*time.Second)
		waitDone(tx.Done(), 2*time.Second)
		return nil, fmt.Errorf("swan: session stopped during handshake")
	}

	espFatal := make(chan error, 1)
	inbound := esp.NewInbound(esp.InboundConfig{
		SPI:       est.Child.InboundSPI,
		Selection: est.Selection,
		Keys:      est.ChildKeys,
	})
	outbound := esp.NewOutbound(esp.OutboundConfig{
		SPI:       est.Child.OutboundSPI,
		Selection: est.Selection,
		Keys:      est.ChildKeys,
	})
	pipeline := esp.NewPipeline(inbound, outbound, s.espIn, s.pktIn, s.pktOut, s.txFrames, est.ChildClosed, espFatal)
	t := &Tunnel{
		inbound:  s.pktOut,
		outbound: s.pktIn,
		assigned: est.Assigned,
		childSA:  est.Child,
		closed:   make(chan struct{}),
		done:     make(chan struct{}),
	}
	t.closeFn = func() error { return s.Stop(context.Background()) }
	runningDone := make(chan struct{})

	// Commit the running state under the same mutex Stop snapshots from,
	// and enqueue the success sequence while still holding it: Emit is
	// non-blocking and the hub mailbox is FIFO, so a concurrent Stop that
	// wins the mutex right after this point can only queue its Events
	// after HandshakeCompleted/ConfigAssigned/Started.
	s.esp = pipeline
	s.runningDone = runningDone
	s.tunnel = t
	s.started = true
	s.emit(events.Event{Kind: events.EventHandshakeCompleted})
	s.emit(events.Event{Kind: events.EventConfigAssigned, Assigned: est.Assigned})
	s.emit(events.Event{Kind: events.EventStarted})
	est.Arm()
	s.mu.Unlock()

	go pipeline.Run(runCtx)
	go s.watchRunning(est.Terminated, runningDone)
	go s.watchDataFatal(espFatal)
	// A peer CHILD_SA delete ends the tunnel surface (Read returns EOF,
	// Write returns ErrClosedPipe) while the IKE SA keeps its keepalive
	// cadence.
	go s.watchChildClosed(est.ChildClosed, t)

	return t, nil
}

// watchDataFatal converts the data plane's fatal error (e.g. ESP sequence
// wrap after 2^32-1 packets) into Broken + full teardown instead of a
// silent data-plane blackhole.
func (s *Session) watchDataFatal(fatal <-chan error) {
	var err error
	select {
	case err = <-fatal:
	case <-s.done:
		return
	}
	if err != nil {
		s.fail(sessionErr(err.Error()))
	}
}

// watchChildClosed marks the tunnel surface ended when the peer deletes the
// active CHILD_SA; the IKE SA itself stays up.
func (s *Session) watchChildClosed(child <-chan struct{}, t *Tunnel) {
	select {
	case <-child:
	case <-s.done:
		return
	}
	if t != nil {
		t.markEnded()
	}
}

// monitorTransport observes one Start generation's rx/tx runners until one
// terminates; the pointers come in as arguments so a later Start retry
// cannot race the field reads. If the session is already started (handshake
// succeeded) and not stopping, the injected transport failed underneath us:
// emit Broken and tear down.
func (s *Session) monitorTransport(rx *transport.RxWorker, tx *transport.TxWorker) {
	select {
	case <-rx.Done():
	case <-tx.Done():
	}
	s.mu.Lock()
	live := s.started && !s.stopping
	s.mu.Unlock()
	if !live {
		return
	}
	s.fail(sessionErr("transport worker stopped unexpectedly"))
}

// watchRunning consumes the single Running exit value, closes runningDone
// for Stop's teardown ordering, and translates the outcome:
//
//	nil            -> peer deleted the IKE SA: clean shutdown, no Broken
//	ctx.Err()      -> session-driven teardown: nothing further to do
//	other error    -> fatal: Broken (already emitted by Running.fail's
//	                  caller paths if applicable; deduped) then shutdown
//
// One read total: runningDone closes with this goroutine's first
// observation, so Stop's bounded wait cannot double-consume.
func (s *Session) watchRunning(terminated <-chan error, runningDone chan struct{}) {
	err, ok := <-terminated
	if !ok {
		err = errors.New("control: running actor terminated without a result")
	}
	close(runningDone)
	switch {
	case err == nil:
		_ = s.Stop(context.Background())
	case errors.Is(err, context.Canceled):
		// Start's ctx was canceled by the caller (or our own Stop already
		// runs). If teardown is not in flight, finish it exactly like Stop
		// so Done/Tunnel.Done/Stopped/hub are all released.
		s.mu.Lock()
		stopping := s.stopping
		s.mu.Unlock()
		if !stopping {
			_ = s.Stop(context.Background())
		}
	default:
		s.fail(sessionErr(err.Error()))
	}
}

// fail emits Broken exactly once and triggers teardown. It is the single
// path for transport/control runtime failures; user-initiated Stop never
// emits Broken.
func (s *Session) fail(err error) {
	s.mu.Lock()
	stopping := s.stopping
	s.mu.Unlock()
	if stopping {
		return
	}
	s.brokenOnce.Do(func() {
		s.emit(events.Event{Kind: events.EventBroken, Reason: err.Error()})
	})
	_ = s.Stop(context.Background())
}

// Stop shuts the running workers down. When the tunnel is active it first
// performs the best-effort DELETE sequence (CHILD_SA then IKE_SA). The
// injected wire is not closed: if the backend is currently blocked in Read
// it may yield later, and only the caller can unblock it by closing the
// wire (workers observe the error then and exit).
func (s *Session) Stop(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.stopOnce.Do(func() {
		s.stopErr = s.stop(ctx)
	})
	return s.stopErr
}

func (s *Session) stop(ctx context.Context) error {
	s.mu.Lock()
	neverStarted := !s.started && s.tunnel == nil && s.rx == nil
	if neverStarted {
		// Terminal: a Stop before Start consumes the lifecycle once, and a
		// later Start must fail ("session is stopping") instead of running
		// workers that a later Stop could no longer reach.
		s.stopping = true
		s.mu.Unlock()
		if s.events != nil {
			s.events.EmitSync(events.Event{Kind: events.EventStopped})
		}
		close(s.done)
		s.closeHub()
		return nil
	}
	if s.stopping {
		// Defensive: only reachable if stopOnce was bypassed.
		s.mu.Unlock()
		return s.stopErr
	}
	s.stopping = true

	// Snapshot every actor under the mutex; all teardown below works on
	// the snapshot so a concurrent Start commit can never race us.
	cancel := s.cancelRun
	rx := s.rx
	tx := s.tx
	esp := s.esp
	runningDone := s.runningDone
	t := s.tunnel
	s.mu.Unlock()

	s.emit(events.Event{Kind: events.EventStopping})

	// Unblock and finish the tunnel surfaces first: Writes after this point
	// fail deterministically, Reads drain what is buffered and then EOF.
	if t != nil {
		t.markEnded()
	}

	// Cancel first so the Running actor (ctx-aware sends) and ESP workers
	// park; then wait for Running. Only after Running has provably exited
	// does the close sequence mutate the shared State — the handoff point
	// that keeps teardown race-free with the live control actor. When the
	// handshake was still in flight (no runningDone), skip the graceful
	// close entirely: Start owns the State until it returns.
	if cancel != nil {
		cancel()
	}
	runningExited := waitDoneResult(runningDone, 2*time.Second)

	// Best-effort graceful close. The tx worker is still pumping the shared
	// write queue; with Running exited the state belongs to this goroutine.
	if runningExited && s.ctrl != nil {
		grace, cancelGrace := context.WithTimeout(ctx, 5*time.Second)
		_, _ = s.ctrl.Close(grace, s.txFrames)
		cancelGrace()
	}

	if rx != nil {
		_ = rx.Close()
	}
	if tx != nil {
		_ = tx.Close()
	}
	waitDone(rx.Done(), 2*time.Second)
	waitDone(tx.Done(), 2*time.Second)

	if esp != nil {
		waitDone(esp.Done(), 5*time.Second)
	}

	// The ESP inbound worker has provably stopped producing: drain whatever
	// batches are still buffered and release each pooled plaintext so
	// teardown cannot leak inbound backings.
	for {
		select {
		case batch := <-s.pktOut:
			for _, pkt := range batch {
				pkt.Release()
			}
			continue
		default:
		}
		break
	}

	// Close the consumer channel only after the ESP inbound worker has
	// definitely stopped sending.
	close(s.pktOut)

	if s.events != nil {
		s.events.EmitSync(events.Event{Kind: events.EventStopped})
	}
	close(s.done)
	s.closeHub()
	return nil
}

// closeHub stops the event hub goroutine after the terminal Stopped event
// has been handled.
func (s *Session) closeHub() {
	if s.events != nil {
		_ = s.events.Close()
	}
}

// Events returns a new subscription on the session event hub. Subscribers
// may be slow or disconnect freely; the hub never blocks on them and replays
// the last N events to newcomers.
func (s *Session) Events() *events.Stream {
	if s == nil || s.events == nil {
		return nil
	}
	return s.events.Subscribe()
}

// Done is closed when the whole session (handshake + running state) has
// terminated. It never signals per-packet conditions.
func (s *Session) Done() <-chan struct{} {
	if s == nil {
		d := make(chan struct{})
		close(d)
		return d
	}
	return s.done
}

func (s *Session) emit(ev events.Event) {
	if s == nil || s.events == nil {
		return
	}
	s.events.Emit(ev)
}

func waitDone(ch <-chan struct{}, d time.Duration) {
	waitDoneResult(ch, d)
}

// waitDoneResult waits for ch up to d and reports whether ch actually
// closed within the bound (nil ch or timeout => false).
func waitDoneResult(ch <-chan struct{}, d time.Duration) bool {
	if ch == nil {
		return false
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ch:
		return true
	case <-t.C:
		return false
	}
}

type sessionErr string

func (e sessionErr) Error() string { return "swan: " + string(e) }
