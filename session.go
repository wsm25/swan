package swan

import (
	"context"
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
	espIn    chan *transport.Packet
	txFrames chan *transport.Frame
	pktIn    chan []byte
	pktOut   chan []byte

	// Layer actors. rx/tx are created per Start; control and hub are
	// created in NewSession.
	rx     *transport.RxWorker
	tx     *transport.TxWorker
	ctrl   *control.Control
	esp    *esp.Pipeline
	events *events.Hub

	// runCtx is the session-scoped context carried by every worker: it is
	// derived from a successful Start, and canceled once by Stop. It is the
	// single teardown switch for control, running and ESP workers.
	runCtx    context.Context
	cancelRun context.CancelFunc

	mu       sync.Mutex
	started  bool
	stopping bool
	tunnel   *Tunnel

	done     chan struct{}
	stopOnce sync.Once
	stopErr  error
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
		espIn:    make(chan *transport.Packet, c.Queue.Esp),
		txFrames: make(chan *transport.Frame, c.Queue.Data),
		pktIn:    make(chan []byte, c.Queue.Data),
		pktOut:   make(chan []byte, c.Queue.Data),
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
// handshake fails. On success the running workers stay alive and the caller
// receives the raw-IP io.ReadWriteCloser via the returned Tunnel.
func (s *Session) Start(ctx context.Context) (*Tunnel, error) {
	if s == nil {
		return nil, fmt.Errorf("swan: nil session")
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil, fmt.Errorf("swan: session already started")
	}
	if s.stopping {
		s.mu.Unlock()
		return nil, fmt.Errorf("swan: session is stopping")
	}
	s.mu.Unlock()

	s.emit(events.Event{Kind: events.EventStarting})
	s.emit(events.Event{Kind: events.EventHandshakeStarted})

	runCtx, cancel := context.WithCancel(context.Background())
	s.runCtx = runCtx
	s.cancelRun = cancel

	s.rx = transport.NewRxWorker(s.wire, s.ctlIn, s.espIn)
	s.tx = transport.NewTxWorker(s.wire, s.txFrames)
	go s.rx.Run()
	go s.tx.Run()

	est, err := s.ctrl.Run(runCtx, s.ctlIn, s.txFrames)
	if err != nil {
		// Terminal events (Broken/Stopped) already emitted by control's fail
		// path; emit them once only.
		_ = s.rx.Close()
		_ = s.tx.Close()
		waitDone(s.rx.Done(), 2*time.Second)
		waitDone(s.tx.Done(), 2*time.Second)
		cancel()
		return nil, err
	}

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
	s.esp = esp.NewPipeline(inbound, outbound, s.espIn, s.pktIn, s.pktOut, s.txFrames)
	go s.esp.Run(runCtx)

	s.emit(events.Event{Kind: events.EventHandshakeCompleted})
	s.emit(events.Event{Kind: events.EventConfigAssigned, Assigned: est.Assigned})
	s.emit(events.Event{Kind: events.EventStarted})

	t := &Tunnel{
		inbound:  s.pktOut,
		outbound: s.pktIn,
		assigned: est.Assigned,
		childSA:  est.Child,
		closed:   make(chan struct{}),
		done:     make(chan struct{}),
	}
	t.closeFn = func() error { return s.Stop(context.Background()) }

	s.mu.Lock()
	s.started = true
	s.tunnel = t
	s.mu.Unlock()
	return t, nil
}

// Stop shuts the running workers down. When the tunnel is active it first
// performs the best-effort DELETE sequence (CHILD_SA then IKE_SA). The
// injected wire is not closed.
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
	if !s.started && s.tunnel == nil && s.rx == nil {
		s.mu.Unlock()
		return nil
	}
	if s.stopping {
		// Defensive: only reachable if stopOnce was bypassed.
		s.mu.Unlock()
		return s.stopErr
	}
	s.stopping = true
	s.mu.Unlock()

	s.emit(events.Event{Kind: events.EventStopping})

	// Best-effort graceful close. The tx worker is still pumping the shared
	// write queue, then the control actor aborts on runCtx cancellation.
	if s.ctrl != nil {
		grace, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, _ = s.ctrl.Close(grace, s.txFrames)
		cancel()
	}

	if s.cancelRun != nil {
		s.cancelRun()
	}

	if s.rx != nil {
		_ = s.rx.Close()
	}
	if s.tx != nil {
		_ = s.tx.Close()
	}
	waitDone(s.rx.Done(), 2*time.Second)
	waitDone(s.tx.Done(), 2*time.Second)

	if s.esp != nil {
		waitDone(s.esp.Done(), 5*time.Second)
	}

	// Unblock and finish the tunnel surfaces, then close the consumer
	// channel only after the ESP workers have definitely stopped sending.
	s.mu.Lock()
	t := s.tunnel
	s.mu.Unlock()
	if t != nil {
		t.markEnded()
	}
	close(s.pktOut)

	s.emit(events.Event{Kind: events.EventStopped})
	close(s.done)
	return nil
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
	if ch == nil {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ch:
	case <-t.C:
	}
}
