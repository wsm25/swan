// Package events is the single event hub of a session.
//
// Semantics:
//
//   - Control-plane transitions only; there are no per-packet events.
//   - Success ordering is deterministic on every subscription:
//     Starting -> HandshakeStarted -> [stage/EAP/algorithm events ...] ->
//     HandshakeCompleted -> ConfigAssigned -> Started.
//   - Emitters never block: hub overflow degrades to dropping the event for
//     subscribers whose mailbox is full (the hub itself always accepts).
//   - New subscribers receive a replay of the last N retained events first,
//     so a late listener can still observe HandshakeCompleted/Started.
//   - Slow or disconnected subscribers cannot stall emitters, the hub or
//     the protocol workers.
//
// One hub goroutine serializes all delivery; Emit/Subscribe only enqueue
// mailbox messages.
package events

import "sync"

// Kind is the event type.
type Kind uint8

const (
	EventStarting Kind = iota
	EventHandshakeStarted
	EventStageChanged
	EventNegotiatedAlgorithm
	EventEapProcess
	EventHandshakeCompleted
	EventConfigAssigned
	EventStarted
	EventStopping
	EventStopped
	EventBroken
)

// Stage names a control-plane phase reported via EventStageChanged.
type Stage uint8

const (
	StageIKEInit Stage = iota
	StageIKEAuth
	StageEAP
	StageChildSA
	StageRunning
)

// NegotiatedAlgorithm pairs with EventNegotiatedAlgorithm. Only fields
// relevant to the reported protocol are non-empty (ESP has no PRF/DH).
type NegotiatedAlgorithm struct {
	Protocol   string // "ike" | "esp"
	Encryption string
	Integrity  string
	PRF        string
	DH         string
}

// EapProcess pairs with EventEapProcess: one per EAP request/response round
// plus started/completed markers.
type EapProcess struct {
	Method string
	State  string
	Round  uint16
}

// Event is one control-plane transition. Exactly the fields relevant to
// Kind are populated:
//
//	StageChanged         -> Stage
//	NegotiatedAlgorithm  -> Alg
//	EapProcess           -> EAP
//	ConfigAssigned       -> Assigned (control.AssignedConfig value)
//	Broken               -> Reason
type Event struct {
	Kind  Kind
	Stage Stage
	Alg   NegotiatedAlgorithm
	EAP   EapProcess
	// Assigned carries the CP configuration on EventConfigAssigned.
	Assigned any
	Reason   string
}

// DefaultReplayHistory is the number of retained events replayed to new
// subscribers (swan2 EventHub keeps 16).
const DefaultReplayHistory = 16

// hubMailboxCapacity bounds Emit-side enqueues. Senders are non-blocking,
// so overflow drops the event before anyone can be stalled.
const hubMailboxCapacity = 256

// Hub fans events out to subscribers. Emit is non-blocking; the single hub
// goroutine preserves emitter ordering (FIFO mailbox).
type Hub struct {
	// mailbox receives emit/subscribe/unsubscribe requests.
	mailbox chan hubReq
	// queue is the per-subscriber channel capacity. It is always >= the
	// replay history so Subscribe can preload the replay non-blockingly.
	queue int
	// retained is the replay ring (oldest first) for new subscribers.
	retained []Event
	// subs are live subscribers; a full sub channel is skipped (drop).
	subs []*Stream

	// stopped signals the worker to drain and exit; closed at most once.
	stopped chan struct{}
	once    sync.Once
}

// hubReq is one mailbox request. Exactly one discriminator field is used:
//
//	isEmit        => deliver event to every subscriber
//	reply != nil  => subscribe: return a Stream preloaded with the replay
//	stream != nil => unsubscribe: drop the subscriber reference
//	done != nil   => synchronous emit: closed once the event was processed
//	                (delivered or dropped by mailbox overflow)
type hubReq struct {
	event  Event
	reply  chan *Stream
	stream *Stream
	isEmit bool
	done   chan struct{}
}

// NewHub builds the hub and starts its goroutine. queue is the per
// subscriber mailbox size; replay is the retained history length.
func NewHub(queue, replay int) *Hub {
	if replay < 0 {
		replay = 0
	}
	// Replay delivery happens while the hub goroutine still owns the new
	// stream; buffering every replayed event guarantees it never blocks.
	if queue < replay {
		queue = replay
	}
	if queue <= 0 {
		queue = 1
	}
	h := &Hub{
		mailbox:  make(chan hubReq, hubMailboxCapacity),
		queue:    queue,
		retained: make([]Event, 0, replay),
		stopped:  make(chan struct{}),
	}
	go h.run()
	return h
}

func (h *Hub) run() {
	for {
		select {
		case <-h.stopped:
			h.drain()
			return
		case req := <-h.mailbox:
			h.handle(req)
		}
	}
}

func (h *Hub) handle(req hubReq) {
	if req.done != nil {
		defer close(req.done)
	}
	switch {
	case req.isEmit:
		h.dispatch(req.event)
	case req.stream != nil:
		h.removeSub(req.stream)
	default:
		h.subscribe(req.reply)
	}
}

// dispatch retains the event and fans it out to every healthy subscriber.
// Delivery is FIFO: each full subscriber channel drops this one event
// without affecting the others.
func (h *Hub) dispatch(ev Event) {
	h.retain(ev)
	for i := 0; i < len(h.subs); i++ {
		s := h.subs[i]
		select {
		case <-s.closed:
			h.removeSub(s)
			i--
			continue
		default:
		}
		select {
		case s.c <- ev:
		default:
			// Full subscriber channel: drop for this subscription only.
		}
	}
}

// retain keeps the last cap(h.retained) events in FIFO order, shifting the
// ring left when it is already full.
func (h *Hub) retain(ev Event) {
	if cap(h.retained) == 0 {
		return
	}
	if len(h.retained) == cap(h.retained) {
		copy(h.retained, h.retained[1:])
		h.retained[len(h.retained)-1] = ev
		return
	}
	h.retained = append(h.retained, ev)
}

// subscribe creates the stream, preloads the replay history, registers the
// subscriber and finally releases the waiter. Replay and later live events
// can never duplicate: live events are only events dispatched after this
// mailbox request.
func (h *Hub) subscribe(reply chan *Stream) {
	s := &Stream{
		c:      make(chan Event, h.queue),
		closed: make(chan struct{}),
		hub:    h,
		once:   sync.Once{},
	}
	for _, ev := range h.retained {
		s.c <- ev
	}
	h.subs = append(h.subs, s)
	reply <- s
}

// removeSub releases one subscriber reference. The stream may keep its own
// buffered events; the hub simply stops writing to it.
func (h *Hub) removeSub(s *Stream) {
	for i, sub := range h.subs {
		if sub == s {
			h.subs = append(h.subs[:i], h.subs[i+1:]...)
			return
		}
	}
}

// drain empties the mailbox after a stop request: plain events are dropped
// and every pending Subscribe waiter is released with a nil stream so no
// caller blocks forever.
func (h *Hub) drain() {
	for {
		select {
		case req := <-h.mailbox:
			if req.reply != nil {
				req.reply <- nil
			}
		default:
			return
		}
	}
}

// Emit publishes one event; it never blocks on subscribers or the hub.
// When the hub mailbox is full the event is dropped entirely.
func (h *Hub) Emit(e Event) {
	if h == nil {
		return
	}
	select {
	case h.mailbox <- hubReq{event: e, isEmit: true}:
	default:
		// Hub mailbox saturated: drop rather than stall a protocol worker.
	}
}

// EmitSync publishes one event and blocks until the hub worker has
// processed it (delivered it to every subscriber's mailbox or dropped it
// because a mailbox was full). Returns false if the hub is shutting down.
// Used for terminal events so teardown can close the hub right after.
func (h *Hub) EmitSync(e Event) bool {
	if h == nil {
		return false
	}
	done := make(chan struct{})
	select {
	case h.mailbox <- hubReq{event: e, isEmit: true, done: done}:
	case <-h.stopped:
		return false
	}
	select {
	case <-done:
		return true
	case <-h.stopped:
		return false
	}
}

// Subscribe registers a new stream: the caller first receives the replay
// history, then live events (no duplicates). Subscriptions may be closed
// freely; disconnect never affects the hub. After Hub.Close a subscription
// returns nil and never blocks, including the linearization window where
// the mailbox send and the hub shutdown race.
func (h *Hub) Subscribe() *Stream {
	if h == nil {
		return nil
	}
	reply := make(chan *Stream, 1)
	select {
	case <-h.stopped:
		return nil
	default:
	}
	select {
	case h.mailbox <- hubReq{reply: reply}:
	case <-h.stopped:
		// The hub worker may still drain our request; never leave the
		// reply channel unconsumed.
		select {
		case s := <-reply:
			return s
		default:
			return nil
		}
	}
	select {
	case s := <-reply:
		return s
	case <-h.stopped:
		select {
		case s := <-reply:
			return s
		default:
			return nil
		}
	}
}

// Close drains the mailbox and stops the hub goroutine. Emitters and
// subscribers racing with Close remain non-blocking; pending Subscribe
// callers receive nil.
func (h *Hub) Close() error {
	if h == nil {
		return nil
	}
	h.once.Do(func() { close(h.stopped) })
	return nil
}

// Stream is one subscriber's event channel.
type Stream struct {
	c      chan Event
	closed chan struct{}
	hub    *Hub
	once   sync.Once
}

// C returns the delivery channel. When the mailbox overflows the hub drops
// events for this subscription only; the stream itself stays valid.
func (s *Stream) C() <-chan Event {
	return s.c
}

// Close unsubscribes the stream and releases the hub's reference. It is
// safe to call multiple times and after Hub.Close.
func (s *Stream) Close() error {
	if s != nil {
		s.once.Do(func() {
			close(s.closed)
			if s.hub != nil {
				s.hub.unsubscribe(s)
			}
		})
	}
	return nil
}

// unsubscribe asks the hub worker to release this stream. If the mailbox is
// saturated the request is dropped; the next dispatch lazily removes closed
// streams, so the reference is released no later than the next event.
func (h *Hub) unsubscribe(s *Stream) {
	select {
	case h.mailbox <- hubReq{stream: s}:
	default:
	}
}
