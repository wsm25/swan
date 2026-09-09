// Package events is the single event hub for one session.
//
// The event stream reports control-plane transitions only. There are no
// per-packet events. On success the order on any single subscription is:
//
//	Starting -> HandshakeStarted
//	    -> [StageChanged | EapProcess | NegotiatedAlgorithm ...]
//	    -> HandshakeCompleted -> ConfigAssigned -> Started
//
// On shutdown or failure the terminal events are Stopping/Stopped, or
// Broken then Stopped for runtime failures.
//
// Delivery rules:
//
//   - Emit never blocks: if the hub mailbox is full the event is dropped.
//   - The hub never blocks on a subscriber: a subscriber whose buffered
//     channel is full simply misses that event; other subscribers still get
//     it. A slow or disconnected subscriber cannot stall protocol workers.
//   - A new subscriber first receives a replay of the last 16 retained
//     events, so a late listener can still observe HandshakeCompleted and
//     Started.
//   - EmitSync blocks until the hub goroutine has processed the event or
//     the hub is closing. The session uses it for the terminal Stopped
//     event so the hub can be closed right after it.
//   - Close drains the mailbox, releases pending Subscribe callers with
//     nil, and stops the hub goroutine. Races with Close stay non-blocking.
//
// One hub goroutine serializes delivery; Emit/Subscribe only enqueue
// mailbox messages.
package events
