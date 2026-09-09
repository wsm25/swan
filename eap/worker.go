package eap

import (
	"context"
	"fmt"
)

// Round is one work item for the eap worker: the inbound EAP packet plus a
// reply mailbox. Reply is always sent exactly once (value or error), which
// keeps the strict FIFO handshake between the control layer and the method
// FSM simple.
type Round struct {
	Packet []byte
	ID     uint16 // IKE_AUTH message-id of the round (for logs/events)

	// Reply returns the method step result or the failure. A Round whose
	// Packet is nil signals Initialize; a Round with nil Reply is invalid.
	Reply chan<- RoundResult
}

// RoundResult carries either the step result or an error for one Round.
type RoundResult struct {
	Result
	Err error
}

// Worker owns one Method instance, runs its FSM and answers Rounds in
// mailbox order. It is the only goroutine allowed to call the Method and is
// deliberately I/O-free: all packet bytes arrive through the mailbox.
type Worker struct {
	method Method
	rounds <-chan Round

	done chan struct{}
}

// NewWorker binds a freshly built (or reset) Method to the mailbox.
func NewWorker(method Method, rounds <-chan Round) *Worker {
	if method == nil {
		panic("swan/eap: NewWorker requires a non-nil method")
	}
	return &Worker{
		method: method,
		rounds: rounds,
		done:   make(chan struct{}),
	}
}

// Run initializes the method, then serves rounds until ctx is done or the
// mailbox closes. Completion (ActionComplete) is reported through the reply
// mailbox of the triggering Round; the worker keeps running and would fail
// subsequent Rounds — the control layer only sends until completion.
func (w *Worker) Run(ctx context.Context) error {
	defer close(w.done)

	if err := w.method.Initialize(); err != nil {
		return fmt.Errorf("swan/eap: initialize %s: %w", w.method.Name(), err)
	}

	completed := false
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case round, ok := <-w.rounds:
			if !ok {
				return nil
			}
			if round.Reply == nil {
				continue
			}

			// A nil Packet is the re-initialize signal documented on
			// Round. The acknowledgment is a zero Result: the control
			// layer treats it as a readiness ack, not as a send action.
			if round.Packet == nil {
				if err := w.method.Initialize(); err != nil {
					round.Reply <- RoundResult{Err: err}
				} else {
					round.Reply <- RoundResult{}
				}
				continue
			}

			if completed {
				round.Reply <- RoundResult{
					Err: fmt.Errorf("swan/eap: method %s already completed", w.method.Name()),
				}
				continue
			}

			result, err := w.method.Handle(round.Packet, round.ID)
			if err != nil {
				round.Reply <- RoundResult{Err: err}
				continue
			}
			round.Reply <- RoundResult{Result: result}
			if result.Action == ActionComplete {
				completed = true
				// Release per-session method resources (e.g. the PEAP TLS
				// engine) as soon as the method cannot produce more steps.
				_ = w.method.Close()
			}
		}
	}
}

// Done is closed when Run has exited.
func (w *Worker) Done() <-chan struct{} {
	return w.done
}
