package control

import (
	"context"
	"fmt"
	"time"

	"swan/eap"
	"swan/eap/methods"
	"swan/events"
	"swan/transport"
	"swan/wire"
)

// EapPeer is the mailbox bridge between the linear handshake worker and the
// separate eap worker goroutine. The eap worker owns the method FSM; the
// bridge only knows how to carry one complete IKE_AUTH exchange per EAP
// round (receive protected response -> extract EAP -> answer via a new
// protected request).
type EapPeer struct {
	// h is the owning handshake (per-round exchange mechanics).
	h   *Handshake
	ctx context.Context
	tx  chan<- *transport.Frame
	in  <-chan *transport.Packet

	// worker serializes method Handle calls and answers each eap.Round
	// exactly once. It is a private copy of eap.Worker's loop with one
	// difference: method initialization is acknowledged synchronously, so
	// the handshake fails immediately instead of blocking on a dead worker
	// when swan/eap Initialize errors.
	worker *eapPeerWorker
	// rounds carries one eap.Round request to the eap worker at a time.
	// The worker serializes Handle calls and always answers once per Round.
	rounds chan eap.Round
	// methodName is captured at start for progress events.
	methodName string
	// firstResponse flips off after the bootstrap IKE_AUTH response so the
	// first-response-only checks (AUTH-vs-EAP) run exactly once.
	firstResponse bool
	round         uint16
}

// maxEAPRounds bounds the EAP loop so a broken peer can never make the
// handshake spin forever (swan2 has an equivalent message-count guard).
const maxEAPRounds = 64

// eapPeerWorker is the control-side EAP worker: it owns one method instance
// and processes rounds in mailbox order. Run must be started before
// waitInit is called.
type eapPeerWorker struct {
	method eap.Method
	rounds <-chan eap.Round

	done     chan struct{}
	initDone chan error
}

func newEAPPeerWorker(method eap.Method, rounds <-chan eap.Round) *eapPeerWorker {
	return &eapPeerWorker{
		method:   method,
		rounds:   rounds,
		done:     make(chan struct{}),
		initDone: make(chan error, 1),
	}
}

// Done is closed when run has exited.
func (w *eapPeerWorker) Done() <-chan struct{} {
	return w.done
}

// waitInit blocks until method initialization has succeeded (nil) or failed.
func (w *eapPeerWorker) waitInit() error {
	return <-w.initDone
}

func (w *eapPeerWorker) run(ctx context.Context) {
	defer close(w.done)

	if err := w.method.Initialize(); err != nil {
		w.initDone <- fmt.Errorf("swan/control: initialize eap method %s: %w", w.method.Name(), err)
		return
	}
	close(w.initDone)

	completed := false
	for {
		select {
		case <-ctx.Done():
			return
		case round, ok := <-w.rounds:
			if !ok {
				return
			}
			if round.Reply == nil {
				continue
			}
			// A nil Packet is the re-initialize signal documented on
			// eap.Round. The acknowledgment is a zero Result (not a send
			// action). The EAP loop below never sends nil rounds; this
			// branch only keeps the local worker compatible with eap.Worker.
			if round.Packet == nil {
				if err := w.method.Initialize(); err != nil {
					round.Reply <- eap.RoundResult{Err: err}
				} else {
					round.Reply <- eap.RoundResult{}
				}
				continue
			}

			if completed {
				round.Reply <- eap.RoundResult{
					Err: fmt.Errorf("swan/control: eap method %s already completed", w.method.Name()),
				}
				continue
			}

			result, err := w.method.Handle(round.Packet, round.ID)
			if err != nil {
				round.Reply <- eap.RoundResult{Err: err}
				continue
			}
			round.Reply <- eap.RoundResult{Result: result}
			if result.Action == eap.ActionComplete {
				completed = true
			}
		}
	}
}

// start builds the method once, spawns the eap worker and waits for the
// method to initialize (swan2 eap_method.run -> initialize before the first
// recv_request).
func (p *EapPeer) start(ctx context.Context) error {
	method, err := methods.New(&p.h.cfg.EAP)
	if err != nil {
		return fmt.Errorf("control: build eap method: %w", err)
	}
	rounds := make(chan eap.Round, 2)
	worker := newEAPPeerWorker(method, rounds)
	go worker.run(ctx)
	if err := worker.waitInit(); err != nil {
		return err
	}

	p.ctx = ctx
	p.worker = worker
	p.rounds = rounds
	p.methodName = method.Name()
	p.firstResponse = true
	p.round = 0
	return nil
}

// recv performs one IKE_AUTH exchange round: receive the protected
// response, process its payloads and return the extracted EAP packet.
func (p *EapPeer) recv() ([]byte, error) {
	if !p.h.state.HasExpectedResponse {
		return nil, fmt.Errorf("control: missing expected IKE_AUTH response message-id")
	}
	msgID := p.h.state.ExpectedResponseMessageID
	msg, _, err := p.h.recvProtectedPayloads(p.ctx, p.in, p.tx, wire.ExchangeIkeAuth, msgID, "eap")
	if err != nil {
		return nil, err
	}
	eapPayload, err := p.h.handleAuthResponse(msg, p.firstResponse)
	p.firstResponse = false
	if err != nil {
		return nil, err
	}
	p.round++
	if len(eapPayload) == 0 {
		return nil, fmt.Errorf("control: IKE_AUTH response missing EAP payload (round %d)", p.round)
	}
	// swan2 RoutineEapPeer::recv_request emits the request mark after the
	// protected response has been accepted and processed, keyed by the
	// IKE_AUTH message-id that carried this round.
	if p.h.events != nil {
		p.h.events.Emit(events.Event{
			Kind: events.EventEapProcess,
			EAP:  events.EapProcess{Method: p.methodName, State: "request", Round: uint16(msgID)},
		})
	}
	return eapPayload, nil
}

// send wraps one EAP response into a protected IKE_AUTH request, sends it
// (remembered as the retransmission checkpoint) and returns the request
// message-id used for the progress event.
func (p *EapPeer) send(data []byte) (uint32, error) {
	inner := cepSinglePayload(data)
	msgID := p.h.beginRequest()
	frames, err := p.h.buildProtected(wire.ExchangeIkeAuth, msgID, wire.PayloadTypeEAP, inner)
	if err != nil {
		return 0, err
	}
	if err := p.h.sendRequest(p.ctx, p.tx, frames); err != nil {
		return 0, err
	}
	return msgID, nil
}

// runEAP is the linear EAP loop: set the AuthEAPInProgress phase, start the
// worker, then alternate recv/handle/send until the method completes and
// exports the MSK. The MSK lands in state.Auth.LocalEAPMSK for the final
// AUTH.
func (h *Handshake) runEAP(ctx context.Context, tx chan<- *transport.Frame, in <-chan *transport.Packet) error {
	h.state.Phase = PhaseAuthEAPInProgress

	peer := &EapPeer{h: h, tx: tx, in: in}
	if err := peer.start(ctx); err != nil {
		return err
	}
	h.emit(events.Event{
		Kind: events.EventEapProcess,
		EAP:  events.EapProcess{Method: peer.methodName, State: "started", Round: 0},
	})
	defer func() {
		if peer.worker != nil {
			close(peer.rounds)
			// The worker always answers mailbox rounds and exits promptly;
			// a small timeout keeps a wedged TLS/PEAP engine from hanging the
			// failing handshake forever.
			select {
			case <-peer.worker.Done():
			case <-time.After(2 * time.Second):
			}
		}
	}()

	for peer.round < maxEAPRounds {
		pkt, err := peer.recv()
		if err != nil {
			return err
		}
		// swan2 EapMethod::run asks the bridge for next_round_index(),
		// which is sa.next_request_message_id: the message-id that will be
		// used if this round produces a response.
		roundID := uint16(h.state.NextRequestMessageID)
		reply := make(chan eap.RoundResult, 1)
		round := eap.Round{Packet: pkt, ID: roundID, Reply: reply}
		select {
		case peer.rounds <- round:
		case <-ctx.Done():
			return ctx.Err()
		}
		var res eap.RoundResult
		select {
		case res = <-reply:
		case <-ctx.Done():
			return ctx.Err()
		}
		if res.Err != nil {
			return fmt.Errorf("control: eap method round %d: %w", peer.round, res.Err)
		}
		switch res.Result.Action {
		case eap.ActionSend:
			sentID, err := peer.send(res.Result.Response)
			if err != nil {
				return err
			}
			h.emit(events.Event{
				Kind: events.EventEapProcess,
				EAP:  events.EapProcess{Method: peer.methodName, State: "response", Round: uint16(sentID)},
			})
		case eap.ActionComplete:
			h.state.Auth.LocalEAPMSK = cepClone(res.Result.ExportedMSK)
			h.emit(events.Event{
				Kind: events.EventEapProcess,
				EAP:  events.EapProcess{Method: peer.methodName, State: "completed", Round: 0},
			})
			return nil
		default:
			return fmt.Errorf("control: eap method returned unknown action %d", res.Result.Action)
		}
	}
	return fmt.Errorf("control: eap loop exceeded %d rounds", maxEAPRounds)
}

// cepSinglePayload builds a one-payload inner plaintext chain: generic
// 4-byte payload header plus body, with next-payload already NONE. The
// payload type travels in the SK payload's next-payload field, not in the
// inner header.
func cepSinglePayload(body []byte) []byte {
	total := 4 + len(body)
	return cepChainPayload(wire.PayloadTypeNone, body, total)
}

// cepChainPayload appends a generic payload header (next payload field next,
// critical bit clear, length total) followed by body. total must equal
// 4+len(body).
func cepChainPayload(next wire.PayloadType, body []byte, total int) []byte {
	out := make([]byte, 0, total)
	out = append(out, byte(next), 0, 0, 0)
	out[2] = byte(total >> 8)
	out[3] = byte(total)
	out = append(out, body...)
	return out
}

// cepClone returns a fresh copy of b (nil-safe).
func cepClone(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}
