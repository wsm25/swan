package swan

import "swan/events"

// Event is re-exported from swan/events so callers usually only import "swan".
//
// Success path ordering is deterministic on any single subscription:
//
//	Starting -> HandshakeStarted
//	    -> [StageChanged | EapProcess | NegotiatedAlgorithm ...]
//	    -> HandshakeCompleted -> ConfigAssigned -> Started
//
// Control-plane transitions only; there is no per-packet noise.
type Event = events.Event

// EventStream is one subscriber's view of the hub: a replay of the last N
// events followed by live delivery. Slow subscribers are tolerated.
type EventStream = events.Stream

// Stage names one control-plane phase reported through EventStageChanged.
type Stage = events.Stage

// Re-exported event kinds for switch statements.
const (
	EventStarting            = events.EventStarting
	EventHandshakeStarted    = events.EventHandshakeStarted
	EventStageChanged        = events.EventStageChanged
	EventNegotiatedAlgorithm = events.EventNegotiatedAlgorithm
	EventEapProcess          = events.EventEapProcess
	EventHandshakeCompleted  = events.EventHandshakeCompleted
	EventConfigAssigned      = events.EventConfigAssigned
	EventStarted             = events.EventStarted
	EventStopping            = events.EventStopping
	EventStopped             = events.EventStopped
	EventBroken              = events.EventBroken
)

// Re-exported stage values.
const (
	StageIKEInit = events.StageIKEInit
	StageIKEAuth = events.StageIKEAuth
	StageEAP     = events.StageEAP
	StageChildSA = events.StageChildSA
	StageRunning = events.StageRunning
)
