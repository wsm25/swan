package swan

import (
	"net"

	"github.com/wsm25/swan/control"
	"github.com/wsm25/swan/events"
)

// Event is re-exported from github.com/wsm25/swan/events so callers usually only import "github.com/wsm25/swan".
//
// Success path ordering is deterministic on any single subscription:
//
//	Starting -> HandshakeStarted
//	    -> [StageChanged | EapProcess | NegotiatedAlgorithm ...]
//	    -> HandshakeCompleted -> ConfigAssigned -> Started
//
// While running, peer-pushed CFG_SET or renewal CFG_REPLY changes emit
// AssignedUpdated with the new snapshot.
//
// Control-plane transitions only; there is no per-packet noise.
type Event = events.Event

// EventStream is one subscriber's view of the hub: a replay of the last N
// events followed by live delivery. Slow subscribers are tolerated.
type EventStream = events.Stream

// Stage names one control-plane phase reported through EventStageChanged.
type Stage = events.Stage

// Assigned is the CP configuration snapshot re-exported from swan/events;
// it travels on EventConfigAssigned and EventAssignedUpdated.
type Assigned = events.Assigned

// assignedEvent converts a control snapshot into the event value, cloning
// every slice so the hub replay and subscribers never alias control state.
func assignedEvent(a control.AssignedConfig) events.Assigned {
	return events.Assigned{
		InternalIPv4:         append(net.IP(nil), a.InternalIPv4...),
		InternalIPv6:         append(net.IP(nil), a.InternalIPv6...),
		InternalIPv6Prefix:   a.InternalIPv6Prefix,
		DNS4:                 cloneIPs(a.DNS4),
		DNS6:                 cloneIPs(a.DNS6),
		AddressExpirySeconds: a.AddressExpirySeconds,
	}
}

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
	EventAssignedUpdated     = events.EventAssignedUpdated
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
