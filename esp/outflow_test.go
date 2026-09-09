package esp

import "testing"

func TestOutboundCheckFlowTriggersNearsWrap(t *testing.T) {
	ch := make(chan struct{}, 1)
	o := &Outbound{cfg: OutboundConfig{WarnAt: 5, FlowWarn: ch}, seq: 5}
	o.checkFlowTriggers()
	select {
	case <-ch:
	default:
		t.Fatal("expected near-wrap trigger at WarnAt threshold")
	}
	o.checkFlowTriggers()
	select {
	case <-ch:
		t.Fatal("near-wrap trigger must be single-shot per SA")
	default:
	}
}

func TestOutboundCheckFlowTriggersPacketLimit(t *testing.T) {
	ch := make(chan struct{}, 1)
	o := &Outbound{
		cfg:      OutboundConfig{FlowWarn: ch, FlowLimit: FlowLimit{Packets: 3}},
		packets:  3,
		bytesOut: 3,
	}
	o.checkFlowTriggers()
	select {
	case <-ch:
	default:
		t.Fatal("expected packet-limit rekey trigger")
	}
}
