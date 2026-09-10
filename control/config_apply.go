package control

import "net"

// configApplyMode selects whole-set replace (CFG_REPLY) or merge (CFG_SET)
// semantics.
type configApplyMode uint8

const (
	configApplyReplace configApplyMode = iota
	configApplyMerge
)

// applyConfigUpdate installs one parsed CFG_REPLY/CFG_SET snapshot onto the
// running state. Replace mode takes the incoming value as the new whole
// set. Merge mode starts from the previous value and only overrides the
// categories the SET payload actually carried, so a partial push does not
// clear unchanged addresses or DNS. A present INTERNAL_ADDRESS_EXPIRY
// re-arms the lease deadline; an absent expiry keeps the previous deadline.
// It returns whether the stored value changed and the value stored.
func (r *Running) applyConfigUpdate(incoming *AssignedConfig, present cesAssignedMask, mode configApplyMode) (bool, AssignedConfig) {
	var next AssignedConfig
	if mode == configApplyMerge && r.state.Assigned != nil {
		next = cloneAssignedConfig(r.state.Assigned)
		if present.v4Addr {
			next.InternalIPv4 = append(net.IP(nil), incoming.InternalIPv4...)
		}
		if present.v6Addr {
			next.InternalIPv6 = append(net.IP(nil), incoming.InternalIPv6...)
			next.InternalIPv6Prefix = incoming.InternalIPv6Prefix
		}
		if present.v4DNS {
			next.DNS4 = cloneIPList(incoming.DNS4)
		}
		if present.v6DNS {
			next.DNS6 = cloneIPList(incoming.DNS6)
		}
		if present.expiry {
			next.AddressExpirySeconds = incoming.AddressExpirySeconds
		}
	} else {
		next = cloneAssignedConfig(incoming)
	}
	changed := r.state.Assigned == nil || !assignedConfigEqual(r.state.Assigned, &next)
	r.state.Assigned = &next
	if next.AddressExpirySeconds > 0 {
		r.armLeaseTimer()
	}
	if changed && r.cfg != nil && r.cfg.DataUpdates != nil {
		select {
		case r.cfg.DataUpdates <- DataplaneUpdate{Kind: UpdateAssigned, Assigned: next}:
		default:
		}
	}
	return changed, next
}

func cloneAssignedConfig(in *AssignedConfig) AssignedConfig {
	if in == nil {
		return AssignedConfig{}
	}
	out := *in
	out.InternalIPv4 = append(net.IP(nil), in.InternalIPv4...)
	out.InternalIPv6 = append(net.IP(nil), in.InternalIPv6...)
	out.DNS4 = cloneIPList(in.DNS4)
	out.DNS6 = cloneIPList(in.DNS6)
	return out
}

func cloneIPList(in []net.IP) []net.IP {
	if in == nil {
		return nil
	}
	out := make([]net.IP, len(in))
	for i := range in {
		out[i] = append(net.IP(nil), in[i]...)
	}
	return out
}

func assignedConfigEqual(a, b *AssignedConfig) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.AddressExpirySeconds == b.AddressExpirySeconds &&
		a.InternalIPv6Prefix == b.InternalIPv6Prefix &&
		a.InternalIPv4.Equal(b.InternalIPv4) &&
		a.InternalIPv6.Equal(b.InternalIPv6) &&
		ipListsEqual(a.DNS4, b.DNS4) &&
		ipListsEqual(a.DNS6, b.DNS6)
}

func ipListsEqual(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}
