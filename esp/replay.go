package esp

// ReplayWindow is the RFC 4303 anti-replay bitmask: highest seen sequence
// number plus a 64-slot bitmap. Sequence 0 is dropped by the caller before
// Accept; out-of-window packets are rejected.
type ReplayWindow struct {
	highest uint32
	bitmap  uint64
}

// Accept validates seq and records it. Returns false for duplicates or
// sequences outside the 64-slot window.
//
// Mirrors swan2 EspState::accept_inbound_seq: first packet seeds the
// window, higher sequences shift (resetting the full window on shifts >=
// 64), older sequences set (and check) one bit.
func (w *ReplayWindow) Accept(seq uint32) bool {
	if seq == 0 {
		return false
	}

	if w.highest == 0 {
		w.highest = seq
		w.bitmap = 1
		return true
	}

	if seq > w.highest {
		delta := seq - w.highest
		if delta >= 64 {
			w.bitmap = 1
		} else {
			w.bitmap = (w.bitmap << delta) | 1
		}
		w.highest = seq
		return true
	}

	delta := w.highest - seq
	if delta >= 64 {
		return false
	}
	bit := uint64(1) << delta
	if w.bitmap&bit != 0 {
		return false
	}
	w.bitmap |= bit
	return true
}

// Reset clears the window for a fresh SA.
func (w *ReplayWindow) Reset() {
	w.highest = 0
	w.bitmap = 0
}
