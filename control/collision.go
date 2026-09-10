package control

import "bytes"

// CollisionDecision is the result of the RFC 7296 simultaneous-rekey nonce
// comparison. The smaller nonce loses; the comparison is bytewise over the
// shorter of the two nonces (memcmp semantics).
type CollisionDecision uint8

const (
	// CollisionNoCollision means at least one side's nonce is unavailable,
	// so no strict winner can be computed.
	CollisionNoCollision CollisionDecision = iota
	// CollisionWeWin means the peer nonce is smaller or equal. Callers keep
	// the existing TEMPORARY_FAILURE response behavior for this side.
	CollisionWeWin
	// CollisionWeLose means our nonce is smaller. Callers abandon their own
	// rekey and accept the peer's rekey.
	CollisionWeLose
)

// decideNonceCollision compares our in-flight rekey nonce with the inbound
// request nonce. Equal nonces are deliberately mapped to CollisionWeWin so
// callers follow the RFC 7296 2.8.1/2.8.2 equal-nonce special case and
// respond with TEMPORARY_FAILURE; equal random nonces are infeasible in
// practice, and a strict smaller-than comparison (strongSwan's memcmp < 0)
// has no natural winner for equality.
func decideNonceCollision(ours, theirs []byte) CollisionDecision {
	if len(ours) == 0 || len(theirs) == 0 {
		return CollisionNoCollision
	}
	n := len(ours)
	if len(theirs) < n {
		n = len(theirs)
	}
	if bytes.Compare(ours[:n], theirs[:n]) < 0 {
		return CollisionWeLose
	}
	return CollisionWeWin
}
