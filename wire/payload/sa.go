package payload

import (
	"fmt"

	"swan/wire"
)

// SA is the body of an SA payload: one or more proposals. For IKE_SA_INIT
// requests each ProposalNum starts at 1 within its protocol family.
type SA struct {
	Proposals []Proposal
}

// AppendSA serializes the whole SA payload body.
func AppendSA(dst []byte, sa SA) []byte {
	for i := range sa.Proposals {
		dst = AppendProposal(dst, sa.Proposals[i], i != len(sa.Proposals)-1)
	}
	return dst
}

// ParseSA decodes the whole SA payload body and verifies proposal chain
// markers and lengths.
func ParseSA(b []byte) (SA, error) {
	var sa SA
	rest := b
	for {
		if len(rest) == 0 {
			break
		}
		if len(rest) < ProposalHeaderLen {
			return SA{}, fmt.Errorf("sst proposal short: %d bytes", len(rest))
		}
		p, tail, err := ParseProposal(rest)
		if err != nil {
			return SA{}, err
		}
		sa.Proposals = append(sa.Proposals, p)
		// ParseProposal returns the chain-marker verification indirectly:
		// the proposal's own last-substructure byte still must make sense
		// relative to the remaining bytes.
		if len(tail) == 0 {
			if rest[0] != wire.TransformChainLast {
				return SA{}, fmt.Errorf("proposal chain missing last marker")
			}
			break
		}
		if rest[0] != wire.ProposalChainMore {
			return SA{}, fmt.Errorf("proposal chain marker 0x%02x before remaining proposals", rest[0])
		}
		rest = tail
	}
	if len(sa.Proposals) == 0 {
		return SA{}, fmt.Errorf("missing sa proposals")
	}
	return sa, nil
}
