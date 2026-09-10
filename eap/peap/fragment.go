package peap

import "fmt"

// PEAP fragmentation flags (draft-josefsson-pppext-eap-tls-eap section 2,
// RFC 5216 style):
//
//	Length included (L) 0x80, More fragments (M) 0x40, Start (S) 0x20,
//	version in the low 3 bits (only version 0 supported by the MVP).
const (
	FlagLengthIncluded = 0x80
	FlagMoreFragments  = 0x40
	FlagStart          = 0x20
	FlagVersionMask    = 0x07
	SupportedVersion   = 0
)

// OutboundFragmenter splits one outbound TLS message into PEAP fragments.
//
// Wire layout of each produced packet (the FSM hands this payload to its
// EAP-envelope builder, which owns the EAP header and type byte):
//
//	first:  <flags byte> [uint32 BE total length on fragmented-first
//	                     or when L is enabled for a single packet] <chunk>
//	next:   <flags byte> <chunk>
//
// Flags per swan2 peap.rs: L(M/0-or-L, fragmented first ALWAYS carries L),
// M (more chunks follow). The S flag is never set on client responses.
// Fragments after the first carry M or 0.
type OutboundFragmenter struct {
	payload       []byte
	offset        int
	chunk         int
	includeLength bool
}

// NewOutboundFragmenter validates chunk bounds. Because the legacy
// constructor cannot return an error, an invalid chunk size yields nil and
// callers must treat nil as invalid configuration.
func NewOutboundFragmenter(chunk int, includeLength bool) *OutboundFragmenter {
	if chunk <= 0 {
		return nil
	}
	return &OutboundFragmenter{
		payload:       nil,
		offset:        0,
		chunk:         chunk,
		includeLength: includeLength,
	}
}

// Start loads a payload and produces the first fragment packet; done
// reports whether one fragment covered everything.
func (f *OutboundFragmenter) Start(payload []byte, baseFlags uint8) (packet []byte, done bool, err error) {
	if f == nil {
		return nil, false, fmt.Errorf("github.com/wsm25/swan/eap/peap: nil outbound fragmenter")
	}
	if f.Pending() {
		return nil, false, fmt.Errorf("github.com/wsm25/swan/eap/peap: outbound fragmenter already active")
	}
	if f.chunk <= 0 {
		return nil, false, fmt.Errorf("github.com/wsm25/swan/eap/peap: fragment chunk size must be > 0")
	}
	if payload == nil {
		payload = []byte{}
	}
	f.payload = payload
	f.offset = 0

	more := len(f.payload) > f.chunk
	flags := baseFlags
	// Fragmented first fragment always carries the total length (swan2
	// emit_fragmented_or_single); a single unfragmented packet carries L
	// only when configured.
	if more || f.includeLength {
		flags |= FlagLengthIncluded
	}
	if more {
		flags |= FlagMoreFragments
	}

	pkt := make([]byte, 0, 5+f.chunk)
	pkt = append(pkt, flags)
	if more || f.includeLength {
		// swan2 emit_fragmented_or_single: a fragmented first packet
		// ALWAYS carries the 4-byte total length, a single packet carries
		// it only when includeLength is configured.
		total := len(f.payload)
		pkt = append(pkt, byte(total>>24), byte(total>>16), byte(total>>8), byte(total))
	}
	end := len(f.payload)
	if end > f.chunk {
		end = f.chunk
	}
	pkt = append(pkt, f.payload[:end]...)
	f.offset = end

	if !more {
		f.payload = nil
		f.offset = 0
		done = true
	}
	return pkt, done, nil
}

// Next produces the next fragment after a server ACK; done reports the
// final fragment. Next with no pending payload is an error.
func (f *OutboundFragmenter) Next() (packet []byte, done bool, err error) {
	if f == nil || !f.Pending() {
		return nil, false, fmt.Errorf("github.com/wsm25/swan/eap/peap: no outbound peap fragments pending")
	}

	start := f.offset
	end := len(f.payload)
	if end > start+f.chunk {
		end = start + f.chunk
	}
	chunk := f.payload[start:end]
	f.offset = end
	more := f.offset < len(f.payload)

	pkt := make([]byte, 0, 1+len(chunk))
	if more {
		pkt = append(pkt, FlagMoreFragments)
	} else {
		pkt = append(pkt, 0)
	}
	pkt = append(pkt, chunk...)

	if !more {
		done = true
		f.payload = nil
		f.offset = 0
	}
	return pkt, done, nil
}

// Pending reports whether fragments remain.
func (f *OutboundFragmenter) Pending() bool {
	return f != nil && f.payload != nil && f.offset < len(f.payload)
}

// InboundFragmenter reassembles one inbound TLS message: the first fragment
// must carry L (when fragmented), continuation fragments must not, and the
// final size must match the declared length.
type InboundFragmenter struct {
	parts    [][]byte
	total    int
	expected int // -1 until L arrives on the first fragment
}

// NewInboundFragmenter allocates an empty collector.
func NewInboundFragmenter() *InboundFragmenter {
	return &InboundFragmenter{expected: -1}
}

// Push accumulates one fragment payload. lengthIncluded is the 32-bit value
// carried by the L field when the packet has FlagLengthIncluded; pass 0 for
// packets without it. complete reports the reassembled message whenever its
// final fragment has been collected, including the single-packet
// unfragmented path.
func (f *InboundFragmenter) Push(flags uint8, lengthIncluded uint32, data []byte) (whole []byte, complete bool, err error) {
	if f == nil {
		return nil, false, fmt.Errorf("github.com/wsm25/swan/eap/peap: nil inbound fragmenter")
	}
	if flags&FlagLengthIncluded != 0 {
		// Only the first fragment may carry L.
		if f.expected != -1 {
			return nil, false, fmt.Errorf("github.com/wsm25/swan/eap/peap: unexpected L flag on continuation fragment")
		}
		if lengthIncluded == 0 {
			return nil, false, fmt.Errorf("github.com/wsm25/swan/eap/peap: L flag set but total length is zero")
		}
		f.parts = nil
		f.total = 0
		f.expected = int(lengthIncluded)
	} else if f.expected == -1 {
		// Unfragmented path: a single packet without L is complete as-is.
		if flags&FlagMoreFragments != 0 {
			return nil, false, fmt.Errorf("github.com/wsm25/swan/eap/peap: fragmented packet missing L on first fragment")
		}
		return append([]byte(nil), data...), true, nil
	}

	f.parts = append(f.parts, data)
	f.total += len(data)
	if f.total > f.expected {
		return nil, false, fmt.Errorf("github.com/wsm25/swan/eap/peap: fragment total %d exceeds declared length %d", f.total, f.expected)
	}

	if flags&FlagMoreFragments != 0 {
		return nil, false, nil
	}
	if f.total != f.expected {
		return nil, false, fmt.Errorf("github.com/wsm25/swan/eap/peap: fragment total %d != declared length %d", f.total, f.expected)
	}

	joined := make([]byte, 0, f.total)
	for _, part := range f.parts {
		joined = append(joined, part...)
	}
	f.parts = nil
	f.total = 0
	f.expected = -1
	return joined, true, nil
}

// Reset clears the collector for the next message.
func (f *InboundFragmenter) Reset() {
	if f == nil {
		return
	}
	f.parts = nil
	f.total = 0
	f.expected = -1
}
