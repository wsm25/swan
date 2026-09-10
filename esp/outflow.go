package esp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/wsm25/swan/transport"
	"github.com/wsm25/swan/xcrypto"
)

// ErrSeqWrapped reports that the outbound sequence number reached zero:
// RFC 4303 forbids cycling the counter, and the sender must stop and rekey
// instead of reusing sequence numbers. It is sticky for the lifetime of the
// Outbound.
var ErrSeqWrapped = errors.New("github.com/wsm25/swan/esp: ESP sequence number wrapped after 2^32-1 packets")

// FlowLimit is the outbound byte/packet rekey trigger. Zero disables a
// limit. Counters are outbound-only per the accepted design.
type FlowLimit struct {
	Bytes   uint64
	Packets uint64
}

// OutboundConfig freezes the per-SA read-only state handed to the outbound
// worker at establishment.
type OutboundConfig struct {
	// SPI is the responder-provided outbound SPI.
	SPI       uint32
	Selection *xcrypto.Selection
	Keys      *xcrypto.ChildKeys

	// WarnAt is the precomputed ESP sequence number at or above which the
	// worker raises a non-blocking emergency rekey trigger (0 disables).
	WarnAt uint32
	// FlowWarn receives the non-blocking emergency/limit trigger. The send
	// never blocks the hot path.
	FlowWarn chan<- struct{}
	// FlowLimit sets outbound byte/packet rekey thresholds.
	FlowLimit FlowLimit
}

// outboundPoolBufSize is the initial ESP datagram backing class size. Larger
// jumbo datagrams replace the pooled slice; Put still recycles the larger
// backing array (the pool simply adapts upwards, exactly like the rx pool).
const outboundPoolBufSize = 4096

// outboundDatagram carries the pooled ESP datagram backing. The slice length
// is recovered from the datagram handed to the transport writer.
type outboundDatagram struct {
	b []byte
}

// Outbound encrypts raw IP packets into UDP-encapsulated ESP datagrams.
// Sequence numbers are allocated strictly in order by this single worker
// (starting at 1; wrap is an error, per RFC 4303).
type Outbound struct {
	cfg OutboundConfig

	seq      uint32
	wrapped  bool
	packets  uint64
	bytesOut uint64
	warned   bool
	enc      *xcrypto.PreparedEncryption
	integ    *xcrypto.PreparedIntegrity
	stateErr error

	// plain/iv are process-local scratch buffers; they never alias a
	// returned datagram after Process returns.
	plain []byte
	iv    []byte

	pool sync.Pool
}

// NewOutbound binds the frozen configuration with the sequence number at
// its RFC 4303 initial value of 1. Reusable keyed cipher state is prepared
// here; any preparation failure is reported by Process.
func NewOutbound(cfg OutboundConfig) *Outbound {
	p := &Outbound{cfg: cfg, seq: 1}
	p.pool = sync.Pool{New: func() any { return &outboundDatagram{b: make([]byte, outboundPoolBufSize)} }}
	p.enc, p.integ, p.stateErr = prepareOutbound(cfg)
	return p
}

// Process pads/encrypts one raw IP packet and returns the ESP datagram
// (without any NAT-T marker; the transport writer applies none for ESP).
// IPv4/IPv6 are translated to the ESP next-header values 4/41; other
// versions are rejected.
func (p *Outbound) Process(packet []byte) (datagram []byte, err error) {
	datagram, _, err = p.process(packet, false)
	return datagram, err
}

// process is the shared encrypt path. pooled selects a transport-releasable
// datagram backing (used by the pipeline); the public Process uses ordinary
// GC memory and therefore returns no release hook.
func (p *Outbound) process(packet []byte, pooled bool) ([]byte, func(), error) {
	if p != nil && p.wrapped {
		// Stick to the fatal error: no packet may ever be sent again on
		// this SA once the counter cycled.
		return nil, nil, ErrSeqWrapped
	}
	if p == nil || p.stateErr != nil {
		if p == nil {
			return nil, nil, errors.New("github.com/wsm25/swan/esp: outbound configuration is incomplete")
		}
		return nil, nil, p.stateErr
	}
	if len(packet) == 0 {
		return nil, nil, errors.New("github.com/wsm25/swan/esp: outbound packet is empty")
	}

	nextHeader, err := ipNextHeader(packet[0])
	if err != nil {
		return nil, nil, err
	}

	enc := p.cfg.Selection.Encryption
	integ := p.cfg.Selection.Integrity

	// ESP padding (RFC 4303 2.4): pad bytes 1..padLen, followed by the
	// pad length byte and the IP next-header byte. The full plaintext
	// (payload + padding + trailer) must be a multiple of the cipher block
	// size: 16 for CBC, 1 for AEAD (no padding).
	padLen := (enc.BlockLen - (len(packet)+2)%enc.BlockLen) % enc.BlockLen
	plainRequired := len(packet) + padLen + 2
	if cap(p.plain) < plainRequired {
		p.plain = make([]byte, plainRequired)
	}
	plain := p.plain[:0]
	plain = append(plain, packet...)
	for i := 1; i <= padLen; i++ {
		plain = append(plain, byte(i))
	}
	plain = append(plain, byte(padLen), nextHeader)

	if cap(p.iv) < enc.IVLen {
		p.iv = make([]byte, enc.IVLen)
	}
	iv := p.iv[:enc.IVLen]
	if err := xcrypto.Fill(iv); err != nil {
		return nil, nil, fmt.Errorf("github.com/wsm25/swan/esp: generate ESP IV: %w", err)
	}

	if p.seq == 0 {
		p.wrapped = true
		return nil, nil, ErrSeqWrapped
	}
	seq := p.seq
	p.seq++
	p.packets++
	p.bytesOut += uint64(len(packet))
	p.checkFlowTriggers()

	// The transport length prefix is 16-bit; reject frames that could not
	// be written before allocating/sealing. A silent oversized write would
	// otherwise kill the shared Tx worker underneath the caller.
	trailerICV := integOuterICV(integ)
	if enc.AEAD {
		trailerICV = enc.ICVLen
	}
	wireLen := espHeaderLen + enc.IVLen + len(plain) + trailerICV
	if wireLen > transport.MaxFramePayload {
		return nil, nil, fmt.Errorf("github.com/wsm25/swan/esp: encapsulated packet %d bytes exceeds transport limit %d", wireLen, transport.MaxFramePayload)
	}

	var (
		datagram []byte
		release  func()
	)
	if pooled {
		datagram, release = p.allocDatagram(wireLen)
	} else {
		datagram = make([]byte, wireLen)
	}
	fail := func(err error) ([]byte, func(), error) {
		if release != nil {
			release()
		}
		return nil, nil, err
	}

	binary.BigEndian.PutUint32(datagram[:4], p.cfg.SPI)
	binary.BigEndian.PutUint32(datagram[4:8], seq)
	copy(datagram[espHeaderLen:espHeaderLen+enc.IVLen], iv)

	datagram, err = p.enc.SealTo(datagram[:espHeaderLen+enc.IVLen], iv, datagram[:espHeaderLen], plain)
	if err != nil {
		return fail(fmt.Errorf("github.com/wsm25/swan/esp: encrypt ESP: %w", err))
	}

	if !enc.AEAD {
		if p.integ == nil {
			return fail(errors.New("github.com/wsm25/swan/esp: CBC requires an integrity transform"))
		}
		icv, err := p.integ.Sign(datagram)
		if err != nil {
			return fail(fmt.Errorf("github.com/wsm25/swan/esp: sign ESP ICV: %w", err))
		}
		datagram = append(datagram, icv...)
	}

	return datagram, release, nil
}

// allocDatagram carves an ESP datagram out of the outbound pool and returns
// the release hook that puts its whole backing array back.
// checkFlowTriggers raises at most one non-blocking rekey trigger per SA
// for sequence near-wrap or byte/packet flow limits.
func (p *Outbound) checkFlowTriggers() {
	if p.warned || p.cfg.FlowWarn == nil {
		return
	}
	limitHit := p.cfg.FlowLimit.Bytes > 0 && p.bytesOut >= p.cfg.FlowLimit.Bytes
	limitHit = limitHit || (p.cfg.FlowLimit.Packets > 0 && p.packets >= p.cfg.FlowLimit.Packets)
	seqHit := p.cfg.WarnAt > 0 && p.seq >= p.cfg.WarnAt
	if !limitHit && !seqHit {
		return
	}
	p.warned = true
	select {
	case p.cfg.FlowWarn <- struct{}{}:
	default:
	}
}

func (p *Outbound) allocDatagram(n int) ([]byte, func()) {
	ob := p.pool.Get().(*outboundDatagram)
	if cap(ob.b) < n {
		ob.b = make([]byte, n)
	}
	return ob.b[:n], func() { p.pool.Put(ob) }
}

// prepareOutbound builds the keyed cipher states the outbound worker reuses
// for the lifetime of the CHILD_SA.
func prepareOutbound(cfg OutboundConfig) (*xcrypto.PreparedEncryption, *xcrypto.PreparedIntegrity, error) {
	if cfg.Selection == nil || cfg.Selection.Encryption == nil || cfg.Keys == nil {
		return nil, nil, errors.New("github.com/wsm25/swan/esp: outbound configuration is incomplete")
	}
	enc := cfg.Selection.Encryption
	state, err := enc.Prepare(cfg.Keys.SKei)
	if err != nil {
		return nil, nil, fmt.Errorf("github.com/wsm25/swan/esp: prepare ESP encryption: %w", err)
	}
	var integ *xcrypto.PreparedIntegrity
	if !enc.AEAD {
		if cfg.Selection.Integrity == nil {
			return nil, nil, errors.New("github.com/wsm25/swan/esp: CBC requires an integrity transform")
		}
		integ, err = cfg.Selection.Integrity.Prepare(cfg.Keys.SKai)
		if err != nil {
			return nil, nil, fmt.Errorf("github.com/wsm25/swan/esp: prepare ESP integrity: %w", err)
		}
	}
	return state, integ, nil
}

// ipNextHeader maps the IP version nibble to the ESP trailer next-header
// value: IPv4 -> 4, IPv6 -> 41.
func ipNextHeader(firstByte byte) (byte, error) {
	switch firstByte >> 4 {
	case 4:
		return nextHeaderIPv4, nil
	case 6:
		return nextHeaderIPv6, nil
	default:
		return 0, fmt.Errorf("github.com/wsm25/swan/esp: unsupported outbound IP version %d", firstByte>>4)
	}
}

// integOuterICV reports the extra trailing bytes on the wire for the
// non-AEAD ICV (AEAD tags are already included in ciphertext by Seal).
func integOuterICV(integ *xcrypto.Integrity) int {
	if integ == nil {
		return 0
	}
	return integ.OutputLen
}
