package transport

import (
	"net"
)

// Wire constants.
const (
	// MaxWireDatagram is the largest legal NAT-T datagram payload. The
	// transport reads into buffers of at least this size; a peer that sends
	// more is outside the protocol and its packet is rejected later by the
	// IKE/ESP layers' own length checks.
	MaxWireDatagram = 65535
	// LogicalNatTPort is the logical NAT-T/IKE port used inside the
	// protocol. NAT-D hashing, keepalives and classification always use
	// this value, never a backend-specific local port.
	LogicalNatTPort = 4500
	// NonESPMarkerLen is the size of the all-zero non-ESP marker that
	// prefixes IKE payloads in NAT-T datagrams.
	NonESPMarkerLen = 4
)

// batchReader / batchWriter are optional wire capabilities discovered by
// type assertion. A wire that implements them gets the batched fast path;
// everything else degrades to one-datagram-per-call loops.
//
// ReadBatch must block until at least one datagram or an error. It may
// return n > 0 together with err (recvmmsg-style): datagrams [0,n) are
// valid, the error aborts the batch afterwards. WriteBatch may write a
// legal prefix of the list; the caller retries the remainder.
type batchReader interface {
	ReadBatch(bufs [][]byte, sizes []int) (int, error)
}

type batchWriter interface {
	WriteBatch(bufs [][]byte) (int, error)
}

// Kind is the classification result / datagram type of a NAT-T payload.
type Kind uint8

const (
	// KindIKE is an IKEv2 control message. On the wire the payload starts
	// with the 4-byte non-ESP marker; Classify strips it before delivery.
	KindIKE Kind = iota
	// KindESP is a UDP-encapsulated ESP datagram.
	KindESP
	// KindKeepalive is the 1-byte NAT-T keepalive probe (0xff). It is
	// consumed inside the transport layer and never delivered.
	KindKeepalive
)

// Frame is an outbound NAT-T datagram destined for the wire. The producer
// transfers ownership when it sends the Frame through the tx channel.
type Frame struct {
	Kind    Kind
	Payload []byte

	release func()
}

// SetRelease attaches an optional release hook to the frame. TxWorker calls
// Release exactly once after the frame bytes have been consumed (on both
// success and error paths). Frames without a hook (all control-plane
// frames, which are reused for retransmits) are unaffected.
func (f *Frame) SetRelease(release func()) {
	if f != nil {
		f.release = release
	}
}

// Release invokes the release hook once. It is a no-op for frames without a
// hook; hooked frames have their payload cleared so a use-after-release
// fails immediately instead of observing recycled bytes.
func (f *Frame) Release() {
	if f == nil || f.release == nil {
		return
	}
	f.release()
	f.release = nil
	f.Payload = nil
}

// Packet is a classified inbound datagram. The payload is exclusive to the
// receiver: the owner is responsible for returning it to the buffer pool
// via Release once parsed (or for retaining a copy when the bytes outlive
// processing). A packet whose release hook is nil owns ordinary GC memory
// and does not need an explicit return.
type Packet struct {
	Kind    Kind
	Payload []byte

	release func()
}

// Release returns a pooled packet buffer to the pool. Call it exactly once
// when the packet bytes are no longer needed; it is a no-op for packets
// that were not carved out of the rx pool. The payload must not be used
// after Release.
func (p *Packet) Release() {
	if p == nil || p.release == nil {
		return
	}
	p.release()
	p.release = nil
	p.Payload = nil
}

// Classify inspects an unframed NAT-T payload and reports its kind.
// It implements the swan2 rules: single 0xff byte is keepalive, a leading
// NonESPMarkerLen bytes of zero is IKE, everything else is ESP.
func Classify(payload []byte) Kind {
	if len(payload) == 1 && payload[0] == 0xff {
		return KindKeepalive
	}
	if len(payload) >= NonESPMarkerLen && zeros(payload[:NonESPMarkerLen]) {
		return KindIKE
	}
	return KindESP
}

func zeros(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// LogicalAddr returns the address with its port replaced by the logical
// NAT-T port 4500. IPv6 zones are preserved, IPAddr values (which have no
// port) are returned as-is, and opaque backend addresses pass through
// unchanged. Resolution stays with the backend; this only normalizes the
// port so NAT-D behaves like the MVP profile requires.
func LogicalAddr(a net.Addr) net.Addr {
	if a == nil {
		return nil
	}
	switch v := a.(type) {
	case *net.TCPAddr:
		out := *v
		out.Port = LogicalNatTPort
		return &out
	case *net.UDPAddr:
		out := *v
		out.Port = LogicalNatTPort
		return &out
	default:
		return a
	}
}
