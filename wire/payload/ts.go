package payload

import (
	"fmt"
	"net"
)

// Selector is one traffic selector inside a TSi/TSr payload (RFC 7296
// 3.13.1). Addresses are stored as net.IP for JSON/log friendliness, but
// this package seeds them from the 4/16-byte wire forms without extra
// allocation where possible.
type Selector struct {
	Type       uint8 // TSTypeIPv4AddrRange | TSTypeIPv6AddrRange
	ProtocolID uint8 // MVP requires 0
	StartPort  uint16
	EndPort    uint16
	StartAddr  net.IP
	EndAddr    net.IP
}

// TrafficSelectors is the body of a TSi/TSr payload: a count byte plus the
// selectors.
type TrafficSelectors struct {
	Selectors []Selector
}

// AppendTS serializes the TSi/TSr payload body (count header + entries).
func AppendTS(dst []byte, ts TrafficSelectors) []byte {
	start := len(dst)
	dst = append(dst, byte(len(ts.Selectors)), 0, 0, 0)
	_ = start
	for _, s := range ts.Selectors {
		dst = appendTrafficSelector(dst, s)
	}
	return dst
}

// ParseTS decodes the payload, verifying per-entry lengths, address widths
// and ordered ranges (start <= end).
func ParseTS(b []byte) (TrafficSelectors, error) {
	if len(b) < TsSelectorFixedLen {
		return TrafficSelectors{}, fmt.Errorf("traffic selector payload too short: %d bytes", len(b))
	}
	count := int(b[0])
	if len(b[1:TsSelectorFixedLen]) == 0 || b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return TrafficSelectors{}, fmt.Errorf("traffic selector payload has non-zero reserved bytes")
	}
	ts := TrafficSelectors{}
	rest := b[TsSelectorFixedLen:]
	for i := 0; i < count; i++ {
		s, tail, err := parseTrafficSelector(rest)
		if err != nil {
			return TrafficSelectors{}, fmt.Errorf("traffic selector %d: %w", i, err)
		}
		ts.Selectors = append(ts.Selectors, s)
		rest = tail
	}
	if len(rest) != 0 {
		return TrafficSelectors{}, fmt.Errorf("traffic selector payload has %d trailing bytes", len(rest))
	}
	return ts, nil
}

func addrLen(tsType uint8) (int, error) {
	switch tsType {
	case 7: // TSTypeIPv4AddrRange
		return 4, nil
	case 8: // TSTypeIPv6AddrRange
		return 16, nil
	default:
		return 0, fmt.Errorf("unsupported traffic selector type %d", tsType)
	}
}

func appendTrafficSelector(dst []byte, s Selector) []byte {
	width := len(ipOctets(s.StartAddr))
	start := len(dst)
	dst = append(dst, s.Type, s.ProtocolID, 0, 0, 0, 0, 0, 0)
	putUint16(dst[start+2:start+4], uint16(TsEntryFixedLen+2*width))
	putUint16(dst[start+4:start+6], s.StartPort)
	putUint16(dst[start+6:start+8], s.EndPort)
	dst = append(dst, ipOctets(s.StartAddr)...)
	return append(dst, ipOctets(s.EndAddr)...)
}

func parseTrafficSelector(b []byte) (Selector, []byte, error) {
	if len(b) < TsEntryFixedLen {
		return Selector{}, nil, fmt.Errorf("entry too short: %d bytes", len(b))
	}
	width, err := addrLen(b[0])
	if err != nil {
		return Selector{}, nil, err
	}
	if b[1] != 0 {
		return Selector{}, nil, fmt.Errorf("mvp traffic selector must use protocol 0, got %d", b[1])
	}
	entryLen := int(beUint16(b[2:4]))
	want := TsEntryFixedLen + 2*width
	if entryLen != want {
		return Selector{}, nil, fmt.Errorf("invalid entry length %d for address width %d", entryLen, width)
	}
	if entryLen > len(b) {
		return Selector{}, nil, fmt.Errorf("entry length %d exceeds remaining %d", entryLen, len(b))
	}

	startPort := beUint16(b[4:6])
	endPort := beUint16(b[6:8])
	if startPort > endPort {
		return Selector{}, nil, fmt.Errorf("port range reversed: %d-%d", startPort, endPort)
	}

	addrs := b[TsEntryFixedLen:entryLen]
	startAddr := cloneIP(addrs[:width])
	endAddr := cloneIP(addrs[width:])
	if len(startAddr) != 0 && compareIP(startAddr, endAddr) > 0 {
		return Selector{}, nil, fmt.Errorf("address range reversed")
	}

	return Selector{
		Type:       b[0],
		ProtocolID: b[1],
		StartPort:  startPort,
		EndPort:    endPort,
		StartAddr:  startAddr,
		EndAddr:    endAddr,
	}, b[entryLen:], nil
}

func ipOctets(ip net.IP) []byte {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

func cloneIP(p []byte) net.IP {
	switch len(p) {
	case 4:
		return net.IPv4(p[0], p[1], p[2], p[3])
	case 16:
		return append(net.IP(nil), p...)
	default:
		return nil
	}
}

func compareIP(a, b net.IP) int {
	switch len(a) - len(b) {
	case 0:
	default:
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	for i, x := range a {
		y := b[i]
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
	}
	return 0
}
