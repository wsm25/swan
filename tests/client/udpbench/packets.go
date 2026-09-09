package main

import (
	"encoding/binary"
	"net"
)

// Private UDP benchmark protocol. All multi-byte fields are big-endian.
const (
	magicData uint32 = 0x5357414e // "SWAN"
	magicEnd  uint32 = 0x454e4453 // "ENDS"
	magicStat uint32 = 0x53544154 // "STAT"

	minUDPPayload = 12
)

type packetKind uint8

const (
	packetUnknown packetKind = iota
	packetData
	packetEnd
	packetStat
)

// parsedPacket is the result of parsing one inbound raw IP packet.
type parsedPacket struct {
	kind       packetKind
	payloadLen int
	srcIP      uint32 // IPv4 source address as big-endian uint32
	srcPort    uint16

	// DATA fields.
	seq uint32

	// END fields.
	count uint32

	// STAT fields.
	stat statPayload
}

type statPayload struct {
	packets uint32
	bytes   uint64
	gaps    uint32
	maxSeq  uint32
}

func foldChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// internetChecksum is the RFC 1071 ones-complement checksum over the given
// bytes (the checksum field must be zero in the input).
func internetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return foldChecksum(sum)
}

// udpChecksum computes the RFC 768 checksum over the IPv4 pseudo-header and
// the UDP segment (UDP checksum field must be zero in the input).
func udpChecksum(src, dst [4]byte, udp []byte) uint16 {
	var sum uint32
	sum += uint32(src[0])<<8 | uint32(src[1])
	sum += uint32(src[2])<<8 | uint32(src[3])
	sum += uint32(dst[0])<<8 | uint32(dst[1])
	sum += uint32(dst[2])<<8 | uint32(dst[3])
	sum += 17
	sum += uint32(len(udp))
	for i := 0; i+1 < len(udp); i += 2 {
		sum += uint32(udp[i])<<8 | uint32(udp[i+1])
	}
	if len(udp)%2 == 1 {
		sum += uint32(udp[len(udp)-1]) << 8
	}
	return foldChecksum(sum)
}

func ip4Array(ip net.IP) [4]byte {
	ip4 := ip.To4()
	return [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}
}

// packetBuilder reuses one IPv4/UDP buffer for DATA packets so pumping does
// not allocate per packet. It is not safe for concurrent use; give one to
// each writer goroutine.
type packetBuilder struct {
	src, dst [4]byte
	srcPort  uint16
	dstPort  uint16

	buf     []byte // full IP packet (20-byte IPv4 + 8-byte UDP + payload)
	payload []byte // UDP payload slice inside buf

	// Incremental checksum state: the sealed checksums always match the
	// buffer contents; per packet only the IP ID and the DATA sequence
	// words change, and each is adjusted with O(1) one's-complement math
	// instead of recomputing 1400+ bytes.
	ipSum   uint16 // sealed IPv4 header checksum
	udpSum  uint16 // sealed RFC 768 checksum (pseudo-header + segment)
	prevID  uint16
	prevSeq uint32
}

func newPacketBuilder(src, dst net.IP, srcPort, dstPort, payloadSize int) *packetBuilder {
	b := &packetBuilder{
		src:     ip4Array(src),
		dst:     ip4Array(dst),
		srcPort: uint16(srcPort),
		dstPort: uint16(dstPort),
		buf:     make([]byte, 20+8+payloadSize),
		payload: make([]byte, 0),
	}
	b.payload = b.buf[28:]
	b.buf[0] = 0x45 // IPv4, 20-byte header
	b.buf[8] = 64   // TTL
	b.buf[9] = 17   // UDP
	binary.BigEndian.PutUint16(b.buf[2:4], uint16(len(b.buf)))
	copy(b.buf[12:16], b.src[:])
	copy(b.buf[16:20], b.dst[:])
	binary.BigEndian.PutUint16(b.buf[20:22], b.srcPort)
	binary.BigEndian.PutUint16(b.buf[22:24], b.dstPort)
	binary.BigEndian.PutUint16(b.buf[24:26], uint16(8+payloadSize))
	binary.BigEndian.PutUint32(b.buf[28:32], magicData)
	// Checksums over the initial fields: IP ID 0 and sequence 0. Both are
	// updated incrementally per packet.
	binary.BigEndian.PutUint16(b.buf[10:12], 0)
	b.ipSum = internetChecksum(b.buf[:20])
	binary.BigEndian.PutUint16(b.buf[10:12], b.ipSum)
	b.udpSum = udpChecksum(b.src, b.dst, b.buf[20:])
	binary.BigEndian.PutUint16(b.buf[26:28], b.udpSum)
	return b
}

// updateChecksum16 adjusts a stored one's-complement checksum after one
// 16-bit word at a fixed position changed from oldV to newV. The values
// are the big-endian wire words; position parity is irrelevant when both
// old and new occupy the same 16-bit slot.
func updateChecksum16(sealed uint16, oldV, newV uint16) uint16 {
	c := uint32(^sealed)
	c += uint32(^oldV) + uint32(newV)
	c = (c & 0xffff) + (c >> 16)
	c = (c & 0xffff) + (c >> 16)
	return ^uint16(c)
}

// data fills the reusable buffer for sequence seq/IP ID ipID and returns
// the complete raw IPv4 packet. The returned slice stays valid until the
// next data call on the same builder; tunnel.Write copies before returning.
func (b *packetBuilder) data(ipID uint16, seq uint32) []byte {
	binary.BigEndian.PutUint16(b.buf[4:6], ipID)
	b.ipSum = updateChecksum16(b.ipSum, b.prevID, ipID)
	binary.BigEndian.PutUint16(b.buf[10:12], b.ipSum)
	b.prevID = ipID

	oldHi, oldLo := uint16(b.prevSeq>>16), uint16(b.prevSeq)
	newHi, newLo := uint16(seq>>16), uint16(seq)
	b.udpSum = updateChecksum16(b.udpSum, oldHi, newHi)
	b.udpSum = updateChecksum16(b.udpSum, oldLo, newLo)
	b.prevSeq = seq
	binary.BigEndian.PutUint32(b.payload[4:8], seq)
	binary.BigEndian.PutUint16(b.buf[26:28], b.udpSum)
	return b.buf
}

// buildEndPacket allocates one END packet (8-byte payload).
func buildEndPacket(src, dst net.IP, srcPort, dstPort, ipID uint16, count uint32) []byte {
	pkt := buildSmallPacket(src, dst, srcPort, dstPort, ipID, packetEndPayload(count))
	return pkt
}

// packetEndPayload returns an END payload: magic + DATA packet count.
func packetEndPayload(count uint32) []byte {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint32(payload[0:4], magicEnd)
	binary.BigEndian.PutUint32(payload[4:8], count)
	return payload
}

// buildSmallPacket wraps a short UDP payload in a raw IPv4 packet.
func buildSmallPacket(src, dst net.IP, srcPort, dstPort, ipID uint16, payload []byte) []byte {
	src4 := ip4Array(src)
	dst4 := ip4Array(dst)
	pkt := make([]byte, 20+8+len(payload))
	pkt[0] = 0x45
	pkt[8] = 64
	pkt[9] = 17
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], ipID)
	copy(pkt[12:16], src4[:])
	copy(pkt[16:20], dst4[:])
	binary.BigEndian.PutUint16(pkt[20:22], uint16(srcPort))
	binary.BigEndian.PutUint16(pkt[22:24], uint16(dstPort))
	binary.BigEndian.PutUint16(pkt[24:26], uint16(8+len(payload)))
	copy(pkt[28:], payload)
	binary.BigEndian.PutUint16(pkt[26:28], 0)
	sum := udpChecksum(src4, dst4, pkt[20:])
	binary.BigEndian.PutUint16(pkt[26:28], sum)
	binary.BigEndian.PutUint16(pkt[10:12], internetChecksum(pkt[:20]))
	return pkt
}

// parseInbound validates a raw IPv4 packet and returns the benchmark UDP
// payload when it is addressed to dstPort.
func parseInbound(pkt []byte, dstPort uint16) (parsedPacket, bool) {
	if len(pkt) < 28 || pkt[0]>>4 != 4 || pkt[9] != 17 {
		return parsedPacket{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return parsedPacket{}, false
	}
	if binary.BigEndian.Uint16(pkt[ihl+2:ihl+4]) != dstPort {
		return parsedPacket{}, false
	}
	udpLen := int(binary.BigEndian.Uint16(pkt[ihl+4 : ihl+6]))
	if udpLen < 8 {
		return parsedPacket{}, false
	}
	payloadStart := ihl + 8
	payloadLen := udpLen - 8
	if payloadLen > len(pkt)-payloadStart {
		payloadLen = len(pkt) - payloadStart
	}
	if payloadLen < 8 {
		return parsedPacket{}, false
	}
	payload := pkt[payloadStart : payloadStart+payloadLen]

	out := parsedPacket{
		payloadLen: payloadLen,
		srcIP:      binary.BigEndian.Uint32(pkt[12:16]),
		srcPort:    binary.BigEndian.Uint16(pkt[ihl : ihl+2]),
	}
	switch binary.BigEndian.Uint32(payload[0:4]) {
	case magicData:
		if payloadLen < minUDPPayload {
			return parsedPacket{}, false
		}
		out.kind = packetData
		out.seq = binary.BigEndian.Uint32(payload[4:8])
	case magicEnd:
		out.kind = packetEnd
		out.count = binary.BigEndian.Uint32(payload[4:8])
	case magicStat:
		if payloadLen < 24 {
			return parsedPacket{}, false
		}
		out.kind = packetStat
		out.stat.packets = binary.BigEndian.Uint32(payload[4:8])
		out.stat.bytes = binary.BigEndian.Uint64(payload[8:16])
		out.stat.gaps = binary.BigEndian.Uint32(payload[16:20])
		out.stat.maxSeq = binary.BigEndian.Uint32(payload[20:24])
	default:
		out.kind = packetUnknown
	}
	return out, true
}
