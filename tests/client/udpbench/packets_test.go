package main

import (
	"encoding/binary"
	"math/rand"
	"net"
	"testing"
)

// The incremental checksum path must match a fresh RFC 1071/768
// recomputation for arbitrary ID/sequence progressions.
func TestIncrementalChecksums(t *testing.T) {
	build := func(id uint16, seq uint32) []byte {
		b := newPacketBuilder(net.IPv4(10, 31, 0, 1), net.IPv4(10, 12, 23, 50), 55555, 55555, 1400)
		return b.data(id, seq)
	}
	r := rand.New(rand.NewSource(42))
	id := uint16(0)
	seq := uint32(0)
	for i := 0; i < 20000; i++ {
		id += uint16(r.Intn(7))
		seq += uint32(r.Intn(4093)) + 1
		pkt := build(id, seq)

		ip := binary.BigEndian.Uint16(pkt[10:12])
		pkt[10], pkt[11] = 0, 0
		fullIP := internetChecksum(pkt[:20])
		if ip != fullIP {
			t.Fatalf("ip checksum mismatch id=%d: incremental=%#x full=%#x", id, ip, fullIP)
		}

		udp := binary.BigEndian.Uint16(pkt[26:28])
		pkt[26], pkt[27] = 0, 0
		var src, dst [4]byte
		copy(src[:], pkt[12:16])
		copy(dst[:], pkt[16:20])
		fullUDP := udpChecksum(src, dst, pkt[20:])
		if udp != fullUDP {
			t.Fatalf("udp checksum mismatch seq=%d: incremental=%#x full=%#x", seq, udp, fullUDP)
		}
	}
}
