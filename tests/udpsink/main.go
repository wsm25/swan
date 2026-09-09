// Command udpsink is the responder-side endpoint of the swan4 private UDP
// throughput benchmark.
//
// Mode "up" binds 0.0.0.0:-port and counts DATA packets until an END packet
// (or SIGINT/SIGTERM); it then drains in-flight DATA for 500ms and replies
// with a STAT packet 3x.
//
// Mode "down" pumps DATA packets to -dst as fast as the socket allows for
// -dur and replies with a STAT packet 3x carrying its own sent counts.
//
// The benchmark protocol is intentionally private and dumb:
//
//	DATA: [u32 "SWAN"][u32 seq][zeros to -size]
//	END:  [u32 "ENDS"][u32 count]
//	STAT: [u32 "STAT"][u32 packets][u64 bytes][u32 gaps][u32 maxseq]
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"
)

const (
	magicData uint32 = 0x5357414e // "SWAN"
	magicEnd  uint32 = 0x454e4453 // "ENDS"
	magicStat uint32 = 0x53544154 // "STAT"

	defaultDuration = 30 * time.Second
	maxDuration     = 60 * time.Second

	drainAfterEnd = 500 * time.Millisecond
	statRepeatGap = 50 * time.Millisecond
)

func main() {
	var (
		mode = flag.String("mode", "up", "sink direction: up (receive+count) or down (pump DATA)")
		dst  = flag.String("dst", "10.31.0.1:55555", "DATA destination for down mode (host:port)")
		dur  = flag.Duration("dur", defaultDuration, "pump duration for down mode (cap 60s)")
		port = flag.Int("port", 55555, "UDP port (up mode) / DATA dst port is part of -dst")
		size = flag.Int("size", 1400, "DATA UDP payload size (>= 12)")
		rate = flag.Int("rate", 180000, "target DATA packets/sec for down mode (0 = as fast as socket allows)")
	)
	flag.Parse()

	switch *mode {
	case "up":
		if err := runUp(*port); err != nil {
			fmt.Fprintln(os.Stderr, "up:", err)
			os.Exit(1)
		}
	case "down":
		if err := runDown(*dst, *dur, *size, *rate); err != nil {
			fmt.Fprintln(os.Stderr, "down:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "mode must be up or down")
		os.Exit(2)
	}
}

func runUp(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be 1..65535")
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetReadBuffer(16 << 20)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	sigArrived := make(chan struct{}, 1)
	go func() {
		<-sigCh
		sigArrived <- struct{}{}
		// Unblock the in-flight ReadFromUDP immediately. The main loop
		// then re-arms a short drain deadline so a SIGINT/SIGTERM ends the
		// benchmark the same way as an END packet.
		_ = conn.SetReadDeadline(time.Now())
	}()

	var (
		packets    uint64
		bytes      uint64
		gaps       uint64
		maxSeq     uint32
		src        *net.UDPAddr
		endAt      time.Time
		signalSeen bool
	)
	buf := make([]byte, 65535)
	for {
		if signalSeen && endAt.IsZero() {
			endAt = time.Now().Add(drainAfterEnd)
			_ = conn.SetReadDeadline(endAt)
		}
		if !endAt.IsZero() && time.Now().After(endAt) {
			break
		}
		n, from, readErr := conn.ReadFromUDP(buf)
		if readErr != nil {
			if isTimeout(readErr) {
				select {
				case <-sigArrived:
					signalSeen = true
				default:
				}
				if signalSeen && endAt.IsZero() {
					endAt = time.Now().Add(drainAfterEnd)
					_ = conn.SetReadDeadline(endAt)
					continue
				}
				if !endAt.IsZero() && time.Now().After(endAt) {
					break
				}
				continue
			}
			return readErr
		}
		if src == nil {
			src = from
		}

		switch classify(buf[:n]) {
		case "data":
			seq := binary.BigEndian.Uint32(buf[4:8])
			if seq <= maxSeq || (maxSeq != 0 && seq > maxSeq+1) {
				gaps++
			}
			if seq > maxSeq {
				maxSeq = seq
			}
			packets++
			bytes += uint64(n)
		case "end":
			if endAt.IsZero() {
				endAt = time.Now().Add(drainAfterEnd)
				_ = conn.SetReadDeadline(endAt)
			}
		}
		// Non-DATA/END datagrams (e.g. random network noise) are ignored.
	}

	if src == nil {
		fmt.Println("STAT up pkts=0 bytes=0 gaps=0 maxseq=0")
		return nil
	}
	sendStat(conn, src, packets, bytes, gaps, maxSeq)
	fmt.Printf("STAT up pkts=%d bytes=%d gaps=%d maxseq=%d\n", packets, bytes, gaps, maxSeq)
	return nil
}

func runDown(dst string, dur time.Duration, size, rate int) error {
	if size < 12 {
		return fmt.Errorf("size must be >= 12")
	}
	if rate < 0 {
		return fmt.Errorf("rate must be >= 0")
	}
	if dur <= 0 {
		return fmt.Errorf("dur must be > 0")
	}
	if dur > maxDuration {
		fmt.Fprintf(os.Stderr, "dur %s exceeds cap %s; using %s\n", dur, maxDuration, maxDuration)
		dur = maxDuration
	}
	addr, err := net.ResolveUDPAddr("udp4", dst)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetWriteBuffer(16 << 20)

	payload := make([]byte, size)
	binary.BigEndian.PutUint32(payload[0:4], magicData)

	var (
		packets uint64
		bytes   uint64
		seq     uint32
		pacer   *packetPacer
	)
	if rate > 0 {
		pacer = newPacketPacer(rate)
	}
	end := time.Now().Add(dur)
	for time.Now().Before(end) {
		pacer.wait()
		seq++
		binary.BigEndian.PutUint32(payload[4:8], seq)
		if _, err := conn.Write(payload); err != nil {
			return err
		}
		packets++
		bytes += uint64(len(payload))
	}

	sendStat(conn, nil, packets, bytes, 0, seq)
	fmt.Printf("STAT down pkts=%d bytes=%d gaps=0 maxseq=%d\n", packets, bytes, seq)
	return nil
}

func sendStat(conn *net.UDPConn, peer *net.UDPAddr, packets, bytes, gaps uint64, maxSeq uint32) {
	payload := make([]byte, 24)
	binary.BigEndian.PutUint32(payload[0:4], magicStat)
	binary.BigEndian.PutUint32(payload[4:8], uint32(packets))
	binary.BigEndian.PutUint64(payload[8:16], bytes)
	binary.BigEndian.PutUint32(payload[16:20], uint32(gaps))
	binary.BigEndian.PutUint32(payload[20:24], maxSeq)
	for i := 0; i < 3; i++ {
		if peer == nil {
			_, _ = conn.Write(payload)
		} else {
			_, _ = conn.WriteToUDP(payload, peer)
		}
		if i < 2 {
			time.Sleep(statRepeatGap)
		}
	}
}

func classify(payload []byte) string {
	if len(payload) < 8 {
		return ""
	}
	switch binary.BigEndian.Uint32(payload[0:4]) {
	case magicData:
		if len(payload) >= 12 {
			return "data"
		}
	case magicEnd:
		return "end"
	}
	return ""
}

type packetPacer struct {
	mu     sync.Mutex
	next   time.Time
	sprint time.Duration
}

func newPacketPacer(rate int) *packetPacer {
	if rate <= 0 {
		return nil
	}
	return &packetPacer{sprint: time.Second / time.Duration(rate)}
}

// wait aligns to the next theoretical send slot. High rates cannot use
// wall-clock timers (host timer floor ~1ms: ms-sized bursts overflow the
// xfrm/UDP path), so this spins in the pump goroutine. It is benchmark
// harness code; delivery accuracy matters more than CPU.
func (p *packetPacer) wait() {
	if p == nil {
		return
	}
	p.mu.Lock()
	now := time.Now()
	if p.next.Before(now) {
		p.next = now
	}
	target := p.next
	p.next = p.next.Add(p.sprint)
	p.mu.Unlock()

	if d := time.Until(target); d > 0 {
		if d > time.Millisecond {
			time.Sleep(d - 500*time.Microsecond)
		}
		for time.Now().Before(target) {
			runtime.Gosched()
		}
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
