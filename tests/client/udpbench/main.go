// Command udpbench drives the swan4 ESP tunnel as a private UDP throughput
// benchmark.
//
// Mode "up" pumps DATA packets into the tunnel toward a UDP sink running
// inside the responder container. Mode "down" is a userspace sink for the
// responder's own pump, proving inbound decrypt throughput.
//
// The benchmark protocol is intentionally private and dumb:
//
//	DATA: [u32 "SWAN"][u32 seq][zeros to -size]
//	END:  [u32 "ENDS"][u32 count]
//	STAT: [u32 "STAT"][u32 packets][u64 bytes][u32 gaps][u32 maxseq]
//
// Run from tests/client:
//
//	SSL_CERT_FILE=../docker/certs/caCert.pem go run ./udpbench -mode up
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	swan "swan"
	"swan4-tests/wiretest"
)

const (
	defaultDuration = 30 * time.Second
	maxDuration     = 10 * time.Minute
	postPumpWait    = 500 * time.Millisecond
	endRepeatGap    = 50 * time.Millisecond
	statWait        = 3 * time.Second
	shutdownTimeout = 10 * time.Second
)

func main() {
	var (
		mode       = flag.String("mode", "up", "benchmark direction: up (client pumps) or down (client sinks)")
		server     = flag.String("server", "127.0.0.1:4500", "strongSwan address (host:port)")
		peer       = flag.String("peer", "10.12.23.50", "inner destination IP for the UDP sink/pump")
		size       = flag.Int("size", 1400, "UDP payload size (>= 12)")
		dur        = flag.Duration("dur", defaultDuration, "measurement duration (cap 60s)")
		port       = flag.Int("port", 55555, "benchmark UDP destination port")
		writers    = flag.Int("writers", 2, "number of concurrent pump writers (up mode)")
		rate       = flag.Int("rate", 180000, "target DATA packets/sec for up mode (0 = as fast as possible)")
		eapUser    = flag.String("eap-user", "testuser", "EAP/MSCHAPv2 identity")
		eapPass    = flag.String("eap-pass", "testpassword", "EAP/MSCHAPv2 password")
		eventLog   = flag.Bool("event-log", false, "print session events")
		cpuProfile = flag.String("cpuprofile", "", "write CPU profile to this file")
		memProfile = flag.String("memprofile", "", "write heap profile to this file")
		hexDump    = flag.Bool("hex-dump", false, "hex-dump raw wire datagrams")
		ikeSpec    = flag.String("ike-spec", "aes256gcm16-prfsha512-curve25519", "IKE proposal (MVP default; local container uses aes256-sha512-prfsha512-curve25519)")
		espSpec    = flag.String("esp-spec", "aes256gcm16-prfsha512-curve25519", "ESP proposal")
	)
	flag.Parse()

	if *mode != "up" && *mode != "down" {
		fmt.Fprintln(os.Stderr, "mode must be up or down")
		os.Exit(2)
	}
	if *size < minUDPPayload {
		fmt.Fprintf(os.Stderr, "size must be >= %d\n", minUDPPayload)
		os.Exit(2)
	}
	if *port < 1 || *port > 65535 {
		fmt.Fprintln(os.Stderr, "port must be 1..65535")
		os.Exit(2)
	}
	if *writers < 1 {
		fmt.Fprintln(os.Stderr, "writers must be >= 1")
		os.Exit(2)
	}
	if *rate < 0 {
		fmt.Fprintln(os.Stderr, "rate must be >= 0")
		os.Exit(2)
	}
	if *dur <= 0 {
		fmt.Fprintln(os.Stderr, "dur must be > 0")
		os.Exit(2)
	}
	if *dur > maxDuration {
		fmt.Fprintf(os.Stderr, "dur %s exceeds cap %s; using %s\n", *dur, maxDuration, maxDuration)
		*dur = maxDuration
	}

	// Block/mutex profiling: the biggest suspect for the remaining
	// per-packet cost is scheduler/wakeup overhead, which the CPU profiler
	// cannot see directly.
	runtime.SetBlockProfileRate(1)
	runtime.SetMutexProfileFraction(1)
	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cpuprofile:", err)
			os.Exit(1)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			fmt.Fprintln(os.Stderr, "cpuprofile:", err)
			os.Exit(1)
		}
		defer pprof.StopCPUProfile()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	wire, session, tunnel, err := setupTunnel(ctx, *server, *eapUser, *eapPass, *ikeSpec, *espSpec, *eventLog, *hexDump)
	if err != nil {
		fmt.Fprintln(os.Stderr, "setup:", err)
		os.Exit(1)
	}
	defer wire.Close()

	switch *mode {
	case "up":
		if err := runUp(ctx, tunnel, *peer, *port, *size, *writers, *rate, *dur); err != nil {
			fmt.Fprintln(os.Stderr, "up:", err)
		}
	case "down":
		if err := runDown(ctx, tunnel, *peer, *port, *dur); err != nil {
			fmt.Fprintln(os.Stderr, "down:", err)
		}
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer stopCancel()
	if err := session.Stop(stopCtx); err != nil {
		fmt.Fprintln(os.Stderr, "stop:", err)
		os.Exit(1)
	}
	fmt.Println("closed")

	if *memProfile != "" {
		f, err := os.Create(*memProfile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "memprofile:", err)
			os.Exit(1)
		}
		_ = pprof.WriteHeapProfile(f)
		f.Close()
	}
	for _, name := range []string{"block", "mutex"} {
		p := pprof.Lookup(name)
		if p == nil {
			continue
		}
		f, err := os.Create(name + ".prof")
		if err != nil {
			fmt.Fprintln(os.Stderr, name+":", err)
			os.Exit(1)
		}
		_ = p.WriteTo(f, 0)
		f.Close()
	}
}

// setupTunnel builds the MVP-profile session exactly like the debug client
// and drives the handshake to completion.
func setupTunnel(ctx context.Context, server, eapUser, eapPass, ikeSpec, espSpec string, eventLog, hexDump bool) (*wiretest.UDPWire, *swan.Session, *swan.Tunnel, error) {
	var logger *slog.Logger
	if eventLog {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	wire, err := wiretest.NewUDPWire(server, &hexDump)
	if err != nil {
		return nil, nil, nil, err
	}

	host, _, err := net.SplitHostPort(server)
	if err != nil {
		wire.Close()
		return nil, nil, nil, fmt.Errorf("server: %w", err)
	}
	peerIP := net.ParseIP(host)
	if peerIP == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			wire.Close()
			return nil, nil, nil, fmt.Errorf("server: resolve %s failed: %w", host, err)
		}
		peerIP = ips[0]
	}

	cfg := swan.DefaultConfig(peerIP)
	ike, esp, err := swan.ParseStrongswanProposals(ikeSpec, espSpec)
	if err != nil {
		wire.Close()
		return nil, nil, nil, fmt.Errorf("proposals: %w", err)
	}
	cfg.IKEProposals = ike
	cfg.ESPProposals = esp
	cfg.IDI = "%config"
	cfg.RightID = "@stu.vpn.sjtu.edu.cn"
	cfg.AAAIdentity = "@radius.net.sjtu.edu.cn"
	cfg.EAP.Method = "peap"
	cfg.EAP.Identity = eapUser
	cfg.EAP.Password = eapPass
	cfg.EAP.ServerName = "@radius.net.sjtu.edu.cn"

	if err := cfg.Validate(); err != nil {
		wire.Close()
		return nil, nil, nil, fmt.Errorf("config: %w", err)
	}

	session, err := swan.NewSession(wire, &cfg, swan.WithLogger(logger))
	if err != nil {
		wire.Close()
		return nil, nil, nil, fmt.Errorf("session: %w", err)
	}

	tunnel, err := session.Start(ctx)
	if err != nil {
		wire.Close()
		return nil, nil, nil, fmt.Errorf("handshake: %w", err)
	}
	assigned := tunnel.Assigned()
	fmt.Printf("tunnel up: ipv4=%v ipv6=%v dns4=%v dns6=%v\n",
		assigned.InternalIPv4, assigned.InternalIPv6, assigned.DNS4, assigned.DNS6)
	return wire, session, tunnel, nil
}

type measureWindow struct {
	start time.Time
	end   time.Time
}

type sinkStats struct {
	packets atomic.Uint64
	bytes   atomic.Uint64
	gaps    atomic.Uint64
	maxSeq  atomic.Uint64
	lastSrc atomic.Uint64 // upper 32 bits = IPv4 src, lower 16 bits = src port
}

func (s *sinkStats) addData(seq uint32, payloadLen int) {
	if payloadLen < minUDPPayload {
		return
	}
	prev := s.maxSeq.Load()
	for {
		if uint64(seq) <= prev {
			s.gaps.Add(1)
			break
		}
		if prev != 0 && uint64(seq) > prev+1 {
			s.gaps.Add(1)
		}
		if s.maxSeq.CompareAndSwap(prev, uint64(seq)) {
			break
		}
		prev = s.maxSeq.Load()
	}
	s.packets.Add(1)
	s.bytes.Add(uint64(payloadLen))
}

func (s *sinkStats) noteSrc(srcIP uint32, srcPort uint16) {
	s.lastSrc.Store(uint64(srcIP)<<16 | uint64(srcPort))
}

func (s *sinkStats) snapshot() (packets, bytes, gaps, maxSeq uint64) {
	return s.packets.Load(), s.bytes.Load(), s.gaps.Load(), s.maxSeq.Load()
}

func (s *sinkStats) snapshotSrc() (uint32, uint16) {
	v := s.lastSrc.Load()
	return uint32(v >> 16), uint16(v)
}

// readLoop classifies inbound raw IP and feeds STAT payloads to statCh. When
// window is non-nil it also counts DATA packets arriving in that window.
func readLoop(tunnel *swan.Tunnel, port uint16, window *measureWindow, stats *sinkStats, statCh chan<- statPayload) {
	buf := make([]byte, 65535)
	for {
		n, err := tunnel.Read(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		pkt, ok := parseInbound(buf[:n], port)
		if !ok {
			continue
		}
		switch pkt.kind {
		case packetStat:
			select {
			case statCh <- pkt.stat:
			default:
			}
		case packetData:
			if stats != nil {
				stats.noteSrc(pkt.srcIP, pkt.srcPort)
				if window != nil {
					now := time.Now()
					if !now.Before(window.start) && !now.After(window.end) {
						stats.addData(pkt.seq, pkt.payloadLen)
					}
				}
			}
		}
	}
}

func waitDur(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func sendEndX3(tunnel *swan.Tunnel, src, dst net.IP, srcPort, dstPort int, count uint32) error {
	id := uint16(time.Now().UnixNano())
	sp := uint16(srcPort)
	dp := uint16(dstPort)
	for i := 0; i < 3; i++ {
		pkt := buildEndPacket(src, dst, sp, dp, id, count)
		if _, err := tunnel.Write(pkt); err != nil {
			return err
		}
		id++
		if i < 2 {
			time.Sleep(endRepeatGap)
		}
	}
	return nil
}

// packetPacer rate-limits sends without burning CPU in a spin loop: one
// goroutine mints token batches on a coarse ticker and writers block on a
// token channel. Token-queue saturation naturally caps the offered rate.
type packetPacer struct {
	// spin-mode pacing: next = the next send slot, sprint = slot interval.
	mu     sync.Mutex
	next   time.Time
	sprint time.Duration

	// token-mode pacing (low rates only): tokens arrive via a ticker
	// goroutine; writers block on the channel rather than spin.
	tokens chan struct{}
	stop   chan struct{}
	done   chan struct{}
}

func newPacketPacer(rate int) *packetPacer {
	if rate <= 0 {
		return nil
	}
	// High rates cannot be smoothed with wall-clock timers (host timer
	// floor ~1ms): ms-sized token bursts overflow the container's UDP
	// path at ~170kpps, so fast rates keep the spin pacer. It burns CPU
	// in this BENCHMARK HARNESS only, where offered-load precision
	// matters more. Low rates use blocking token slots (zero spin).
	if rate < 2500 {
		return newTokenPacer(rate)
	}
	return &packetPacer{
		mu:     sync.Mutex{},
		sprint: time.Second / time.Duration(rate),
	}
}

// newTokenPacer builds the blocking no-spin pacer for low rates.
func newTokenPacer(rate int) *packetPacer {
	slot := time.Millisecond
	batch := rate * int(slot/time.Millisecond) / 1000
	if batch < 1 {
		batch = 1
		slot = time.Second / time.Duration(rate)
	}

	p := &packetPacer{
		tokens: make(chan struct{}, 2*batch),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		sprint: time.Second / time.Duration(rate),
	}
	go func() {
		defer close(p.done)
		t := time.NewTicker(slot)
		defer t.Stop()
		for {
			select {
			case <-p.stop:
				return
			case <-t.C:
				for i := 0; i < batch; i++ {
					select {
					case p.tokens <- struct{}{}:
					case <-p.stop:
						return
					}
				}
			}
		}
	}()
	return p
}

// wait reserves one send slot. Spin mode busily aligns to the theoretical
// sending moment; token mode parks on the token channel.
func (p *packetPacer) wait() {
	if p == nil {
		return
	}
	if p.tokens != nil {
		<-p.tokens
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

func (p *packetPacer) closePacer() {
	if p == nil {
		return
	}
	if p.tokens != nil {
		close(p.stop)
		<-p.done
	}
}

func waitStat(ctx context.Context, statCh <-chan statPayload) (statPayload, bool) {
	timer := time.NewTimer(statWait)
	defer timer.Stop()
	for {
		select {
		case st := <-statCh:
			return st, true
		case <-ctx.Done():
			return statPayload{}, false
		case <-timer.C:
			return statPayload{}, false
		}
	}
}

func runUp(ctx context.Context, tunnel *swan.Tunnel, peer string, port, size, writers, rate int, dur time.Duration) error {
	assigned := tunnel.Assigned()
	src := assigned.InternalIPv4.To4()
	if src == nil {
		return fmt.Errorf("assigned IPv4 address is nil")
	}
	dst := net.ParseIP(peer).To4()
	if dst == nil {
		return fmt.Errorf("peer %q is not an IPv4 address", peer)
	}

	statCh := make(chan statPayload, 16)
	go readLoop(tunnel, uint16(port), nil, nil, statCh)

	fmt.Printf("up sending: writers=%d size=%d rate=%d dur=%s\n", writers, size, rate, dur)
	stop := make(chan struct{})
	var seq atomic.Uint64
	var ipID atomic.Uint64
	var sentPackets atomic.Uint64
	var sentBytes atomic.Uint64
	var pacer *packetPacer
	if rate > 0 {
		pacer = newPacketPacer(rate)
	}
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pb := newPacketBuilder(src, dst, port, port, size)
			for {
				select {
				case <-stop:
					return
				default:
				}
				pacer.wait()
				s := seq.Add(1)
				id := uint16(ipID.Add(1))
				pkt := pb.data(id, uint32(s))
				if _, err := tunnel.Write(pkt); err != nil {
					return
				}
				sentPackets.Add(1)
				sentBytes.Add(uint64(size))
			}
		}()
	}

	if err := waitDur(ctx, dur); err != nil {
		close(stop)
		wg.Wait()
		pacer.closePacer()
		return err
	}
	close(stop)
	wg.Wait()
	pacer.closePacer()

	// Let the last in-flight DATA packets settle before END; the sink then
	// drains for another 500ms per the protocol.
	time.Sleep(postPumpWait)

	packets := sentPackets.Load()
	bytes := sentBytes.Load()
	secs := dur.Seconds()
	fmt.Printf("up sent=%d bytes=%d pps=%.1f mbps=%.3f\n",
		packets, bytes, float64(packets)/secs, float64(bytes)*8/secs/1e6)

	count := uint32(packets)
	if packed := packets >> 32; packed != 0 {
		count = ^uint32(0)
	}
	if err := sendEndX3(tunnel, src, dst, port, port, count); err != nil {
		return fmt.Errorf("send END: %w", err)
	}

	st, ok := waitStat(ctx, statCh)
	if !ok {
		fmt.Println("up stat: no STAT reply")
		return nil
	}
	loss := 0.0
	if packets > 0 {
		if uint64(st.packets) > packets {
			loss = 0
		} else {
			loss = float64(packets-uint64(st.packets)) / float64(packets) * 100
		}
	}
	fmt.Printf("up stat pkts=%d bytes=%d gaps=%d maxseq=%d loss=%.2f%%\n",
		st.packets, st.bytes, st.gaps, st.maxSeq, loss)
	return nil
}

func runDown(ctx context.Context, tunnel *swan.Tunnel, peer string, port int, dur time.Duration) error {
	assigned := tunnel.Assigned()
	src := assigned.InternalIPv4.To4()
	if src == nil {
		return fmt.Errorf("assigned IPv4 address is nil")
	}

	fmt.Printf("ready-for-pump\n")
	start := time.Now()
	window := &measureWindow{start: start, end: start.Add(dur)}
	stats := &sinkStats{}
	statCh := make(chan statPayload, 16)
	go readLoop(tunnel, uint16(port), window, stats, statCh)

	// Stay in receive-measurement window for -dur; continue reading after
	// it so the final STAT (and any in-flight DATA) still get consumed.
	if err := waitDur(ctx, dur); err != nil {
		return err
	}

	recvPackets, recvBytes, recvGaps, recvMaxSeq := stats.snapshot()
	secs := dur.Seconds()
	fmt.Printf("down recv=%d bytes=%d pps=%.1f mbps=%.3f\n",
		recvPackets, recvBytes, float64(recvPackets)/secs, float64(recvBytes)*8/secs/1e6)

	if recvPackets > 0 {
		var (
			dst     net.IP
			dstPort = port
		)
		if srcIP, srcPort := stats.snapshotSrc(); srcIP != 0 && srcPort != 0 {
			dst = net.IPv4(byte(srcIP>>24), byte(srcIP>>16), byte(srcIP>>8), byte(srcIP)).To4()
			dstPort = int(srcPort)
		} else {
			dst = net.ParseIP(peer).To4()
		}
		if dst == nil {
			return fmt.Errorf("peer %q is not an IPv4 address", peer)
		}
		if err := sendEndX3(tunnel, src, dst, port, dstPort, uint32(recvPackets)); err != nil {
			return fmt.Errorf("send END: %w", err)
		}
	}

	st, ok := waitStat(ctx, statCh)
	if !ok {
		fmt.Printf("down stat: no STAT reply (recv gaps=%d maxseq=%d)\n", recvGaps, recvMaxSeq)
		return nil
	}
	loss := 0.0
	if st.packets > 0 {
		if recvPackets > uint64(st.packets) {
			loss = 0
		} else {
			loss = float64(uint64(st.packets)-recvPackets) / float64(st.packets) * 100
		}
	}
	fmt.Printf("down stat pkts=%d bytes=%d gaps=%d maxseq=%d loss=%.2f%%\n",
		st.packets, st.bytes, st.gaps, st.maxSeq, loss)
	return nil
}
