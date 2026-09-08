// swan4 debug client.
//
// This is integration/debug code, not part of the swan library: it owns a
// real UDP socket and adapts UDP datagrams into the swan stream framing
// ([u16 big-endian length][payload]) that the library expects on its
// injected io.ReadWriteCloser. Run it against the strongSwan container from
// tests/docker:
//
//	SSL_CERT_FILE=../docker/certs/caCert.pem go run . -server 127.0.0.1:4500
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	swan "swan"
	"swan/events"
)

// udpWire adapts a connected UDP socket (*net.UDPConn implements
// Read/Write/Close on datagrams) into the swan byte-stream wire format.
type udpWire struct {
	conn *net.UDPConn
	hex  *bool

	// writeBuf accumulates the stream until complete frames can be sent.
	writeBuf []byte
	// readBuf holds the current frame being delivered to Read callers.
	readBuf []byte
	readOff int
}

func newUDPWire(server string, hex *bool) (*udpWire, error) {
	addr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", server, err)
	}
	var laddr *net.UDPAddr
	if addr.IP.IsLoopback() {
		if addr.IP.To4() != nil {
			laddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
		} else {
			laddr = &net.UDPAddr{IP: net.IPv6loopback}
		}
	}
	conn, err := net.DialUDP("udp", laddr, addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", server, err)
	}
	return &udpWire{conn: conn, hex: hex}, nil
}

// Read serves one stream byte at a time from the current frame; when the
// frame is exhausted the next UDP datagram is fetched and re-framed.
func (w *udpWire) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for w.readOff == len(w.readBuf) {
		buf := make([]byte, 65535)
		n, err := w.conn.Read(buf)
		if err != nil {
			return 0, err
		}
		// Stream frame: u16 big-endian length + datagram payload.
		if w.hex != nil && *w.hex {
			fmt.Printf("wire recv %d: %x\n", n, buf[:n])
		}
		w.readBuf = make([]byte, 2+n)
		w.readBuf[0] = byte(n >> 8)
		w.readBuf[1] = byte(n)
		copy(w.readBuf[2:], buf[:n])
		w.readOff = 0
	}
	n := copy(p, w.readBuf[w.readOff:])
	w.readOff += n
	return n, nil
}

// Write buffers stream bytes and emits every complete frame as one UDP
// datagram to the connected peer.
func (w *udpWire) Write(p []byte) (int, error) {
	w.writeBuf = append(w.writeBuf, p...)
	off := 0
	for len(w.writeBuf)-off >= 2 {
		length := int(w.writeBuf[off])<<8 | int(w.writeBuf[off+1])
		if len(w.writeBuf)-off < 2+length {
			break
		}
		if w.hex != nil && *w.hex {
			fmt.Printf("wire send %d: %x\n", length, w.writeBuf[off+2:off+2+length])
		}
		if _, err := w.conn.Write(w.writeBuf[off+2 : off+2+length]); err != nil {
			return 0, err
		}
		off += 2 + length
	}
	w.writeBuf = append(w.writeBuf[:0], w.writeBuf[off:]...)
	return len(p), nil
}

func (w *udpWire) Close() error { return w.conn.Close() }

func main() {
	var (
		server   = flag.String("server", "127.0.0.1:4500", "strongSwan address (host:port)")
		eapUser  = flag.String("eap-user", "testuser", "EAP/MSCHAPv2 identity")
		eapPass  = flag.String("eap-pass", "testpassword", "EAP/MSCHAPv2 password")
		eventLog = flag.Bool("event-log", true, "print session events and packet summaries")
		hexDump  = flag.Bool("hex-dump", false, "hex-dump raw wire datagrams")
		ikeSpec  = flag.String("ike-spec", "aes256gcm16-prfsha512-curve25519", "IKE proposal (MVP default; local container uses aes256-sha512-prfsha512-curve25519)")
		espSpec  = flag.String("esp-spec", "aes256gcm16-prfsha512-curve25519", "ESP proposal")
	)
	flag.Parse()

	level := slog.LevelWarn
	var logger *slog.Logger
	if *eventLog {
		level = slog.LevelDebug
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	wire, err := newUDPWire(*server, hexDump)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wire:", err)
		os.Exit(1)
	}
	defer wire.Close()

	host, _, err := net.SplitHostPort(*server)
	if err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		os.Exit(1)
	}
	peerIP := net.ParseIP(host)
	if peerIP == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			fmt.Fprintln(os.Stderr, "server: resolve", host, "failed:", err)
			os.Exit(1)
		}
		peerIP = ips[0]
	}

	// MVP-profile configuration (mirrors swan2 config.toml shape).
	cfg := swan.DefaultConfig(peerIP)
	ike, esp, err := swan.ParseStrongswanProposals(*ikeSpec, *espSpec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "proposals:", err)
		os.Exit(1)
	}
	cfg.IKEProposals = ike
	cfg.ESPProposals = esp
	cfg.IDI = "%config"
	cfg.RightID = "@stu.vpn.sjtu.edu.cn"
	cfg.AAAIdentity = "@radius.net.sjtu.edu.cn"
	cfg.EAP.Method = "peap"
	cfg.EAP.Identity = *eapUser
	cfg.EAP.Password = *eapPass
	cfg.EAP.ServerName = "@radius.net.sjtu.edu.cn"

	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}

	session, err := swan.NewSession(wire, &cfg, swan.WithLogger(logger))
	if err != nil {
		fmt.Fprintln(os.Stderr, "session:", err)
		os.Exit(1)
	}

	stopEvents := make(chan struct{})
	defer close(stopEvents)
	go func() {
		stream := session.Events()
		defer stream.Close()
		for {
			select {
			case ev, ok := <-stream.C():
				if !ok {
					return
				}
				printEvent(ev)
			case <-stopEvents:
				return
			}
		}
	}()

	fmt.Println("starting handshake against", *server)
	tunnel, err := session.Start(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "handshake:", err)
		os.Exit(1)
	}
	assigned := tunnel.Assigned()
	fmt.Printf("tunnel up: ipv4=%v ipv6=%v dns4=%v dns6=%v\n",
		assigned.InternalIPv4, assigned.InternalIPv6, assigned.DNS4, assigned.DNS6)

	// Pressure the ESP data plane: answer IPv4 ICMP echo requests from the
	// responder (e.g. `podman exec swan4-ss ping 10.31.0.1`), proving both
	// inbound ESP decrypt and outbound ESP encrypt work end to end.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := tunnel.Read(buf)
			if err != nil {
				if *eventLog {
					fmt.Println("tunnel read end:", err)
				}
				return
			}
			if n == 0 {
				continue
			}
			pkt := buf[:n]
			if *eventLog {
				ver := pkt[0] >> 4
				fmt.Printf("esp packet: version=%d len=%d\n", ver, n)
			}
			if reply, ok := icmpEchoReply(pkt); ok {
				if _, err := tunnel.Write(reply); err != nil {
					fmt.Println("ping reply send:", err)
					return
				}
				fmt.Println("ping reply sent")
			}
		}
	}()

	// Idle IKE keepalives run on their own; wait for Ctrl-C, then perform
	// the graceful close sequence (CHILD_SA DELETE, IKE_SA DELETE).
	<-ctx.Done()
	fmt.Println("closing...")
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()
	if err := session.Stop(stopCtx); err != nil {
		fmt.Fprintln(os.Stderr, "stop:", err)
		os.Exit(1)
	}
	fmt.Println("closed")
}

func printEvent(ev events.Event) {
	switch ev.Kind {
	case events.EventStageChanged:
		fmt.Printf("event: StageChanged(%s)\n", stageName(ev.Stage))
	case events.EventNegotiatedAlgorithm:
		a := ev.Alg
		fmt.Printf("negotiated: %s %s/%s PRF=%s DH=%s\n",
			a.Protocol, a.Encryption, orDash(a.Integrity), orDash(a.PRF), orDash(a.DH))
	case events.EventEapProcess:
		fmt.Printf("event: EapProcess(%s %s round=%d)\n", ev.EAP.Method, ev.EAP.State, ev.EAP.Round)
	case events.EventConfigAssigned:
		fmt.Printf("event: ConfigAssigned(%+v)\n", ev.Assigned)
	case events.EventBroken:
		fmt.Printf("event: Broken(%s)\n", ev.Reason)
	default:
		fmt.Printf("event: %d (stage=%s)\n", ev.Kind, stageName(ev.Stage))
	}
}

func stageName(s events.Stage) string {
	switch s {
	case events.StageIKEInit:
		return "ike_init"
	case events.StageIKEAuth:
		return "ike_auth"
	case events.StageEAP:
		return "eap"
	case events.StageChildSA:
		return "child_sa"
	case events.StageRunning:
		return "running"
	default:
		return fmt.Sprintf("#%d", s)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// icmpEchoReply recognizes an IPv4 ICMP Echo Request and builds the matching
// Echo Reply (swapped addresses, type 8 -> 0, recomputed ICMP checksum).
func icmpEchoReply(pkt []byte) ([]byte, bool) {
	if len(pkt) < 28 || pkt[0]>>4 != 4 || pkt[9] != 1 || pkt[20] != 8 {
		return nil, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return nil, false
	}
	reply := append([]byte(nil), pkt...)
	// Swap source and destination IPv4 addresses.
	copy(reply[12:16], pkt[16:20])
	copy(reply[16:20], pkt[12:16])
	reply[ihl] = 0 // Echo Reply
	reply[ihl+2], reply[ihl+3] = 0, 0
	sum := icmpChecksum(reply[ihl:])
	reply[ihl+2], reply[ihl+3] = byte(sum>>8), byte(sum)
	return reply, true
}

// icmpChecksum is the RFC 1071 ones-complement checksum over the ICMP
// message starting at its type byte (checksum field treated as zero).
func icmpChecksum(msg []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(msg); i += 2 {
		sum += uint32(msg[i])<<8 | uint32(msg[i+1])
	}
	if len(msg)%2 == 1 {
		sum += uint32(msg[len(msg)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
