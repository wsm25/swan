use anyhow::{Context as _, Result, anyhow};
use bytes::Bytes;
use futures::channel::mpsc as futures_mpsc;
use futures::executor::block_on;
use futures::{FutureExt, Sink, SinkExt, Stream, StreamExt, select};
use ikev2::{Ikev2Config, Ikev2Event, Ikev2Interface, UdpConn, UdpPacket};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::task::{Context, Poll};
use std::thread::JoinHandle;
use std::time::Duration;

const UDP_RECV_SHUTDOWN_POLL: Duration = Duration::from_millis(50);

mod icmp_echo {
    use anyhow::{Result, ensure};
    use bytes::Bytes;

    const IPV4_MIN_HEADER_LEN: usize = 20;
    const ICMP_ECHO_REQUEST: u8 = 8;
    const ICMP_ECHO_REPLY: u8 = 0;
    const IP_PROTOCOL_ICMP: u8 = 1;

    pub fn build_reply(packet: &Bytes) -> Result<Option<Bytes>> {
        ensure!(packet.len() >= IPV4_MIN_HEADER_LEN, "IPv4 packet too short");
        let version = packet[0] >> 4;
        if version != 4 {
            return Ok(None);
        }

        let ihl = usize::from(packet[0] & 0x0f) * 4;
        ensure!(ihl >= IPV4_MIN_HEADER_LEN, "invalid IPv4 header length");
        ensure!(packet.len() >= ihl, "truncated IPv4 header");
        ensure!(packet.len() >= 20, "IPv4 packet too short");

        let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        ensure!(total_len >= ihl, "invalid IPv4 total length");
        let total_len = total_len.min(packet.len());

        if packet[9] != IP_PROTOCOL_ICMP {
            return Ok(None);
        }

        let icmp = &packet[ihl..total_len];
        ensure!(icmp.len() >= 8, "ICMP packet too short");
        if icmp[0] != ICMP_ECHO_REQUEST {
            return Ok(None);
        }

        let mut reply = packet[..total_len].to_vec();
        reply[12..16].copy_from_slice(&packet[16..20]);
        reply[16..20].copy_from_slice(&packet[12..16]);
        reply[8] = 64;
        reply[10] = 0;
        reply[11] = 0;
        let ip_checksum = checksum(&reply[..ihl]);
        reply[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        reply[ihl] = ICMP_ECHO_REPLY;
        reply[ihl + 2] = 0;
        reply[ihl + 3] = 0;
        let icmp_checksum = checksum(&reply[ihl..total_len]);
        reply[ihl + 2..ihl + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

        Ok(Some(Bytes::from(reply)))
    }

    fn checksum(data: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut chunks = data.chunks_exact(2);
        for chunk in &mut chunks {
            sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
        }
        if let Some(&byte) = chunks.remainder().first() {
            sum = sum.wrapping_add(u32::from(byte) << 8);
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
}

struct UdpNatTConn {
    inbound_rx: futures_mpsc::UnboundedReceiver<UdpPacket>,
    inbound_tx: futures_mpsc::UnboundedSender<UdpPacket>,
    outbound_tx: Option<std_mpsc::Sender<UdpPacket>>,
    running: Option<Arc<AtomicBool>>,
    recv_worker: Option<JoinHandle<()>>,
    send_worker: Option<JoinHandle<()>>,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
}

impl UdpNatTConn {
    fn connect(bind_addr: SocketAddr, peer_addr: SocketAddr) -> Result<Self> {
        let (inbound_tx, inbound_rx) = futures_mpsc::unbounded();
        let socket = UdpSocket::bind(bind_addr)
            .with_context(|| format!("bind UDP socket to {bind_addr}"))?;
        socket.connect(peer_addr)?;
        let mut conn = Self {
            inbound_rx,
            inbound_tx,
            outbound_tx: None,
            running: None,
            recv_worker: None,
            send_worker: None,
            peer_addr,
            local_addr: bind_addr,
        };
        conn.spawn_workers(socket)?;
        Ok(conn)
    }

    fn shutdown_workers(&mut self) {
        if let Some(running) = self.running.take() {
            running.store(false, Ordering::Relaxed);
        }
        self.outbound_tx.take();
        if let Some(worker) = self.recv_worker.take() {
            let _ = worker.join();
        }
        if let Some(worker) = self.send_worker.take() {
            let _ = worker.join();
        }
    }

    fn spawn_workers(&mut self, socket: UdpSocket) -> Result<SocketAddr> {
        let local_addr = Self::resolve_local_addr(&socket, self.peer_addr)?;
        let recv_socket = socket.try_clone().context("clone UDP socket for recv worker")?;
        recv_socket
            .set_read_timeout(Some(UDP_RECV_SHUTDOWN_POLL))
            .context("set UDP read timeout")?;

        let (outbound_tx, outbound_rx) = std_mpsc::channel::<UdpPacket>();
        let running = Arc::new(AtomicBool::new(true));
        let inbound_tx = self.inbound_tx.clone();
        let running_recv = Arc::clone(&running);
        let recv_worker = std::thread::spawn(move || {
            let mut buf = [0_u8; 8192];
            while running_recv.load(Ordering::Relaxed) {
                match recv_socket.recv_from(&mut buf) {
                    Ok((n, src)) if n > 0 => {
                        log::debug!(
                            "[UDP] recv len={} local={} peer={} first8={}",
                            n,
                            local_addr,
                            src,
                            hex_prefix(&buf[..n], 8)
                        );
                        if inbound_tx
                            .unbounded_send(UdpPacket {
                                src,
                                dst: local_addr,
                                payload: Bytes::copy_from_slice(&buf[..n]),
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                    Ok(_) => {}
                    Err(err)
                        if err.kind() == io::ErrorKind::WouldBlock
                            || err.kind() == io::ErrorKind::TimedOut => {}
                    Err(err) => {
                        eprintln!("udp recv failed: {err}");
                        return;
                    }
                }
            }
        });
        let send_worker = std::thread::spawn(move || {
            while let Ok(packet) = outbound_rx.recv() {
                log::debug!(
                    "[UDP] send len={} local={} peer={} first8={}",
                    packet.payload.len(),
                    packet.src,
                    packet.dst,
                    hex_prefix(packet.payload.as_ref(), 8)
                );
                if let Err(err) = socket.send_to(packet.payload.as_ref(), packet.dst) {
                    eprintln!("udp send failed: {err}");
                    return;
                }
            }
        });

        self.local_addr = local_addr;
        self.outbound_tx = Some(outbound_tx);
        self.running = Some(running);
        self.recv_worker = Some(recv_worker);
        self.send_worker = Some(send_worker);
        Ok(local_addr)
    }

    fn resolve_local_addr(socket: &UdpSocket, peer_addr: SocketAddr) -> Result<SocketAddr> {
        let bind_addr = match peer_addr {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
        };
        let probe = UdpSocket::bind(bind_addr)
            .with_context(|| format!("bind UDP probe socket to {bind_addr}"))?;
        probe
            .connect(peer_addr)
            .with_context(|| format!("connect UDP probe socket to {peer_addr}"))?;
        let resolved = probe.local_addr().context("get resolved UDP local address")?;
        Ok(SocketAddr::new(resolved.ip(), socket.local_addr()?.port()))
    }
}

impl Stream for UdpNatTConn {
    type Item = UdpPacket;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inbound_rx).poll_next(cx)
    }
}

impl Sink<UdpPacket> for UdpNatTConn {
    type Error = anyhow::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> std::result::Result<(), Self::Error> {
        self.get_mut()
            .outbound_tx
            .as_ref()
            .context("udp outbound queue closed")?
            .send(item)
            .map_err(|err| anyhow!("udp outbound queue closed: {err}"))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        self.shutdown_workers();
        Poll::Ready(Ok(()))
    }
}

impl UdpConn for UdpNatTConn {
    fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

impl Drop for UdpNatTConn {
    fn drop(&mut self) {
        self.shutdown_workers();
    }
}

fn drain_events<S>(events: &mut S)
where
    S: Stream<Item = Ikev2Event> + Unpin,
{
    while let Some(event) = events.next().now_or_never().flatten() {
        println!("event: {}", format_event(&event));
    }
}

async fn start_and_print_events(
    interface: &mut Ikev2Interface,
    events: &mut (impl Stream<Item = Ikev2Event> + Unpin),
) -> Result<()> {
    let start = interface.start().fuse();
    futures::pin_mut!(start);
    loop {
        let event = events.next().fuse();
        futures::pin_mut!(event);
        select! {
            result = start => {
                drain_events(events);
                return result;
            }
            event = event => {
                let Some(event) = event else {
                    continue;
                };
                println!("event: {}", format_event(&event));
            }
        }
    }
}

fn hex_prefix(bytes: &[u8], max_len: usize) -> String {
    use std::fmt::Write as _;
    let shown = bytes.len().min(max_len);
    let mut out = String::with_capacity(shown * 2);
    for byte in &bytes[..shown] {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn format_event(event: &Ikev2Event) -> String {
    match event {
        Ikev2Event::Starting => "Starting".to_string(),
        Ikev2Event::HandshakeStarted => "HandshakeStarted".to_string(),
        Ikev2Event::StageChanged(stage) => format!(
            "StageChanged({})",
            match stage {
                ikev2::Ikev2Stage::IkeInit => "ike_init",
                ikev2::Ikev2Stage::IkeAuth => "ike_auth",
                ikev2::Ikev2Stage::Eap => "eap",
                ikev2::Ikev2Stage::ChildSa => "child_sa",
                ikev2::Ikev2Stage::Running => "running",
            }
        ),
        Ikev2Event::NegotiatedAlgorithm(alg) => format!(
            "NegotiatedAlgorithm(protocol={}, encr={}, integ={}, prf={}, dh={})",
            alg.protocol,
            alg.encryption,
            alg.integrity.as_deref().unwrap_or("-"),
            alg.prf.as_deref().unwrap_or("-"),
            alg.dh.as_deref().unwrap_or("-"),
        ),
        Ikev2Event::EapProcess(process) => format!(
            "EapProcess(method={}, state={}, round={})",
            process.method,
            process.state,
            process.round.map(|value| value.to_string()).unwrap_or_else(|| "-".to_string())
        ),
        Ikev2Event::HandshakeCompleted => "HandshakeCompleted".to_string(),
        Ikev2Event::ConfigAssigned(config) => format!(
            "ConfigAssigned(ipv4={:?}, ipv6={:?}, dns4={:?}, dns6={:?})",
            config.internal_ipv4, config.internal_ipv6, config.dns4, config.dns6
        ),
        Ikev2Event::Started => "Started".to_string(),
        Ikev2Event::Stopping => "Stopping".to_string(),
        Ikev2Event::Stopped => "Stopped".to_string(),
        Ikev2Event::Broken(reason) => format!("Broken({reason})"),
    }
}

fn build_config(peer: SocketAddr) -> Result<Ikev2Config> {
    Ikev2Config::builder()
        .ike_suite_strongswan("aes128gcm16-aes256gcm16-prfsha512-prfsha512-curve25519")?
        .esp_suite_strongswan("aes128gcm16-aes256gcm16-prfsha256-prfsha512-curve25519")?
        .peer(peer)
        .eap_method("peap")?
        .idi("%config")?
        .eap_identity("testuser")?
        .eap_password("password")?
        .aaa_identity("@radius.net.sjtu.edu.cn")?
        .rightid("@stu.vpn.sjtu.edu.cn")?
        .strongswan_compatible(true)
        .build()
}

fn main() -> Result<()> {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Debug)
        .format(|buf, record| writeln!(buf, "{}", record.args()))
        .init();

    let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(111, 186, 44, 0)), 4500);
    // let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 25, 192, 1)), 12000);

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let udp_conn = UdpNatTConn::connect(bind_addr, peer_addr)?;
    let local_addr = udp_conn.local_addr()?;
    let config = build_config(peer_addr)?;

    let mut interface = Ikev2Interface::new(config, Box::new(udp_conn));
    let mut events = interface.event();

    println!("connecting to {peer_addr} from {local_addr} ...");
    block_on(start_and_print_events(&mut interface, &mut events)).context("IKEv2 start failed")?;

    println!("connected. press Enter to stop.");
    let (stop_tx, mut stop_rx) = futures_mpsc::unbounded::<()>();
    std::thread::spawn(move || {
        let mut input = String::new();
        let _ = io::stdin().read_line(&mut input);
        let _ = stop_tx.unbounded_send(());
    });
    block_on(async {
        loop {
            let packet = interface.next().fuse();
            let event = events.next().fuse();
            let stop = stop_rx.next().fuse();
            futures::pin_mut!(packet, event, stop);
            select! {
                packet = packet => {
                    let Some(packet) = packet else {
                        break;
                    };
                    println!(
                        "inbound ip packet len={} first32={}",
                        packet.len(),
                        hex_prefix(packet.as_ref(), 32)
                    );
                    if let Some(reply) = icmp_echo::build_reply(&packet)? {
                        println!(
                            "replying icmp echo len={} first32={}",
                            reply.len(),
                            hex_prefix(reply.as_ref(), 32)
                        );
                        interface.send(reply).await.context("send ICMP echo reply")?;
                    }
                }
                event = event => {
                    if let Some(event) = event {
                        println!("event: {}", format_event(&event));
                    }
                }
                _ = stop => break,
            }
        }
        Result::<()>::Ok(())
    })?;

    block_on(interface.stop()).context("IKEv2 stop failed")?;
    drain_events(&mut events);
    println!("stopped.");
    Ok(())
}
