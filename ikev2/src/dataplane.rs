use anyhow::{Context, Result, anyhow, bail, ensure};
use bytemuck::{Pod, Zeroable, pod_read_unaligned};
use bytes::{Bytes, BytesMut};
use futures::channel::{mpsc, oneshot};
use futures::{FutureExt, SinkExt, Stream, StreamExt, select};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::{ChildSaInstall, ChildSaKeyMaterial};
use crate::cipher::rand_bytes;
use crate::{
    EventHub, Ikev2Event, IpPacket, UdpConn, UdpPacket,
    config::CipherSuiteSelection,
    routine::{CloseOutcome, InboundControlOutcome, InboundUdpPacket, OutboundUdpPacket},
};

const CONTROL_IDLE_INTERVAL: Duration = Duration::from_secs(20);

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
struct EspHeader {
    spi: rend::u32_be,
    sequence_number: rend::u32_be,
}

struct EspState {
    outbound_seq: u32,
    highest_inbound_seq: u32,
    replay_window: u64,
}

impl EspState {
    fn new() -> Self {
        Self { outbound_seq: 1, highest_inbound_seq: 0, replay_window: 0 }
    }

    fn accept_inbound_seq(&mut self, sequence_number: u32) -> Result<()> {
        ensure!(sequence_number != 0, "invalid ESP sequence number 0");
        if self.highest_inbound_seq == 0 {
            self.highest_inbound_seq = sequence_number;
            self.replay_window = 1;
            return Ok(());
        }

        if sequence_number > self.highest_inbound_seq {
            let shift = sequence_number - self.highest_inbound_seq;
            if shift >= 64 {
                self.replay_window = 1;
            } else {
                self.replay_window <<= shift;
                self.replay_window |= 1;
            }
            self.highest_inbound_seq = sequence_number;
            return Ok(());
        }

        let delta = self.highest_inbound_seq - sequence_number;
        ensure!(delta < 64, "ESP replay window exceeded");
        let mask = 1u64 << delta;
        ensure!((self.replay_window & mask) == 0, "duplicate ESP packet");
        self.replay_window |= mask;
        Ok(())
    }
}

struct DataPlaneInit {
    child_sa: ChildSaInstall,
    keys: ChildSaKeyMaterial,
    selection: CipherSuiteSelection,
    inbound_tx: mpsc::UnboundedSender<IpPacket>,
    outbound_rx: mpsc::UnboundedReceiver<IpPacket>,
    events: Arc<Mutex<EventHub>>,
}

pub struct DataPlaneContext {
    udp_conn: Box<dyn UdpConn>,
    routine: super::Ikev2Routine,
    child_sa: ChildSaInstall,
    keys: ChildSaKeyMaterial,
    selection: CipherSuiteSelection,
    inbound_tx: mpsc::UnboundedSender<IpPacket>,
    outbound_rx: mpsc::UnboundedReceiver<IpPacket>,
    events: Arc<Mutex<EventHub>>,
    esp: EspState,
    last_control_activity: Instant,
}

impl DataPlaneContext {
    fn new(udp_conn: Box<dyn UdpConn>, routine: super::Ikev2Routine, init: DataPlaneInit) -> Self {
        crate::debug_fmt::log_udp(
            "run",
            &format!(
                "child-sa active inbound_spi=0x{:08x} outbound_spi=0x{:08x}",
                init.child_sa.inbound_spi, init.child_sa.outbound_spi
            ),
        );
        crate::debug_fmt::log_child_sa_runtime(&init.child_sa, &init.keys, &init.selection);
        Self {
            udp_conn,
            routine,
            child_sa: init.child_sa,
            keys: init.keys,
            selection: init.selection,
            inbound_tx: init.inbound_tx,
            outbound_rx: init.outbound_rx,
            events: init.events,
            esp: EspState::new(),
            last_control_activity: Instant::now(),
        }
    }

    async fn run_daemon(mut self, stop_rx: oneshot::Receiver<()>) -> Box<dyn UdpConn> {
        let mut stop_rx = stop_rx.fuse();

        loop {
            let control_delay = self.control_delay();
            let inbound = self.udp_conn.next().fuse();
            let outbound = self.outbound_rx.next().fuse();
            let control_tick = futures_timer::Delay::new(control_delay).fuse();
            futures::pin_mut!(inbound, outbound, control_tick);
            select! {
                _ = stop_rx => {
                    break;
                }
                packet = inbound => {
                    match packet {
                        Some(packet) => {
                            match self.handle_inbound_packet(packet).await {
                                Ok(InboundControlOutcome::PeerShutdownRequested) => {
                                    self.report_stopped();
                                    return self.udp_conn;
                                }
                                Ok(InboundControlOutcome::Continue) => {}
                                Err(err) => {
                                    crate::debug_fmt::log_udp(
                                        "recv",
                                        &format!("dropping malformed inbound packet: {err}"),
                                    );
                                }
                            }
                        }
                        None => {
                            self.report_failure("udp connection closed".to_string());
                            return self.udp_conn;
                        }
                    }
                }
                _ = control_tick => {
                    if let Err(err) = self.send_keepalive().await {
                        return self.fail_and_close(err.to_string()).await;
                    }
                }
                packet = outbound => {
                    match packet {
                        Some(packet) => {
                            if let Err(err) = self.handle_outbound_packet(packet).await {
                                return self.fail_and_close(err.to_string()).await;
                            }
                        }
                        None => {
                            return self.fail_and_close("outbound queue closed".to_string()).await;
                        }
                    }
                }
            }
        }

        match self.routine.close(&mut *self.udp_conn).await {
            Ok(CloseOutcome::AlreadyClosed | CloseOutcome::Closed) => {}
            Err(err) => self.report_failure(err.to_string()),
        }
        self.udp_conn
    }

    fn control_delay(&self) -> Duration {
        CONTROL_IDLE_INTERVAL.saturating_sub(self.last_control_activity.elapsed())
    }

    fn report_failure(&self, reason: String) {
        if let Ok(mut hub) = self.events.lock() {
            hub.emit(Ikev2Event::Broken(reason));
            hub.emit(Ikev2Event::Stopped);
        }
    }

    fn report_stopped(&self) {
        if let Ok(mut hub) = self.events.lock() {
            hub.emit(Ikev2Event::Stopped);
        }
    }

    async fn fail_and_close(&mut self, reason: String) -> Box<dyn UdpConn> {
        if let Err(close_err) = self.routine.close(&mut *self.udp_conn).await {
            crate::debug_fmt::log_udp(
                "close",
                &format!("best-effort close failed after error: {close_err}"),
            );
        }
        self.report_failure(reason);
        std::mem::replace(&mut self.udp_conn, Box::new(ClosedUdpConn))
    }

    async fn handle_inbound_packet(&mut self, packet: UdpPacket) -> Result<InboundControlOutcome> {
        match self.routine.process_inbound_udp_packet(packet)? {
            InboundUdpPacket::Ike { packet } => {
                let outcome =
                    self.routine.handle_running_control_packet(&mut *self.udp_conn, packet).await?;
                self.last_control_activity = Instant::now();
                Ok(outcome)
            }
            InboundUdpPacket::Esp { packet } => {
                self.handle_inbound_esp(packet)?;
                Ok(InboundControlOutcome::Continue)
            }
            InboundUdpPacket::NatKeepalive => Ok(InboundControlOutcome::Continue),
        }
    }

    async fn send_keepalive(&mut self) -> Result<()> {
        if self.routine.sa.expected_response_message_id.is_some() {
            return Ok(());
        }
        self.routine.send_empty_informational_request(&mut *self.udp_conn).await?;
        self.last_control_activity = Instant::now();
        Ok(())
    }

    fn handle_inbound_esp(&mut self, packet: Bytes) -> Result<()> {
        ensure!(packet.len() >= std::mem::size_of::<EspHeader>(), "ESP packet too short");
        let header = pod_read_unaligned::<EspHeader>(&packet[..std::mem::size_of::<EspHeader>()]);
        let spi = header.spi.to_native();
        if spi != self.child_sa.inbound_spi {
            let direction_hint =
                if spi == self.child_sa.outbound_spi { " matched local outbound SPI" } else { "" };
            crate::debug_fmt::log_udp(
                "recv",
                &format!(
                    "dropping ESP packet with unknown SPI=0x{spi:08x}; expected inbound_spi=0x{:08x} outbound_spi=0x{:08x}{direction_hint}",
                    self.child_sa.inbound_spi, self.child_sa.outbound_spi,
                ),
            );
            return Ok(());
        }
        self.esp.accept_inbound_seq(header.sequence_number.to_native())?;

        let enc = self.selection.encryption;
        let integ = self.selection.integrity;
        let iv_len = enc.iv_len;
        let icv_len = if enc.is_aead { enc.icv_len } else { integ.output_len };
        let body = &packet[std::mem::size_of::<EspHeader>()..];
        if body.len() < iv_len + icv_len {
            crate::debug_fmt::log_udp("recv", "dropping ESP packet that is too short");
            return Ok(());
        }
        crate::debug_fmt::log_udp(
            "recv",
            &format!(
                "esp verify spi=0x{spi:08x} seq={} len={} iv_len={} icv_len={} integ_key_len={} enc_key_len={}",
                header.sequence_number.to_native(),
                packet.len(),
                iv_len,
                icv_len,
                self.keys.sk_ar.len(),
                self.keys.sk_er.len(),
            ),
        );
        let (iv, rest) = body.split_at(iv_len);
        let plaintext = if enc.is_aead {
            match enc.decrypt_vec(
                self.keys.sk_er.as_ref(),
                iv,
                &packet[..std::mem::size_of::<EspHeader>()],
                rest,
            ) {
                Ok(plaintext) => plaintext,
                Err(_) => {
                    crate::debug_fmt::log_udp(
                        "recv",
                        "dropping ESP packet that failed AEAD verification",
                    );
                    return Ok(());
                }
            }
        } else {
            let (ciphertext, recv_icv) = rest.split_at(rest.len() - icv_len);
            let expected_icv =
                integ.sign_vec(self.keys.sk_ar.as_ref(), &packet[..packet.len() - icv_len])?;
            if expected_icv.len() < icv_len || expected_icv[..icv_len] != recv_icv[..] {
                crate::debug_fmt::log_udp(
                    "recv",
                    "dropping ESP packet with invalid integrity check",
                );
                return Ok(());
            }
            match enc.decrypt_vec(self.keys.sk_er.as_ref(), iv, &[], ciphertext) {
                Ok(plaintext) => plaintext,
                Err(_) => {
                    crate::debug_fmt::log_udp("recv", "dropping ESP packet that failed decryption");
                    return Ok(());
                }
            }
        };
        if plaintext.is_empty() {
            crate::debug_fmt::log_udp("recv", "dropping empty ESP plaintext");
            return Ok(());
        }
        if plaintext.len() < 2 {
            crate::debug_fmt::log_udp("recv", "dropping ESP packet missing trailer");
            return Ok(());
        }
        let pad_len = plaintext[plaintext.len() - 2] as usize;
        if plaintext.len() <= pad_len + 1 {
            crate::debug_fmt::log_udp("recv", "dropping ESP packet with invalid padding");
            return Ok(());
        }
        let next_header = plaintext[plaintext.len() - 1];
        if !matches!(next_header, 4 | 41) {
            crate::debug_fmt::log_udp(
                "recv",
                &format!("dropping ESP packet with unsupported inner protocol {next_header}"),
            );
            return Ok(());
        }
        let inner_len = plaintext.len() - pad_len - 2;
        crate::debug_fmt::log_udp(
            "recv",
            &format!(
                "esp accepted spi=0x{spi:08x} seq={} inner_len={} next_header={next_header}",
                header.sequence_number.to_native(),
                inner_len
            ),
        );
        self.inbound_tx
            .unbounded_send(Bytes::copy_from_slice(&plaintext[..inner_len]))
            .context("inbound raw packet queue closed")
    }

    async fn handle_outbound_packet(&mut self, packet: Bytes) -> Result<()> {
        let next_header = match packet.first().copied().context("outbound packet is empty")? >> 4 {
            4 => 4u8,
            6 => 41u8,
            other => bail!("unsupported outbound IP version {other}"),
        };

        let enc = self.selection.encryption;
        let integ = self.selection.integrity;
        let mut plaintext = BytesMut::from(packet.as_ref());
        let base = plaintext.len() + 2;
        let pad_len = (enc.block_len - (base % enc.block_len)) % enc.block_len;
        plaintext.extend((1..=pad_len).map(|v| v as u8));
        plaintext.extend_from_slice(&[pad_len as u8, next_header]);

        let mut iv = vec![0u8; enc.iv_len];
        rand_bytes(&mut iv);

        let seq = self.esp.outbound_seq;
        ensure!(seq != 0, "ESP outbound sequence number wrapped");
        self.esp.outbound_seq = self.esp.outbound_seq.wrapping_add(1);

        let mut out = BytesMut::with_capacity(std::mem::size_of::<EspHeader>() + iv.len() + plaintext.len() + if enc.is_aead { enc.icv_len } else { integ.output_len });
        out.extend_from_slice(bytemuck::bytes_of(&EspHeader {
            spi: self.child_sa.outbound_spi.into(),
            sequence_number: seq.into(),
        }));
        let ciphertext = if enc.is_aead {
            enc.encrypt_vec(self.keys.sk_ei.as_ref(), &iv, out.as_ref(), plaintext.as_ref())?
        } else {
            enc.encrypt_vec(self.keys.sk_ei.as_ref(), &iv, &[], plaintext.as_ref())?
        };
        out.extend_from_slice(&iv);
        out.extend_from_slice(&ciphertext);
        if !enc.is_aead {
            out.resize(out.len() + integ.output_len, 0);
            let icv_start = out.len() - integ.output_len;
            let (data, icv) = out.split_at_mut(icv_start);
            (integ.sign)(self.keys.sk_ai.as_ref(), data, icv)?;
        }
        let dst = self
            .routine
            .transport
            .as_ref()
            .context("missing transport for outbound ESP packet")?
            .peer_addr;
        let packet = self
            .routine
            .encode_outbound_udp_packet(OutboundUdpPacket::Esp { packet: out.freeze(), dst })?;
        self.udp_conn.send(packet).await.context("send ESP packet")
    }
}

struct ClosedUdpConn;

impl Stream for ClosedUdpConn {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::task::Poll::Ready(None)
    }
}

impl futures::Sink<UdpPacket> for ClosedUdpConn {
    type Error = anyhow::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<()>> {
        std::task::Poll::Ready(Err(anyhow!("closed udp connection placeholder")))
    }

    fn start_send(self: Pin<&mut Self>, _item: UdpPacket) -> Result<()> {
        Err(anyhow!("closed udp connection placeholder"))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<()>> {
        std::task::Poll::Ready(Err(anyhow!("closed udp connection placeholder")))
    }

    fn poll_close(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl UdpConn for ClosedUdpConn {
    fn local_addr(&self) -> Result<std::net::SocketAddr> {
        Err(anyhow!("closed udp connection placeholder"))
    }
}

pub struct RunningDataPlane {
    pub inbound_rx: mpsc::UnboundedReceiver<IpPacket>,
    pub outbound_tx: mpsc::UnboundedSender<IpPacket>,
    ctx: Arc<Mutex<Option<DataPlaneContext>>>,
    stop_tx: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<Box<dyn UdpConn>>>,
}

impl RunningDataPlane {
    pub(crate) fn spawn(
        udp_conn: Box<dyn UdpConn>,
        routine: super::Ikev2Routine,
        child_sa: ChildSaInstall,
        keys: ChildSaKeyMaterial,
        selection: CipherSuiteSelection,
        events: Arc<Mutex<EventHub>>,
    ) -> Self {
        let (inbound_tx, inbound_rx) = mpsc::unbounded();
        let (outbound_tx, outbound_rx) = mpsc::unbounded();
        let (stop_tx, stop_rx) = oneshot::channel();
        let ctx = Arc::new(Mutex::new(Some(DataPlaneContext::new(
            udp_conn,
            routine,
            DataPlaneInit { child_sa, keys, selection, inbound_tx, outbound_rx, events },
        ))));
        let thread_ctx = Arc::clone(&ctx);
        let join = std::thread::spawn(move || {
            let ctx = thread_ctx
                .lock()
                .expect("dataplane context mutex poisoned")
                .take()
                .expect("dataplane context missing");
            futures::executor::block_on(ctx.run_daemon(stop_rx))
        });

        Self { inbound_rx, outbound_tx, ctx, stop_tx: Some(stop_tx), join: Some(join) }
    }

    pub fn stop(&mut self) -> Option<Box<dyn UdpConn>> {
        let _ = &self.ctx;
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        self.join.take().and_then(|join| join.join().ok())
    }

    pub fn is_finished(&self) -> bool {
        self.join.as_ref().is_some_and(|join| join.is_finished())
    }
}
