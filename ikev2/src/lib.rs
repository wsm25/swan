#[macro_use]
mod macros;

pub mod config;
pub mod consts;
pub mod cipher;
pub mod dataplane;
pub mod debug_fmt;
pub mod eap;
pub mod payload;
pub mod routine;
pub mod state;

pub use config::{Ikev2Config, Ikev2ConfigBuilder, PeerAddress};
pub use crate::AssignedConfig as Ikev2AssignedConfig;

use anyhow::{Context, Result, anyhow, ensure};
use bytes::Bytes;
use config::CipherSuiteSelection;
use futures::channel::mpsc;
use futures::{Sink, Stream};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};

pub use routine::{Ikev2Routine, PeerIdentity, RoutineSummary, TransportSetup};
pub use state::{
    ActiveChildSa, IkeAuthState, IkeKeyMaterial, IkeSa, IkeSaState, InboundFragmentReassembly,
    InboundRequestResponse, KeyExchangePayload, NatDetectionState, NegotiatingChildSa,
    PeerCapabilities,
};

pub const IKEV2_NAT_T_PORT: u16 = 4500;
pub type IpPacket = Bytes;

#[derive(Clone)]
pub struct UdpPacket {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: Bytes,
}

pub struct ChildSaKeyMaterial {
    pub sk_ei: Box<[u8]>,
    pub sk_ai: Box<[u8]>,
    pub sk_er: Box<[u8]>,
    pub sk_ar: Box<[u8]>,
}

#[derive(Clone, Default)]
pub struct AssignedConfig {
    pub internal_ipv4: Option<[u8; 4]>,
    pub internal_ipv6: Option<[u8; 16]>,
    pub internal_ipv6_prefix_len: Option<u8>,
    pub dns4: Vec<[u8; 4]>,
    pub dns6: Vec<[u8; 16]>,
}

pub struct ChildSaInstall {
    pub inbound_spi: u32,
    pub outbound_spi: u32,
    pub tsi: Bytes,
    pub tsr: Bytes,
}

#[derive(Default)]
pub struct Ikev2Context {
    pub is_initiator: bool,
}

#[derive(Default)]
pub struct Ikev2EapHandshake {
    pub(crate) ike_proposal: Option<CipherSuiteSelection>,
    pub(crate) ike_keys: Option<IkeKeyMaterial>,
    pub(crate) context: Ikev2Context,
}

impl Ikev2EapHandshake {
    pub fn new(context: Ikev2Context) -> Self {
        Self { context, ..Default::default() }
    }
}

pub trait ChildSaInstaller: Send {
    fn install(&mut self, child_sa: &ChildSaInstall) -> Result<()>;
}

pub trait UdpConn:
    Stream<Item = UdpPacket> + Sink<UdpPacket, Error = anyhow::Error> + Unpin + Send
{
    fn local_addr(&self) -> Result<SocketAddr>;
}

#[derive(Clone)]
pub enum Ikev2Event {
    Starting,
    HandshakeStarted,
    HandshakeCompleted,
    ConfigAssigned(Ikev2AssignedConfig),
    Started,
    Stopping,
    Stopped,
    Broken(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InterfaceState {
    Stopped,
    Running,
}

pub(crate) struct EventHub {
    history: VecDeque<Ikev2Event>,
    subscribers: Vec<mpsc::UnboundedSender<Ikev2Event>>,
}

impl EventHub {
    const MAX_HISTORY: usize = 16;

    fn new() -> Self {
        Self { history: VecDeque::new(), subscribers: Vec::new() }
    }

    fn subscribe(&mut self) -> Ikev2EventStream {
        let (tx, rx) = mpsc::unbounded();
        for event in self.history.iter().cloned() {
            if tx.unbounded_send(event).is_err() {
                break;
            }
        }
        self.subscribers.push(tx);
        Ikev2EventStream { rx }
    }

    fn emit(&mut self, event: Ikev2Event) {
        if self.history.len() == Self::MAX_HISTORY {
            self.history.pop_front();
        }
        self.history.push_back(event.clone());
        self.subscribers.retain(|sub| sub.unbounded_send(event.clone()).is_ok());
    }
}

pub struct Ikev2EventStream {
    rx: mpsc::UnboundedReceiver<Ikev2Event>,
}

impl Stream for Ikev2EventStream {
    type Item = Ikev2Event;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.rx).poll_next(cx)
    }
}

pub struct Ikev2Interface {
    pub config: Ikev2Config,
    udp_conn: Option<Box<dyn UdpConn>>,
    child_sa_installer: Option<Box<dyn ChildSaInstaller>>,
    assigned_config: Option<Ikev2AssignedConfig>,
    state: InterfaceState,
    running: Option<dataplane::RunningDataPlane>,
    events: Arc<Mutex<EventHub>>,
}

impl Ikev2Interface {
    pub fn new(config: Ikev2Config, udp_conn: Box<dyn UdpConn>) -> Self {
        Self {
            config,
            udp_conn: Some(udp_conn),
            child_sa_installer: None,
            assigned_config: None,
            state: InterfaceState::Stopped,
            running: None,
            events: Arc::new(Mutex::new(EventHub::new())),
        }
    }

    pub fn new_with_child_sa_installer(
        config: Ikev2Config,
        udp_conn: Box<dyn UdpConn>,
        child_sa_installer: Box<dyn ChildSaInstaller>,
    ) -> Self {
        Self {
            config,
            udp_conn: Some(udp_conn),
            child_sa_installer: Some(child_sa_installer),
            assigned_config: None,
            state: InterfaceState::Stopped,
            running: None,
            events: Arc::new(Mutex::new(EventHub::new())),
        }
    }

    fn push_event(&self, event: Ikev2Event) {
        if let Ok(mut hub) = self.events.lock() {
            hub.emit(event);
        }
    }

    fn clear_running(&mut self) -> Result<()> {
        if let Some(mut running) = self.running.take() {
            let udp_conn = running.stop().context("running data plane stopped unexpectedly")?;
            self.udp_conn = Some(udp_conn);
        }
        Ok(())
    }

    fn finalize_start_success(
        &mut self,
        mut summary: RoutineSummary,
        routine: Ikev2Routine,
    ) -> Result<()> {
        let child_sa_install = summary
            .child_sa_install
            .take()
            .context("routine completed without CHILD_SA install")?;
        if let Some(installer) = self.child_sa_installer.as_deref_mut() {
            installer.install(&child_sa_install)?;
        }
        let child_sa_keys = routine.derive_child_sa_key_material()?;
        let child_sa_selection = routine.first_esp_selection()?.clone();
        let udp_conn = self.udp_conn.take().context("udp connection missing")?;
        self.running = Some(dataplane::RunningDataPlane::spawn(
            udp_conn,
            routine,
            child_sa_install,
            child_sa_keys,
            child_sa_selection,
            self.events.clone(),
        ));
        self.assigned_config = summary.assigned_config.take();
        self.state = InterfaceState::Running;
        self.push_event(Ikev2Event::HandshakeCompleted);
        self.push_event(Ikev2Event::Started);
        if let Some(config) = self.assigned_config.take() {
            self.push_event(Ikev2Event::ConfigAssigned(config));
        }
        Ok(())
    }

    async fn finalize_start_failure(
        &mut self,
        routine: &mut Ikev2Routine,
        err: &anyhow::Error,
    ) -> String {
        if let Some(udp_conn) = self.udp_conn.as_mut() {
            let _ = routine.send_authentication_failed_notify(&mut **udp_conn).await;
        }
        let failure_reason = routine.fail_and_cleanup(err.to_string());
        self.state = InterfaceState::Stopped;
        self.push_event(Ikev2Event::Broken(failure_reason.clone()));
        self.push_event(Ikev2Event::Stopped);
        failure_reason
    }

    fn finalize_stop_success(&mut self) {
        self.push_event(Ikev2Event::Stopped);
    }

    fn finalize_stop_failure(&mut self, err: &anyhow::Error) {
        self.push_event(Ikev2Event::Broken(err.to_string()));
        self.push_event(Ikev2Event::Stopped);
    }

    fn sync_running_state(&mut self) -> Result<bool> {
        if self.running.as_ref().is_some_and(|running| running.is_finished()) {
            self.clear_running()?;
            self.state = InterfaceState::Stopped;
            return Ok(true);
        }
        Ok(false)
    }

    pub fn event(&self) -> Ikev2EventStream {
        self.events.lock().expect("event hub mutex poisoned").subscribe()
    }

    pub async fn start(&mut self) -> Result<()> {
        ensure!(
            matches!(self.state, InterfaceState::Stopped),
            "interface must be stopped before start"
        );
        ensure!(self.running.is_none(), "interface already running");
        ensure!(self.udp_conn.is_some(), "udp connection is missing");

        self.assigned_config = None;
        self.push_event(Ikev2Event::Starting);
        self.push_event(Ikev2Event::HandshakeStarted);

        let mut routine = Ikev2Routine::new(self.config.clone());
        let result = {
            let udp_conn = self.udp_conn.as_mut().expect("checked above");
            routine.run(&mut **udp_conn).await
        };

        match result {
            Ok(summary) => self.finalize_start_success(summary, routine),
            Err(err) => {
                self.finalize_start_failure(&mut routine, &err).await;
                Err(err)
            }
        }
    }

    pub async fn stop(&mut self) -> Result<()> {
        if matches!(self.state, InterfaceState::Stopped) {
            return Ok(());
        }
        self.push_event(Ikev2Event::Stopping);
        self.state = InterfaceState::Stopped;
        if let Err(err) = self.clear_running() {
            self.finalize_stop_failure(&err);
            return Err(err);
        }
        self.finalize_stop_success();
        Ok(())
    }
}

impl Stream for Ikev2Interface {
    type Item = IpPacket;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.sync_running_state().is_err() {
            return Poll::Ready(None);
        }
        if this.state != InterfaceState::Running {
            return Poll::Ready(None);
        }
        let Some(running) = this.running.as_mut() else {
            return Poll::Ready(None);
        };
        Pin::new(&mut running.inbound_rx).poll_next(cx)
    }
}

impl Sink<IpPacket> for Ikev2Interface {
    type Error = anyhow::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        if this.sync_running_state().is_err() {
            return Poll::Ready(Err(anyhow!("running data plane stopped unexpectedly")));
        }
        if this.state != InterfaceState::Running {
            return Poll::Ready(Err(anyhow!("interface is not running")));
        }
        let Some(running) = this.running.as_ref() else {
            return Poll::Ready(Err(anyhow!("running data plane is missing")));
        };
        if running.outbound_tx.is_closed() {
            return Poll::Ready(Err(anyhow!("outbound queue closed")));
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: IpPacket) -> Result<()> {
        let this = self.get_mut();
        let _ = this.sync_running_state();
        if this.state != InterfaceState::Running {
            return Err(anyhow!("interface is not running"));
        }
        let Some(running) = this.running.as_mut() else {
            return Err(anyhow!("running data plane is missing"));
        };
        running.outbound_tx.unbounded_send(item).context("outbound queue closed")
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        let _ = this.clear_running();
        Poll::Ready(Ok(()))
    }
}
