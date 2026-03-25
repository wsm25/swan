mod auth_bootstrap;
mod auth_shared;
mod child_sa;
pub(crate) mod common;
mod control;
mod delete_exchange;
mod eap;
mod exchange_io;
mod ids;
mod packet_io;
mod peer_auth;
mod sa_init;
mod sa_init_shared;
mod transport_setup;

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::{
    EventHub, Ikev2Config, Ikev2EapProcess, Ikev2Event, Ikev2NegotiatedAlgorithm, Ikev2Stage,
    UdpConn,
    eap::{EapMethod, EapMethodConfig, build_method},
};

use super::{AssignedConfig, ChildSaInstall, IkeSa, state::IkeSaState};

pub(crate) use common::{
    InboundControlOutcome, InboundResponseDisposition, InboundUdpPacket, OutboundUdpPacket,
};

pub struct TransportSetup {
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub natt_active: bool,
}

pub struct PeerIdentity {
    pub id_type: u8,
    pub value: Box<[u8]>,
}

pub struct RoutineSummary {
    pub assigned_config: Option<AssignedConfig>,
    pub child_sa_install: Option<ChildSaInstall>,
}

pub enum CloseOutcome {
    AlreadyClosed,
    Closed,
}

pub struct Ikev2Routine {
    pub config: Ikev2Config,
    pub sa: IkeSa,
    pub eap_method: Box<dyn EapMethod>,
    events: Arc<Mutex<EventHub>>,
    pub transport: Option<TransportSetup>,
    pub peer_identity: Option<PeerIdentity>,
    pub local_identity: Option<PeerIdentity>,
    pub(super) broken: bool,
    pub(super) local_dh: Option<super::cipher::DhKeyPair>,
    pub(super) selected_suite: Option<crate::config::CipherSuiteSelection>,
    pub(super) selected_child_suite: Option<crate::config::CipherSuiteSelection>,
}

impl Ikev2Routine {
    pub fn new(config: Ikev2Config) -> Self {
        Self::new_with_events(config, Arc::new(Mutex::new(EventHub::new())))
    }

    pub(crate) fn new_with_events(config: Ikev2Config, events: Arc<Mutex<EventHub>>) -> Self {
        let eap_identity = config.eap_identity.clone();
        let eap_password = config.eap_password.clone();
        let aaa_identity = config.aaa_identity.clone();
        let eap_method = config.eap_method.clone();
        let peap_fragment_size = config.peap_fragment_size;
        let peap_max_message_count = config.peap_max_message_count;
        let peap_include_length = config.peap_include_length;
        let strongswan_compatible = config.strongswan_compatible;
        Self {
            config,
            sa: IkeSa::new(),
            eap_method: build_method(EapMethodConfig {
                peer_identity: eap_identity,
                peer_password: eap_password,
                aaa_identity,
                method_name: eap_method,
                peap_fragment_size,
                peap_max_message_count,
                peap_include_length,
                strongswan_compatible,
            })
            .unwrap(),
            events,
            transport: None,
            peer_identity: None,
            local_identity: None,
            broken: false,
            local_dh: None,
            selected_suite: None,
            selected_child_suite: None,
        }
    }

    pub async fn run(&mut self, udp_conn: &mut dyn UdpConn) -> Result<RoutineSummary> {
        self.emit_event(Ikev2Event::StageChanged(Ikev2Stage::IkeInit));
        self.setup_transport(udp_conn)?;
        self.run_sa_init(udp_conn).await?;
        self.emit_event(Ikev2Event::StageChanged(Ikev2Stage::IkeAuth));
        self.start_auth(udp_conn).await?;
        self.emit_event(Ikev2Event::StageChanged(Ikev2Stage::Eap));
        self.run_eap(udp_conn).await?;
        self.emit_event(Ikev2Event::StageChanged(Ikev2Stage::ChildSa));
        let child_sa_install = self.finish_auth(udp_conn).await?;
        self.sa.state = IkeSaState::Running;
        Ok(RoutineSummary {
            assigned_config: self.sa.assigned_config.take(),
            child_sa_install: Some(child_sa_install),
        })
    }

    pub fn mark_failed(&mut self, reason: impl Into<String>) {
        self.sa.failure_reason = Some(reason.into());
        self.sa.state = IkeSaState::Failed;
    }

    pub fn fail_and_cleanup(&mut self, reason: impl Into<String>) -> String {
        self.mark_failed(reason);
        let failure_reason = self
            .sa
            .failure_reason
            .as_ref()
            .cloned()
            .unwrap_or_else(|| "routine failed".to_string());
        self.cleanup_session();
        failure_reason
    }

    pub fn is_broken(&self) -> bool {
        self.broken
    }

    pub(crate) fn cleanup_session(&mut self) {
        self.sa.assigned_config = None;
        self.sa.negotiating_child_sa = None;
        self.sa.active_child_sa = None;
        self.sa.clear_outbound_request();
        self.sa.key_material = None;
        self.sa.inbound_fragments = None;
        self.sa.inbound_request_history.clear();
        self.sa.first_ike_auth_seen = false;
        self.local_dh = None;
        self.selected_suite = None;
        self.transport = None;
        self.peer_identity = None;
        self.local_identity = None;
        self.broken = false;
        self.sa.expected_response_message_id = None;
        self.sa.state = IkeSaState::Stopped;
    }

    pub(crate) fn emit_event(&self, event: Ikev2Event) {
        if let Ok(mut hub) = self.events.lock() {
            hub.emit(event);
        }
    }

    pub(crate) fn emit_negotiated_ike_algorithms(&self) -> Result<()> {
        let selection = self.selected_ike_proposal()?;
        self.emit_event(Ikev2Event::NegotiatedAlgorithm(Ikev2NegotiatedAlgorithm {
            protocol: "ike",
            encryption: selection.encryption.name.into(),
            integrity: (!selection.encryption.is_aead).then(|| selection.integrity.name.into()),
            prf: Some(selection.prf.name.into()),
            dh: Some(selection.dh.name.into()),
        }));
        Ok(())
    }

    pub(crate) fn emit_negotiated_esp_algorithms(&self) -> Result<()> {
        let selection = self.selected_esp_proposal()?;
        self.emit_event(Ikev2Event::NegotiatedAlgorithm(Ikev2NegotiatedAlgorithm {
            protocol: "esp",
            encryption: selection.encryption.name.into(),
            integrity: (!selection.encryption.is_aead).then(|| selection.integrity.name.into()),
            prf: None,
            dh: None,
        }));
        Ok(())
    }

    pub(crate) fn emit_eap_process(&self, state: &'static str, round: Option<u16>) {
        self.emit_event(Ikev2Event::EapProcess(Ikev2EapProcess {
            method: self.eap_method.name().into(),
            state,
            round,
        }));
    }
}
