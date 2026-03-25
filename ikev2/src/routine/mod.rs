pub(crate) mod common;
mod control;
mod delete_exchange;
mod exchange_io;
mod ids;
mod packet_io;
mod transport_setup;
mod sa_init;
mod sa_init_shared;
mod auth_shared;
mod auth_bootstrap;
mod eap;
mod peer_auth;
mod child_sa;

use anyhow::Result;
use std::net::SocketAddr;

use crate::{
    Ikev2Config, UdpConn,
    eap::{EapMethod, EapMethodConfig, build_method},
};

use super::{AssignedConfig, ChildSaInstall, IkeSa, state::IkeSaState};

pub(crate) use common::{InboundControlOutcome, InboundResponseDisposition, InboundUdpPacket, OutboundUdpPacket};

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
    pub transport: Option<TransportSetup>,
    pub peer_identity: Option<PeerIdentity>,
    pub local_identity: Option<PeerIdentity>,
    pub(super) broken: bool,
    pub(super) local_dh: Option<super::cipher::DhKeyPair>,
    pub(super) selected_suite: Option<crate::config::CipherSuiteSelection>,
}

impl Ikev2Routine {
    pub fn new(config: Ikev2Config) -> Self {
        let eap_identity = config.eap_identity.clone();
        let eap_password = config.eap_password.clone();
        let aaa_identity = config.aaa_identity.clone();
        let eap_method = config.eap_method.clone();
        let peap_fragment_size = config.peap_fragment_size;
        let peap_max_message_count = config.peap_max_message_count;
        let peap_include_length = config.peap_include_length;
        let peap_tls13_strongswan_compat = config.peap_tls13_strongswan_compat;
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
                peap_tls13_strongswan_compat,
            })
            .unwrap(),
            transport: None,
            peer_identity: None,
            local_identity: None,
            broken: false,
            local_dh: None,
            selected_suite: None,
        }
    }

    pub async fn run(&mut self, udp_conn: &mut dyn UdpConn) -> Result<RoutineSummary> {
        self.setup_transport(udp_conn)?;
        self.run_sa_init(udp_conn).await?;
        self.start_auth(udp_conn).await?;
        self.run_eap(udp_conn).await?;
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
}
