use bytes::Bytes;
use std::{collections::VecDeque, time::Instant};

use super::{AssignedConfig, ChildSaInstall};

#[derive(Clone, Copy, Default)]
pub enum IkeSaState {
    #[default]
    Stopped,
    Starting,
    IkeSaInitSent,
    IkeSaInitEstablished,
    IkeAuthBootstrap,
    IkeAuthEapInProgress,
    ChildSaInstalling,
    Running,
    Failed,
}

impl IkeSaState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Stopped | Self::Running | Self::Failed)
    }

    pub fn is_handshaking(self) -> bool {
        matches!(
            self,
            Self::Starting
                | Self::IkeSaInitSent
                | Self::IkeSaInitEstablished
                | Self::IkeAuthBootstrap
                | Self::IkeAuthEapInProgress
                | Self::ChildSaInstalling
        )
    }
}

#[derive(Default)]
pub struct IkeSa {
    pub state: IkeSaState,
    pub next_request_message_id: u32,
    pub expected_response_message_id: Option<u32>,
    pub last_completed_response_message_id: Option<u32>,
    pub first_ike_auth_seen: bool,
    pub initiator_spi: u64,
    pub responder_spi: u64,
    pub sa_init_request: Option<Bytes>,
    pub sa_init_response: Option<Bytes>,
    pub sa_init_cookie: Option<Box<[u8]>>,
    pub initiator_nonce: Option<Bytes>,
    pub responder_nonce: Option<Bytes>,
    pub initiator_ke: Option<KeyExchangePayload>,
    pub responder_ke: Option<KeyExchangePayload>,
    pub key_material: Option<IkeKeyMaterial>,
    pub nat: NatDetectionState,
    pub auth: IkeAuthState,
    pub assigned_config: Option<AssignedConfig>,
    pub negotiating_child_sa: Option<NegotiatingChildSa>,
    pub active_child_sa: Option<ActiveChildSa>,
    pub outbound_request: Option<OutboundRequest>,
    pub inbound_request_history: VecDeque<InboundRequestResponse>,
    pub peer: PeerCapabilities,
    pub inbound_fragments: Option<InboundFragmentReassembly>,
    pub failure_reason: Option<String>,
    pub suppress_error_auth_failed_notify: bool,
}

impl IkeSa {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }

    pub fn set_outbound_request(&mut self, message_id: u32, packets: Vec<Bytes>) {
        self.outbound_request = Some(OutboundRequest { message_id, packets });
    }

    pub fn clear_outbound_request(&mut self) {
        self.outbound_request = None;
    }
}

#[derive(Clone)]
pub struct KeyExchangePayload {
    pub dh_group: u16,
    pub value: Box<[u8]>,
}

#[derive(Clone)]
pub struct IkeKeyMaterial {
    pub sk_d: Box<[u8]>,
    pub sk_ai: Box<[u8]>,
    pub sk_ar: Box<[u8]>,
    pub sk_ei: Box<[u8]>,
    pub sk_er: Box<[u8]>,
    pub sk_pi: Box<[u8]>,
    pub sk_pr: Box<[u8]>,
}

#[derive(Default)]
pub struct NatDetectionState {
    pub source_hash_local: Option<Box<[u8]>>,
    pub destination_hash_local: Option<Box<[u8]>>,
    pub source_hash_remote: Option<Box<[u8]>>,
    pub destination_hash_remote: Option<Box<[u8]>>,
    pub detected: bool,
}

impl NatDetectionState {
    pub fn new() -> Self {
        Self {
            source_hash_local: None,
            destination_hash_local: None,
            source_hash_remote: None,
            destination_hash_remote: None,
            detected: false,
        }
    }
}

#[derive(Default)]
pub struct IkeAuthState {
    pub first_idi_payload: Option<Bytes>,
    pub peer_idr_payload: Option<Bytes>,
    pub peer_auth_method: Option<u8>,
    pub peer_signature_hash_algorithms: Box<[u16]>,
    pub peer_cert_der: Option<Bytes>,
    pub peer_cert_chain: Vec<Bytes>,
    pub local_eap_msk: Option<Box<[u8]>>,
}

impl IkeAuthState {
    pub fn new() -> Self {
        Self {
            first_idi_payload: None,
            peer_idr_payload: None,
            peer_auth_method: None,
            peer_signature_hash_algorithms: Box::new([]),
            peer_cert_der: None,
            peer_cert_chain: Vec::new(),
            local_eap_msk: None,
        }
    }
}

pub struct NegotiatingChildSa {
    pub inbound_spi: u32,
}

pub struct ActiveChildSa {
    pub install: ChildSaInstall,
}

pub struct OutboundRequest {
    pub message_id: u32,
    pub packets: Vec<Bytes>,
}

pub struct InboundRequestResponse {
    pub message_id: u32,
    pub response_packets: Vec<Bytes>,
}

pub struct WireCheckpoint {
    pub message_id: u32,
    pub packet: Bytes,
}

#[derive(Default)]
pub struct SaInitState {
    pub request: Option<WireCheckpoint>,
    pub response: Option<WireCheckpoint>,
    pub cookie: Option<Box<[u8]>>,
}

impl SaInitState {
    pub fn new() -> Self {
        Default::default()
    }
}

#[derive(Default)]
pub struct EapRoundState {
    pub inbound_request: Option<WireCheckpoint>,
    pub outbound_response: Option<WireCheckpoint>,
    pub round_index: u16,
}

impl EapRoundState {
    pub fn new() -> Self {
        Default::default()
    }
}

#[derive(Default)]
pub struct PeerCapabilities {
    pub supports_eap_only_authentication: bool,
    pub supports_message_id_sync: bool,
    pub supports_fragmentation: bool,
}

impl PeerCapabilities {
    pub fn new() -> Self {
        Default::default()
    }
}

pub struct InboundFragmentReassembly {
    pub exchange_type: u8,
    pub message_id: u32,
    pub first_inner_payload: Option<u8>,
    pub fragments: Vec<Option<Bytes>>,
    pub expires_at: Instant,
}
