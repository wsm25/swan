pub mod mschapv2;
pub mod payload;
pub mod peap;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use bytes::Bytes;

pub use mschapv2::{Mschapv2Config, Mschapv2Method, Mschapv2Phase};
pub use payload::{InboundEapPacket, build_eap_response, build_identity_response, parse_eap};
pub use peap::{PeapConfig, PeapMethod, PeapPhase};

const_variant! {
    EAP_CODE_NAMES, u8, (&'static str, &'static str):
    (EAP_CODE_REQUEST, 1u8, ("REQ", "Request")),
    (EAP_CODE_RESPONSE, 2u8, ("RES", "Response")),
    (EAP_CODE_SUCCESS, 3u8, ("SUCCESS", "Success")),
    (EAP_CODE_FAILURE, 4u8, ("FAILURE", "Failure")),
}

const_variant! {
    EAP_TYPE_NAMES, u8, (&'static str, &'static str):
    (EAP_TYPE_IDENTITY, 1u8, ("IDENTITY", "Identity")),
    (EAP_TYPE_NAK, 3u8, ("NAK", "Nak")),
    (EAP_TYPE_PEAP, 25u8, ("PEAP", "Protected EAP")),
    (EAP_TYPE_MSCHAPV2, 26u8, ("MSCHAPV2", "MS-CHAP-V2")),
}

pub struct EapMethodConfig {
    pub peer_identity: String,
    pub peer_password: String,
    pub aaa_identity: String,
    pub method_name: String,
    pub peap_fragment_size: usize,
    pub peap_max_message_count: usize,
    pub peap_include_length: bool,
    pub strongswan_compatible: bool,
}

pub struct EapRunResult {
    pub exported_msk: Box<[u8]>,
}

pub enum EapAction {
    Send(Bytes),
    Complete(Box<[u8]>),
}

#[derive(Default)]
pub struct EapConversation {
    pub round_index: u16,
    pub last_request: Option<Bytes>,
    pub last_response: Option<Bytes>,
    pub peer_msk: Option<Box<[u8]>>,
}

impl EapConversation {
    pub fn new() -> Self {
        Default::default()
    }
}

#[async_trait]
pub trait EapPeer: Send {
    async fn recv_request(&mut self) -> Result<Bytes>;

    async fn send_response(&mut self, packet: Bytes) -> Result<()>;

    fn next_round_index(&self) -> u16;
}

#[async_trait]
pub trait EapMethod: Send {
    fn name(&self) -> &str;

    // Clone the method configuration and reusable setup, not any live in-flight
    // exchange state. Implementations should return a fresh method instance that
    // is suitable for a new run rather than trying to duplicate active protocol
    // session state such as PEAP/TLS transcripts.
    fn clone_box(&self) -> Box<dyn EapMethod>;

    fn initialize(&mut self) -> Result<()>;

    fn handle_packet(&mut self, packet: Bytes, round_index: u16) -> Result<EapAction>;

    async fn run(&mut self, peer: &mut dyn EapPeer) -> Result<EapRunResult> {
        self.initialize()?;
        loop {
            let packet = peer.recv_request().await?;
            crate::debug_fmt::log_eap("recv", &packet);
            match self.handle_packet(packet, peer.next_round_index())? {
                EapAction::Send(response) => {
                    crate::debug_fmt::log_eap("send", &response);
                    peer.send_response(response).await?
                }
                EapAction::Complete(exported_msk) => return Ok(EapRunResult { exported_msk }),
            }
        }
    }
}

impl Clone for Box<dyn EapMethod> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

pub fn build_method(config: EapMethodConfig) -> Result<Box<dyn EapMethod>> {
    match config.method_name.as_str() {
        "peap" => Ok(Box::new(PeapMethod::new(PeapConfig {
            identity: config.peer_identity,
            password: config.peer_password,
            aaa_identity: config.aaa_identity,
            fragment_size: config.peap_fragment_size,
            max_message_count: config.peap_max_message_count,
            include_length: config.peap_include_length,
            strongswan_compatible: config.strongswan_compatible,
        })?)),
        "mschapv2" => Ok(Box::new(Mschapv2Method::new(Mschapv2Config {
            identity: config.peer_identity,
            password: config.peer_password,
        }))),
        other => bail!("unsupported eap method scaffold: {other}"),
    }
}
