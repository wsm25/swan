mod core;
mod md4;

use anyhow::{Result, bail, ensure};
use bytes::Bytes;

use crate::eap::{
    InboundEapPacket, build_identity_response, parse_eap, payload::build_nak_response,
};
use md4::md4;

use super::{EAP_TYPE_MSCHAPV2, EapAction, EapConversation, EapMethod};

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum Mschapv2Phase {
    #[default]
    Idle,
    Negotiating,
    Challenging,
    Verifying,
    Completed,
    Failed,
}

#[derive(Clone)]
pub struct Mschapv2Config {
    pub identity: String,
    pub password: String,
}

pub struct Mschapv2Method {
    config: Mschapv2Config,
    phase: Mschapv2Phase,
    conversation: EapConversation,
    state: Option<core::Mschapv2State>,
}

impl Mschapv2Method {
    pub fn new(config: Mschapv2Config) -> Self {
        Self {
            config,
            phase: Mschapv2Phase::Idle,
            conversation: EapConversation::new(),
            state: None,
        }
    }

    fn reset(&mut self) {
        self.phase = Mschapv2Phase::Negotiating;
        self.state = None;
        self.conversation = EapConversation::new();
    }
}

impl EapMethod for Mschapv2Method {
    fn name(&self) -> &str {
        "mschapv2"
    }

    fn clone_box(&self) -> Box<dyn EapMethod> {
        Box::new(Self::new(self.config.clone()))
    }

    fn initialize(&mut self) -> Result<()> {
        ensure!(!self.config.identity.is_empty(), "mschapv2 identity is empty");
        ensure!(!self.config.password.is_empty(), "mschapv2 password is empty");
        self.reset();
        Ok(())
    }

    fn handle_packet(&mut self, packet: Bytes, round_index: u16) -> Result<EapAction> {
        self.conversation.round_index = round_index;
        self.conversation.last_request = Some(packet.clone());
        let payloads = parse_eap(&packet)?;
        match payloads {
            InboundEapPacket::Identity { identifier } => {
                self.phase = Mschapv2Phase::Negotiating;
                let response =
                    build_identity_response(identifier, self.config.identity.as_bytes())?;
                self.conversation.last_response = Some(response.clone());
                Ok(EapAction::Send(response))
            }
            InboundEapPacket::Request { identifier, eap_type, payload } => {
                if eap_type != EAP_TYPE_MSCHAPV2 {
                    self.phase = Mschapv2Phase::Negotiating;
                    let response = build_nak_response(identifier, &[EAP_TYPE_MSCHAPV2])?;
                    self.conversation.last_response = Some(response.clone());
                    return Ok(EapAction::Send(response));
                }

                self.phase = if self.state.is_some() {
                    Mschapv2Phase::Verifying
                } else {
                    Mschapv2Phase::Challenging
                };
                match core::on_request(
                    &mut self.state,
                    identifier,
                    payload,
                    &self.config.identity,
                    &self.config.password,
                )? {
                    core::Mschapv2Step::Outbound(msg) => {
                        self.conversation.last_response = Some(msg.clone());
                        Ok(EapAction::Send(msg))
                    }
                    core::Mschapv2Step::Failure(reason) => {
                        self.phase = Mschapv2Phase::Failed;
                        bail!(reason)
                    }
                }
            }
            InboundEapPacket::Success { identifier: _ } => {
                let Some(state) = &self.state else {
                    bail!("mschapv2 success without prior challenge");
                };
                ensure!(!state.expecting_success, "outer eap success before verified mschapv2");
                let exported_msk = state.msk.clone();
                self.phase = Mschapv2Phase::Completed;
                self.conversation.peer_msk = Some(exported_msk.clone());
                Ok(EapAction::Complete(exported_msk))
            }
            InboundEapPacket::Failure { identifier } => {
                self.phase = Mschapv2Phase::Failed;
                bail!("received eap failure with identifier {}", identifier)
            }
        }
    }
}
