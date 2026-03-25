mod core;

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;

use super::{
    EAP_CODE_FAILURE, EAP_CODE_REQUEST, EAP_CODE_RESPONSE, EAP_CODE_SUCCESS, EAP_TYPE_IDENTITY,
    EAP_TYPE_MSCHAPV2, EAP_TYPE_NAK, EapAction, EapConversation, EapMethod,
};

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

    fn parse_eap(packet: &[u8]) -> Result<(u8, u8, Option<u8>, &[u8])> {
        ensure!(packet.len() >= 4, "eap packet too short");
        let code = packet[0];
        let identifier = packet[1];
        let length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        ensure!(length == packet.len(), "eap length mismatch");
        if matches!(code, EAP_CODE_SUCCESS | EAP_CODE_FAILURE) {
            ensure!(length == 4, "eap result packet length must be 4");
            return Ok((code, identifier, None, &[]));
        }
        ensure!(length >= 5, "eap request missing type");
        Ok((code, identifier, Some(packet[4]), &packet[5..]))
    }

    fn encode_identity_response(identifier: u8, identity: &[u8]) -> Bytes {
        let len = 5 + identity.len();
        let mut out = Vec::with_capacity(len);
        out.push(EAP_CODE_RESPONSE);
        out.push(identifier);
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.push(EAP_TYPE_IDENTITY);
        out.extend_from_slice(identity);
        Bytes::from(out)
    }

    fn encode_nak_response(identifier: u8) -> Bytes {
        let len = 6u16;
        let mut out = Vec::with_capacity(len as usize);
        out.push(EAP_CODE_RESPONSE);
        out.push(identifier);
        out.extend_from_slice(&len.to_be_bytes());
        out.push(EAP_TYPE_NAK);
        out.push(EAP_TYPE_MSCHAPV2);
        Bytes::from(out)
    }

    fn handle_packet_inner(&mut self, packet: Bytes, round_index: u16) -> Result<EapAction> {
        self.conversation.round_index = round_index;
        self.conversation.last_request = Some(packet.clone());

        let (code, identifier, eap_type, payload) = Self::parse_eap(packet.as_ref())?;
        match code {
            EAP_CODE_REQUEST => {
                let eap_type = eap_type.context("eap request missing type")?;
                match eap_type {
                    EAP_TYPE_IDENTITY => {
                        self.phase = Mschapv2Phase::Negotiating;
                        let response = Self::encode_identity_response(
                            identifier,
                            self.config.identity.as_bytes(),
                        );
                        self.conversation.last_response = Some(response.clone());
                        Ok(EapAction::Send(response))
                    }
                    EAP_TYPE_MSCHAPV2 => {
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
                    _ => {
                        self.phase = Mschapv2Phase::Negotiating;
                        let response = Self::encode_nak_response(identifier);
                        self.conversation.last_response = Some(response.clone());
                        Ok(EapAction::Send(response))
                    }
                }
            }
            EAP_CODE_SUCCESS => {
                ensure!(self.state.is_some(), "mschapv2 success without prior challenge");
                ensure!(
                    !core::expecting_success(&self.state),
                    "received outer eap success before verified mschapv2 success"
                );
                let exported_msk =
                    core::msk(&self.state).context("mschapv2 completed without exported msk")?;
                self.phase = Mschapv2Phase::Completed;
                self.conversation.peer_msk = Some(exported_msk.clone());
                Ok(EapAction::Complete(exported_msk))
            }
            EAP_CODE_FAILURE => {
                self.phase = Mschapv2Phase::Failed;
                bail!("received eap failure with identifier {}", identifier)
            }
            _ => bail!("unsupported eap code {}", code),
        }
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
        self.handle_packet_inner(packet, round_index)
    }
}
