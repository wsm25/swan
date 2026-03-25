mod avp;
mod identity;
mod tls;

use anyhow::{Context, Result, anyhow, bail, ensure};
use bytes::{Bytes, BytesMut};

use super::{
    EAP_CODE_REQUEST, EAP_CODE_RESPONSE, EAP_TYPE_IDENTITY, EAP_TYPE_PEAP, EapAction,
    EapConversation, EapMethod, Mschapv2Config, Mschapv2Method,
};
use avp::{decode_peer_request, encode_peer_response};
use tls::{OpenSslPeapTlsBackend, PeapTlsBackend, PeapTlsStep};

pub const PEAP_FLAG_LENGTH_INCLUDED: u8 = 0x80;
pub const PEAP_FLAG_MORE_FRAGMENTS: u8 = 0x40;
pub const PEAP_FLAG_START: u8 = 0x20;
pub const PEAP_SUPPORTED_VERSION: u8 = 0;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum PeapPhase {
    #[default]
    Idle,
    OuterIdentity,
    TlsTunnel,
    InnerMethod,
    AwaitingOuterSuccess,
    AwaitingOuterFailure,
    Completed,
    Failed,
}

#[derive(Clone)]
pub struct PeapConfig {
    pub identity: String,
    pub password: String,
    pub aaa_identity: String,
    pub fragment_size: usize,
    pub max_message_count: usize,
    pub include_length: bool,
    pub tls13_strongswan_compat: bool,
}

pub struct PeapPacket {
    pub code: u8,
    pub identifier: u8,
    pub flags: u8,
    pub tls_message_length: Option<u32>,
    pub tls_data: Bytes,
}

enum InboundEapPacket {
    Identity { identifier: u8 },
    Peap(PeapPacket),
    Success { identifier: u8 },
    Failure { identifier: u8 },
}

pub struct PeapMethod {
    config: PeapConfig,
    phase: PeapPhase,
    conversation: EapConversation,
    tls: OpenSslPeapTlsBackend,
    inner: Mschapv2Method,
    inbound_tls_fragments: BytesMut,
    inbound_tls_total_len: Option<usize>,
    outbound_fragment_buffer: Option<Bytes>,
    outbound_fragment_offset: usize,
    processed_message_count: usize,
}

impl PeapMethod {
    pub fn new(config: PeapConfig) -> Result<Self> {
        let tls =
            OpenSslPeapTlsBackend::new(config.aaa_identity.clone(), config.tls13_strongswan_compat)?;
        let inner = Mschapv2Method::new(Mschapv2Config {
            identity: config.identity.clone(),
            password: config.password.clone(),
        });
        Ok(Self {
            config,
            phase: PeapPhase::Idle,
            conversation: EapConversation::new(),
            tls,
            inner,
            inbound_tls_fragments: BytesMut::new(),
            inbound_tls_total_len: None,
            outbound_fragment_buffer: None,
            outbound_fragment_offset: 0,
            processed_message_count: 0,
        })
    }

    fn reset(&mut self) {
        self.phase = PeapPhase::OuterIdentity;
        self.conversation = EapConversation::new();
        self.tls.reset();
        self.inner = Mschapv2Method::new(Mschapv2Config {
            identity: self.config.identity.clone(),
            password: self.config.password.clone(),
        });
        self.inbound_tls_fragments.clear();
        self.inbound_tls_total_len = None;
        self.outbound_fragment_buffer = None;
        self.outbound_fragment_offset = 0;
        self.processed_message_count = 0;
    }

    fn parse_peap(packet: &[u8]) -> Result<PeapPacket> {
        ensure!(packet.len() >= 6, "peap packet too short");
        let code = packet[0];
        let identifier = packet[1];
        let length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        ensure!(length == packet.len(), "peap eap length mismatch");
        ensure!(packet[4] == EAP_TYPE_PEAP, "unexpected outer eap type");
        let flags = packet[5];
        let version = flags & 0x07;
        ensure!(version == PEAP_SUPPORTED_VERSION, "unsupported peap version");

        let mut offset = 6;
        let tls_message_length = if flags & PEAP_FLAG_LENGTH_INCLUDED != 0 {
            ensure!(packet.len() >= 10, "peap packet missing tls length");
            let len = u32::from_be_bytes([
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3],
            ]);
            offset += 4;
            Some(len)
        } else {
            None
        };
        ensure!(offset <= packet.len(), "invalid peap payload offset");
        Ok(PeapPacket {
            code,
            identifier,
            flags,
            tls_message_length,
            tls_data: Bytes::copy_from_slice(&packet[offset..]),
        })
    }

    fn parse_inbound_packet(packet: &[u8]) -> Result<InboundEapPacket> {
        ensure!(packet.len() >= 4, "eap packet too short");
        let identifier = packet[1];
        let length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        ensure!(length == packet.len(), "eap length mismatch");
        match packet[0] {
            EAP_CODE_REQUEST => {}
            super::EAP_CODE_SUCCESS => return Ok(InboundEapPacket::Success { identifier }),
            super::EAP_CODE_FAILURE => return Ok(InboundEapPacket::Failure { identifier }),
            other => bail!("unsupported outer eap code {other} for peap"),
        }
        ensure!(length >= 5, "eap request missing type");
        match packet[4] {
            EAP_TYPE_IDENTITY => Ok(InboundEapPacket::Identity { identifier }),
            EAP_TYPE_PEAP => Ok(InboundEapPacket::Peap(Self::parse_peap(packet)?)),
            other => bail!("unsupported outer eap type {other} for peap"),
        }
    }

    fn encode_identity_response(&self, identifier: u8) -> Bytes {
        let identity = self.config.identity.as_bytes();
        let len = 5 + identity.len();
        let mut out = Vec::with_capacity(len);
        out.push(EAP_CODE_RESPONSE);
        out.push(identifier);
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.push(EAP_TYPE_IDENTITY);
        out.extend_from_slice(identity);
        Bytes::from(out)
    }

    fn encode_peap_response(
        &self,
        identifier: u8,
        flags: u8,
        payload: &[u8],
        total_length: Option<u32>,
    ) -> Result<Bytes> {
        let mut out = Vec::with_capacity(10 + payload.len());
        out.push(EAP_CODE_RESPONSE);
        out.push(identifier);
        out.extend_from_slice(&0u16.to_be_bytes());
        out.push(EAP_TYPE_PEAP);
        let mut packet_flags = flags | PEAP_SUPPORTED_VERSION;
        if total_length.is_some() {
            packet_flags |= PEAP_FLAG_LENGTH_INCLUDED;
        }
        out.push(packet_flags);
        if let Some(total_length) = total_length {
            out.extend_from_slice(&total_length.to_be_bytes());
        }
        out.extend_from_slice(payload);
        let len = u16::try_from(out.len()).context("peap packet too large")?;
        out[2..4].copy_from_slice(&len.to_be_bytes());
        Ok(Bytes::from(out))
    }

    fn encode_empty_ack(&self, identifier: u8) -> Result<Bytes> {
        self.encode_peap_response(identifier, 0, &[], None)
    }

    fn emit_fragmented_or_single(
        &mut self,
        identifier: u8,
        payload: Bytes,
        initial_flags: u8,
    ) -> Result<Bytes> {
        let max_fragment_len = self.config.fragment_size;
        if payload.len() <= max_fragment_len {
            let total_length = self.config.include_length.then_some(
                u32::try_from(payload.len()).context("peap payload too large")?,
            );
            return self.encode_peap_response(
                identifier,
                initial_flags,
                payload.as_ref(),
                total_length,
            );
        }

        let first = payload.slice(0..max_fragment_len);
        self.outbound_fragment_buffer = Some(payload);
        self.outbound_fragment_offset = max_fragment_len;
        let total_length = self
            .outbound_fragment_buffer
            .as_ref()
            .map(|buf| buf.len())
            .ok_or_else(|| anyhow!("missing outbound peap buffer"))?;
        self.encode_peap_response(
            identifier,
            initial_flags | PEAP_FLAG_MORE_FRAGMENTS,
            first.as_ref(),
            Some(u32::try_from(total_length).context("peap payload too large")?),
        )
    }

    fn emit_next_fragment(&mut self, identifier: u8) -> Result<Bytes> {
        let payload = self
            .outbound_fragment_buffer
            .as_ref()
            .ok_or_else(|| anyhow!("no outbound peap fragment pending"))?;
        let start = self.outbound_fragment_offset;
        let end = payload.len().min(start.saturating_add(self.config.fragment_size));
        ensure!(start <= end, "invalid outbound peap fragment offsets");
        let more = end < payload.len();
        let flags = if more { PEAP_FLAG_MORE_FRAGMENTS } else { 0 };
        let response = self.encode_peap_response(identifier, flags, &payload[start..end], None)?;
        self.outbound_fragment_offset = end;
        if !more {
            self.outbound_fragment_buffer = None;
            self.outbound_fragment_offset = 0;
        }
        Ok(response)
    }

    fn is_ack_packet(request: &PeapPacket) -> bool {
        request.tls_data.is_empty()
            && request.tls_message_length.is_none()
            && (request.flags
                & (PEAP_FLAG_START | PEAP_FLAG_MORE_FRAGMENTS | PEAP_FLAG_LENGTH_INCLUDED))
                == 0
    }

    fn collect_tls_record(&mut self, request: &PeapPacket) -> Result<Option<Bytes>> {
        let is_fragmented = (request.flags & PEAP_FLAG_MORE_FRAGMENTS) != 0
            || self.inbound_tls_total_len.is_some()
            || !self.inbound_tls_fragments.is_empty();
        if !is_fragmented {
            if let Some(total_len) = request.tls_message_length {
                ensure!(
                    request.tls_data.len() == total_len as usize,
                    "peap tls length mismatch on unfragmented packet"
                );
            }
            return Ok(Some(request.tls_data.clone()));
        }

        if self.inbound_tls_total_len.is_none() {
            ensure!(
                (request.flags & PEAP_FLAG_START) == 0,
                "unexpected peap start flag on fragmented tls record"
            );
            ensure!(
                request.tls_message_length.is_some(),
                "first fragmented peap packet must include tls length"
            );
            self.inbound_tls_total_len = request.tls_message_length.map(|value| value as usize);
        } else {
            ensure!(
                (request.flags & PEAP_FLAG_START) == 0,
                "unexpected peap start flag on continuation fragment"
            );
            ensure!(
                request.tls_message_length.is_none(),
                "unexpected peap tls length on continuation fragment"
            );
        }

        self.inbound_tls_fragments.extend_from_slice(&request.tls_data);
        if let Some(total_len) = self.inbound_tls_total_len {
            ensure!(
                self.inbound_tls_fragments.len() <= total_len,
                "peap tls reassembly exceeded declared total length"
            );
        }
        if (request.flags & PEAP_FLAG_MORE_FRAGMENTS) != 0 {
            return Ok(None);
        }

        let expected_total = self
            .inbound_tls_total_len
            .take()
            .ok_or_else(|| anyhow!("missing peap tls total length during reassembly"))?;
        ensure!(
            self.inbound_tls_fragments.len() == expected_total,
            "peap tls reassembly length mismatch"
        );
        Ok(Some(self.inbound_tls_fragments.split().freeze()))
    }

    fn on_tls_step(&mut self, identifier: u8, step: PeapTlsStep) -> Result<EapAction> {
        match step {
            PeapTlsStep::NeedMoreData => Ok(EapAction::Send(self.encode_empty_ack(identifier)?)),
            PeapTlsStep::Outbound(record) => {
                if self.phase == PeapPhase::TlsTunnel && self.tls.is_tunnel_ready() {
                    self.tls.verify_server_identity(&self.config.aaa_identity)?;
                    self.phase = PeapPhase::InnerMethod;
                    self.inner.initialize()?;
                }
                Ok(EapAction::Send(self.emit_fragmented_or_single(identifier, record, 0)?))
            }
            PeapTlsStep::TunnelReady => {
                self.tls.verify_server_identity(&self.config.aaa_identity)?;
                self.phase = PeapPhase::InnerMethod;
                self.inner.initialize()?;
                let response = self.encode_empty_ack(identifier)?;
                Ok(EapAction::Send(response))
            }
        }
    }
    fn handle_packet_inner(&mut self, packet: Bytes, round_index: u16) -> Result<EapAction> {
        self.conversation.round_index = round_index;
        self.conversation.last_request = Some(packet.clone());
        let inbound = Self::parse_inbound_packet(packet.as_ref())?;

        if let InboundEapPacket::Peap(peap) = &inbound {
            self.processed_message_count = self.processed_message_count.saturating_add(1);
            if self.config.max_message_count > 0
                && self.processed_message_count > self.config.max_message_count
            {
                self.phase = PeapPhase::Failed;
                bail!("peap packet count exceeded");
            }
            if self.outbound_fragment_buffer.is_some() {
                ensure!(
                    Self::is_ack_packet(peap),
                    "expected peap ack while outbound fragments pending"
                );
                let response = self.emit_next_fragment(peap.identifier)?;
                self.conversation.last_response = Some(response.clone());
                return Ok(EapAction::Send(response));
            }
        }

        let result = match (self.phase, inbound) {
            (PeapPhase::Idle, _) => bail!("peap method was not initialized"),
            (PeapPhase::OuterIdentity, InboundEapPacket::Identity { identifier }) => {
                Ok(EapAction::Send(self.encode_identity_response(identifier)))
            }
            (PeapPhase::OuterIdentity, InboundEapPacket::Peap(peap)) => {
                ensure!((peap.flags & PEAP_FLAG_START) != 0, "expected peap start flag");
                ensure!(peap.code == EAP_CODE_REQUEST, "expected eap request code");
                ensure!(peap.tls_message_length.is_none(), "unexpected peap tls length on start");
                ensure!(peap.tls_data.is_empty(), "unexpected peap tls payload on start");
                self.phase = PeapPhase::TlsTunnel;
                let client_hello = self.tls.start_client_hello()?;
                Ok(EapAction::Send(self.emit_fragmented_or_single(
                    peap.identifier,
                    client_hello,
                    0,
                )?))
            }
            (PeapPhase::OuterIdentity, _) => {
                bail!("unexpected outer eap packet during peap outer identity phase")
            }
            (PeapPhase::TlsTunnel, InboundEapPacket::Identity { .. }) => {
                bail!("unexpected outer identity request during peap tls tunnel")
            }
            (PeapPhase::TlsTunnel, InboundEapPacket::Failure { .. }) => {
                self.phase = PeapPhase::Failed;
                bail!("peap authentication failed")
            }
            (PeapPhase::TlsTunnel, InboundEapPacket::Success { identifier }) => {
                self.phase = PeapPhase::Failed;
                bail!("unexpected outer EAP success {identifier} during peap tls tunnel")
            }
            (PeapPhase::TlsTunnel, InboundEapPacket::Peap(peap)) => {
                ensure!((peap.flags & PEAP_FLAG_START) == 0, "unexpected peap start flag");
                if Self::is_ack_packet(&peap) {
                    return Ok(EapAction::Send(self.encode_empty_ack(peap.identifier)?));
                }
                let record = self.collect_tls_record(&peap)?;
                let Some(record) = record else {
                    return Ok(EapAction::Send(self.encode_empty_ack(peap.identifier)?));
                };
                let step = self.tls.on_tls_record(record.as_ref())?;
                self.on_tls_step(peap.identifier, step)
            }
            (PeapPhase::InnerMethod, InboundEapPacket::Identity { .. }) => {
                bail!("unexpected outer identity request during peap inner method")
            }
            (PeapPhase::InnerMethod, InboundEapPacket::Failure { .. }) => {
                self.phase = PeapPhase::Failed;
                bail!("peap authentication failed")
            }
            (PeapPhase::InnerMethod, InboundEapPacket::Success { identifier }) => {
                self.phase = PeapPhase::Failed;
                bail!("unexpected outer EAP success {identifier} during peap inner method")
            }
            (PeapPhase::InnerMethod, InboundEapPacket::Peap(peap)) => {
                ensure!((peap.flags & PEAP_FLAG_START) == 0, "unexpected peap start flag");
                if Self::is_ack_packet(&peap) {
                    return Ok(EapAction::Send(self.encode_empty_ack(peap.identifier)?));
                }
                let record = self.collect_tls_record(&peap)?;
                let Some(record) = record else {
                    return Ok(EapAction::Send(self.encode_empty_ack(peap.identifier)?));
                };
                let plaintext = self.tls.unprotect_tunnel_data(record.as_ref())?;
                ensure!(!plaintext.is_empty(), "unexpected empty inner tunneled payload");
                let inner_request = decode_peer_request(plaintext.as_ref(), peap.identifier)?;
                match inner_request[0] {
                    super::EAP_CODE_SUCCESS => {
                        let tunneled = encode_peer_response(inner_request.as_ref())?;
                        let protected = self.tls.protect_tunnel_data(tunneled.as_ref())?;
                        self.phase = PeapPhase::AwaitingOuterSuccess;
                        Ok(EapAction::Send(self.emit_fragmented_or_single(
                            peap.identifier,
                            protected,
                            0,
                        )?))
                    }
                    super::EAP_CODE_FAILURE => {
                        let tunneled = encode_peer_response(inner_request.as_ref())?;
                        let protected = self.tls.protect_tunnel_data(tunneled.as_ref())?;
                        self.phase = PeapPhase::AwaitingOuterFailure;
                        Ok(EapAction::Send(self.emit_fragmented_or_single(
                            peap.identifier,
                            protected,
                            0,
                        )?))
                    }
                    _ => match self.inner.handle_packet(inner_request, round_index)? {
                        EapAction::Send(response) => {
                            let tunneled = encode_peer_response(response.as_ref())?;
                            let protected = self.tls.protect_tunnel_data(tunneled.as_ref())?;
                            Ok(EapAction::Send(self.emit_fragmented_or_single(
                                peap.identifier,
                                protected,
                                0,
                            )?))
                        }
                        EapAction::Complete(_) => {
                            bail!(
                                "unexpected standalone mschapv2 completion without terminal inner packet"
                            )
                        }
                    },
                }
            }
            (PeapPhase::AwaitingOuterSuccess, InboundEapPacket::Success { .. }) => {
                let exported_msk = self
                    .tls
                    .export_eap_msk()?
                    .ok_or_else(|| anyhow!("peap tls did not export eap msk"))?;
                self.phase = PeapPhase::Completed;
                self.conversation.peer_msk = Some(exported_msk.clone());
                Ok(EapAction::Complete(exported_msk))
            }
            (PeapPhase::AwaitingOuterSuccess, InboundEapPacket::Failure { identifier }) => {
                self.phase = PeapPhase::Failed;
                bail!("unexpected outer EAP failure {identifier} after inner success")
            }
            (PeapPhase::AwaitingOuterFailure, InboundEapPacket::Failure { .. }) => {
                self.phase = PeapPhase::Failed;
                bail!("peap authentication failed")
            }
            (PeapPhase::AwaitingOuterFailure, InboundEapPacket::Success { identifier }) => {
                self.phase = PeapPhase::Failed;
                bail!("unexpected outer EAP success {identifier} after inner failure")
            }
            (PeapPhase::AwaitingOuterSuccess, _) => {
                bail!("unexpected outer eap packet while awaiting outer success")
            }
            (PeapPhase::AwaitingOuterFailure, _) => {
                bail!("unexpected outer eap packet while awaiting outer failure")
            }
            (PeapPhase::Completed, _) => {
                let exported_msk = self
                    .conversation
                    .peer_msk
                    .clone()
                    .context("peap completed without exported msk")?;
                Ok(EapAction::Complete(exported_msk))
            }
            (PeapPhase::Failed, _) => bail!("peap method is in failure state"),
        };

        if let Ok(EapAction::Send(response)) = &result {
            self.conversation.last_response = Some(response.clone());
        }
        if result.is_err() {
            self.phase = PeapPhase::Failed;
        }
        result
    }
}

impl EapMethod for PeapMethod {
    fn name(&self) -> &str {
        "peap"
    }

    fn clone_box(&self) -> Box<dyn EapMethod> {
        Box::new(Self::new(self.config.clone()).unwrap())
    }

    fn initialize(&mut self) -> Result<()> {
        ensure!(!self.config.identity.is_empty(), "peap identity is empty");
        ensure!(!self.config.password.is_empty(), "peap password is empty");
        ensure!(!self.config.aaa_identity.is_empty(), "peap aaa_identity is empty");
        ensure!(self.config.fragment_size > 0, "peap fragment_size must be > 0");
        self.reset();
        Ok(())
    }

    fn handle_packet(&mut self, packet: Bytes, round_index: u16) -> Result<EapAction> {
        self.handle_packet_inner(packet, round_index)
    }
}
