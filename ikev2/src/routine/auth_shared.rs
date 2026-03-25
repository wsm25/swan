use super::Ikev2Routine;
use crate::{
    cipher::rand_bytes,
    consts::{
        CONFIG_ATTR_INTERNAL_IP4_ADDRESS, CONFIG_ATTR_INTERNAL_IP4_DNS,
        CONFIG_ATTR_INTERNAL_IP6_ADDRESS, CONFIG_ATTR_INTERNAL_IP6_DNS, EXCHANGE_TYPE_IKE_AUTH,
        EXCHANGE_TYPE_INFORMATIONAL, ID_TYPE_FQDN, ID_TYPE_IPV4_ADDR, ID_TYPE_IPV6_ADDR,
        ID_TYPE_KEY_ID, ID_TYPE_RFC822_ADDR, NOTIFY_TYPE_AUTHENTICATION_FAILED,
    },
    payload::{
        IkeHeader, IkeMessageBuilder, PAYLOAD_HEADER_LEN, PAYLOAD_TYPE_NONE, PAYLOAD_TYPE_NOTIFY,
        Payload, PayloadHeader, PayloadParseResult, PayloadParser,
    },
};
use anyhow::Result;
use bytemuck::{Pod, Zeroable, bytes_of};
use bytes::{BufMut, Bytes, BytesMut};

const IKE_FRAGMENT_PLAINTEXT_LIMIT: usize = 1024;

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
struct ConfigPayloadHeader {
    // CFG_REQUEST / CFG_REPLY plus the 24-bit reserved field.
    cfg_type: u8,
    reserved: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
struct ConfigAttributeHeader {
    // Configuration attribute type and explicit value length.
    attr_type: rend::u16_be,
    value_length: rend::u16_be,
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
struct IdPayloadHeader {
    // ID type plus the 24-bit reserved field.
    id_type: u8,
    reserved: [u8; 3],
}

impl Ikev2Routine {
    pub(super) fn parse_protected_packet(
        &mut self,
        packet: Bytes,
    ) -> Result<Option<(IkeHeader, Vec<Payload>)>> {
        let mut parser = PayloadParser::new(
            std::sync::Arc::new(self.payload_context()?),
            self.sa.inbound_fragments.take(),
        );
        let parsed = parser.parse_packet(packet)?;
        self.sa.inbound_fragments = parser.into_reassembly();
        Ok(match parsed {
            PayloadParseResult::Done { header, payloads } => {
                crate::debug_fmt::log_ike_parsed("recv parsed", header, payloads.as_slice());
                Some((header, payloads))
            }
            PayloadParseResult::NeedMore { .. } => None,
        })
    }

    pub(super) fn parse_response_protected(
        &mut self,
        packet: Bytes,
        exchange_type: u8,
        message_id: u32,
    ) -> Result<Option<Vec<Payload>>> {
        self.validate_expected_response_message_id(message_id)?;
        match self.parse_protected_packet(packet)? {
            Some((header, payloads)) => {
                self.validate_response_header(header, exchange_type, message_id)?;
                if exchange_type == crate::consts::EXCHANGE_TYPE_IKE_AUTH {
                    self.sa.first_ike_auth_seen = true;
                }
                self.sa.last_completed_response_message_id = Some(message_id);
                self.sa.inbound_fragments = None;
                self.sa.clear_outbound_request();
                Ok(Some(payloads))
            }
            None => {
                if exchange_type == crate::consts::EXCHANGE_TYPE_IKE_AUTH {
                    self.sa.first_ike_auth_seen = true;
                }
                Ok(None)
            }
        }
    }

    pub(super) fn build_single_protected_payload_packets_for_exchange(
        &self,
        exchange_type: u8,
        message_id: u32,
        payload_type: u8,
        payload_body: &[u8],
    ) -> Result<Vec<Bytes>> {
        let mut plaintext = BytesMut::with_capacity(PAYLOAD_HEADER_LEN + payload_body.len());
        plaintext.resize(plaintext.len() + PAYLOAD_HEADER_LEN, 0);
        let start = plaintext.len();
        plaintext.extend_from_slice(payload_body);
        let length = (PAYLOAD_HEADER_LEN + payload_body.len()) as u16;
        plaintext[start - PAYLOAD_HEADER_LEN..start]
            .copy_from_slice(bytes_of(&PayloadHeader::new(PAYLOAD_TYPE_NONE, false, length)));
        self.build_protected_message_packets(exchange_type, message_id, payload_type, plaintext)
    }

    pub(super) fn build_single_protected_payload_packets(
        &self,
        message_id: u32,
        payload_type: u8,
        payload_body: &[u8],
    ) -> Result<Vec<Bytes>> {
        self.build_single_protected_payload_packets_for_exchange(
            crate::consts::EXCHANGE_TYPE_IKE_AUTH,
            message_id,
            payload_type,
            payload_body,
        )
    }

    pub(super) fn build_protected_request(
        &self,
        message_id: u32,
        inner: IkeMessageBuilder,
    ) -> Result<Vec<Bytes>> {
        let first_payload = inner.first_payload;
        self.build_protected_message_packets(
            crate::consts::EXCHANGE_TYPE_IKE_AUTH,
            message_id,
            first_payload,
            inner.buffer,
        )
    }

    pub(crate) async fn send_authentication_failed_notify(
        &mut self,
        udp_conn: &mut dyn super::UdpConn,
    ) -> Result<()> {
        if self.sa.suppress_error_auth_failed_notify
            || self.sa.responder_spi == 0
            || self.sa.key_material.is_none()
        {
            return Ok(());
        }
        let message_id = self.sa.next_request_message_id;
        let notify = {
            let mut payload = BytesMut::new();
            Self::append_notify_payload(&mut payload, NOTIFY_TYPE_AUTHENTICATION_FAILED, &[]);
            payload.freeze()
        };
        let exchange_type = if matches!(
            self.sa.state,
            crate::IkeSaState::IkeAuthBootstrap
                | crate::IkeSaState::IkeAuthEapInProgress
                | crate::IkeSaState::ChildSaInstalling
        ) {
            EXCHANGE_TYPE_IKE_AUTH
        } else {
            EXCHANGE_TYPE_INFORMATIONAL
        };
        let packets = self.build_single_protected_payload_packets_for_exchange(
            exchange_type,
            message_id,
            PAYLOAD_TYPE_NOTIFY,
            notify.as_ref(),
        )?;
        self.sa.next_request_message_id = self.sa.next_request_message_id.saturating_add(1);
        self.send_packets(udp_conn, packets).await
    }

    pub(super) fn build_protected_message_packets(
        &self,
        exchange_type: u8,
        message_id: u32,
        first_payload: u8,
        plaintext: BytesMut,
    ) -> Result<Vec<Bytes>> {
        crate::debug_fmt::log_ike_plaintext(
            "send",
            exchange_type,
            message_id,
            first_payload,
            &plaintext,
        );
        let context = self.payload_context()?;
        let mut packets = Vec::new();
        if self.sa.peer.supports_fragmentation && plaintext.len() > IKE_FRAGMENT_PLAINTEXT_LIMIT {
            let total_fragments = plaintext.len().div_ceil(IKE_FRAGMENT_PLAINTEXT_LIMIT);
            anyhow::ensure!(total_fragments <= u16::MAX as usize, "too many IKE fragments");
            for (index, chunk) in plaintext.chunks(IKE_FRAGMENT_PLAINTEXT_LIMIT).enumerate() {
                let mut outer =
                    IkeMessageBuilder::new(BytesMut::from(bytemuck::bytes_of(&IkeHeader::new(
                        self.sa.initiator_spi,
                        self.sa.responder_spi,
                        exchange_type,
                        crate::payload::IkeFlags::INITIATOR,
                        message_id,
                    ))));
                let next_payload = if index == 0 { first_payload } else { PAYLOAD_TYPE_NONE };
                outer.push_encrypt(
                    next_payload,
                    Some(((index + 1) as u16, total_fragments as u16)),
                    &context,
                    false,
                    chunk.into(),
                )?;
                packets.push(Self::finalize_packet(outer)?);
            }
            return Ok(packets);
        }

        let mut outer =
            IkeMessageBuilder::new(BytesMut::from(bytemuck::bytes_of(&IkeHeader::new(
                self.sa.initiator_spi,
                self.sa.responder_spi,
                exchange_type,
                crate::payload::IkeFlags::INITIATOR,
                message_id,
            ))));
        outer.push_encrypt(first_payload, None, &context, false, plaintext)?;
        packets.push(Self::finalize_packet(outer)?);
        Ok(packets)
    }

    pub(super) fn payload_context(&self) -> Result<crate::Ikev2EapHandshake> {
        Ok(crate::Ikev2EapHandshake {
            ike_proposal: Some(self.selected_ike_proposal()?.clone()),
            ike_keys: self.sa.key_material.clone(),
            context: crate::Ikev2Context { is_initiator: true },
        })
    }

    pub(super) fn build_id_payload_typed(id_type: u8, id: &[u8]) -> Bytes {
        let mut payload = Vec::with_capacity(super::common::ID_PAYLOAD_FIXED_FIELDS_LEN + id.len());
        Self::append_id_payload_typed(&mut payload, id_type, id);
        Bytes::from(payload)
    }

    pub(super) fn append_id_payload_typed(payload: &mut impl BufMut, id_type: u8, id: &[u8]) {
        payload.put_slice(bytes_of(&IdPayloadHeader { id_type, reserved: [0; 3] }));
        payload.put_slice(id);
    }

    pub(super) fn expected_rightid(&self) -> Option<&str> {
        self.config.rightid.as_deref().filter(|value| !matches!(value.trim(), "%any" | "*"))
    }

    pub(super) fn configured_id_type_and_value(identity: &str) -> (u8, &str) {
        let value = identity.trim();
        if let Some(key_id) = value
            .strip_prefix("keyid:")
            .or_else(|| value.strip_prefix("@#"))
            .or_else(|| value.strip_prefix('#'))
        {
            return (ID_TYPE_KEY_ID, key_id);
        }
        if let Some(fqdn) = value
            .strip_prefix("fqdn:")
            .or_else(|| value.strip_prefix("dns:"))
            .or_else(|| value.strip_prefix('%'))
            .or_else(|| value.strip_prefix('@'))
        {
            return (ID_TYPE_FQDN, fqdn);
        }
        if let Some(rfc822) = value
            .strip_prefix("rfc822:")
            .or_else(|| value.strip_prefix("email:"))
            .or_else(|| value.strip_prefix("userfqdn:"))
            .or_else(|| value.strip_prefix("@@"))
        {
            return (ID_TYPE_RFC822_ADDR, rfc822);
        }
        if let Some(ipv4) = value.strip_prefix("ipv4:")
            && ipv4.parse::<std::net::Ipv4Addr>().is_ok()
        {
            return (ID_TYPE_IPV4_ADDR, ipv4);
        }
        if let Some(ipv6) = value.strip_prefix("ipv6:")
            && ipv6.parse::<std::net::Ipv6Addr>().is_ok()
        {
            return (ID_TYPE_IPV6_ADDR, ipv6);
        }
        if value.contains('@') {
            return (ID_TYPE_RFC822_ADDR, value);
        }
        if let Ok(ip) = value.parse::<std::net::IpAddr>() {
            return match ip {
                std::net::IpAddr::V4(_) => (ID_TYPE_IPV4_ADDR, value),
                std::net::IpAddr::V6(_) => (ID_TYPE_IPV6_ADDR, value),
            };
        }
        (ID_TYPE_FQDN, value)
    }

    pub(super) fn append_cp_requests(payload: &mut BytesMut) {
        payload.extend_from_slice(bytes_of(&ConfigPayloadHeader { cfg_type: 1, reserved: [0; 3] }));
        for attr_type in [
            CONFIG_ATTR_INTERNAL_IP4_ADDRESS,
            CONFIG_ATTR_INTERNAL_IP6_ADDRESS,
            CONFIG_ATTR_INTERNAL_IP4_DNS,
            CONFIG_ATTR_INTERNAL_IP6_DNS,
        ] {
            payload.extend_from_slice(bytes_of(&ConfigAttributeHeader {
                attr_type: attr_type.into(),
                value_length: 0.into(),
            }));
        }
    }

    pub(super) fn append_ts_any_dual_stack(payload: &mut BytesMut) {
        payload.extend_from_slice(bytes_of(&super::common::TrafficSelectorPayloadHeader {
            count: 2,
            reserved: [0; 3],
        }));
        payload.extend_from_slice(bytes_of(&super::common::TrafficSelectorHeader {
            ts_type: super::common::TRAFFIC_SELECTOR_TYPE_IPV4_ADDR_RANGE,
            ip_protocol_id: 0,
            selector_length: 16.into(),
            start_port: 0.into(),
            end_port: u16::MAX.into(),
        }));
        payload.extend_from_slice(&std::net::Ipv4Addr::UNSPECIFIED.octets());
        payload.extend_from_slice(&std::net::Ipv4Addr::new(255, 255, 255, 255).octets());
        payload.extend_from_slice(bytes_of(&super::common::TrafficSelectorHeader {
            ts_type: super::common::TRAFFIC_SELECTOR_TYPE_IPV6_ADDR_RANGE,
            ip_protocol_id: 0,
            selector_length: 40.into(),
            start_port: 0.into(),
            end_port: u16::MAX.into(),
        }));
        payload.extend_from_slice(&std::net::Ipv6Addr::UNSPECIFIED.octets());
        payload.extend_from_slice(&std::net::Ipv6Addr::from(u128::MAX).octets());
    }

    pub(super) fn append_tsr_strongswan_default(payload: &mut BytesMut) {
        payload.extend_from_slice(bytes_of(&super::common::TrafficSelectorPayloadHeader {
            count: 2,
            reserved: [0; 3],
        }));
        payload.extend_from_slice(bytes_of(&super::common::TrafficSelectorHeader {
            ts_type: super::common::TRAFFIC_SELECTOR_TYPE_IPV4_ADDR_RANGE,
            ip_protocol_id: 0,
            selector_length: 16.into(),
            start_port: 0.into(),
            end_port: u16::MAX.into(),
        }));
        payload.extend_from_slice(&std::net::Ipv4Addr::UNSPECIFIED.octets());
        payload.extend_from_slice(&std::net::Ipv4Addr::new(255, 255, 255, 255).octets());
        payload.extend_from_slice(bytes_of(&super::common::TrafficSelectorHeader {
            ts_type: super::common::TRAFFIC_SELECTOR_TYPE_IPV6_ADDR_RANGE,
            ip_protocol_id: 0,
            selector_length: 40.into(),
            start_port: 0.into(),
            end_port: u16::MAX.into(),
        }));
        payload.extend_from_slice(&std::net::Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0).octets());
        payload.extend_from_slice(
            &std::net::Ipv6Addr::new(
                0x3fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            )
            .octets(),
        );
    }

    pub(super) fn generate_child_spi() -> u32 {
        let mut bytes = [0u8; 4];
        rand_bytes(&mut bytes);
        u32::from_be_bytes(bytes).max(1)
    }
}
