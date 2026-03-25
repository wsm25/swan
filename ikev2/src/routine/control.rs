use anyhow::{Context, Result, bail, ensure};
use bytes::{Bytes, BytesMut};

use super::{
    Ikev2Routine, InboundControlOutcome, common::PROTOCOL_ID_ESP, delete_exchange::DeletePayload,
};
use crate::{
    IkeSaState, UdpConn,
    payload::{IkeFlags, PAYLOAD_TYPE_DELETE, Payload, PayloadParseResult, PayloadParser},
};

const MAX_INBOUND_REQUEST_HISTORY: usize = 4;
impl Ikev2Routine {
    pub(crate) async fn handle_running_control_packet(
        &mut self,
        udp_conn: &mut dyn UdpConn,
        packet: Bytes,
    ) -> Result<InboundControlOutcome> {
        let (header, _) = PayloadParser::split_header(packet.clone())
            .context("parse inbound IKE control header")?;
        let flags = header.flags()?;
        ensure!(
            header.exchange_type == crate::consts::EXCHANGE_TYPE_INFORMATIONAL,
            "unexpected running-state IKE exchange"
        );
        if flags.contains(IkeFlags::RESPONSE) {
            return self.handle_inbound_control_response(packet);
        }
        self.handle_inbound_control_packet(udp_conn, packet).await
    }

    pub(crate) async fn handle_inbound_control_packet(
        &mut self,
        udp_conn: &mut dyn UdpConn,
        packet: Bytes,
    ) -> Result<InboundControlOutcome> {
        let (request_message_id, payloads) = self.parse_inbound_control_request(packet)?;
        if let Some(cached_response) = self.find_inbound_request_response(request_message_id) {
            self.send_packets(udp_conn, cached_response.response_packets.clone()).await?;
            return Ok(InboundControlOutcome::Continue);
        }
        self.validate_new_inbound_request_message_id(request_message_id)?;
        let outcome = self.process_informational_request_payloads(payloads)?;
        let packets = self.build_informational_empty_response(request_message_id)?;
        self.send_packets(udp_conn, packets.clone()).await?;
        self.remember_inbound_request_response(request_message_id, packets);
        if matches!(outcome, InboundControlOutcome::PeerShutdownRequested) {
            self.cleanup_session();
        }
        Ok(outcome)
    }

    pub(crate) async fn send_empty_informational_request(
        &mut self,
        udp_conn: &mut dyn UdpConn,
    ) -> Result<u32> {
        let message_id = self.begin_request_exchange();
        let packets = self.build_informational_empty_response(message_id)?;
        self.send_request_packets(udp_conn, message_id, packets).await?;
        Ok(message_id)
    }

    fn parse_inbound_control_request(&self, packet: Bytes) -> Result<(u32, Vec<Payload>)> {
        let mut parser = PayloadParser::new(std::sync::Arc::new(self.payload_context()?), None);
        let parsed = parser.parse_packet(packet)?;
        let PayloadParseResult::Done { header, payloads } = parsed else {
            bail!("unexpected fragmented inbound IKE control packet");
        };
        crate::debug_fmt::log_ike_parsed("recv parsed", header, payloads.as_slice());
        ensure!(
            header.exchange_type == crate::consts::EXCHANGE_TYPE_INFORMATIONAL,
            "unexpected inbound IKE control exchange"
        );
        ensure!(header.version == 0x20, "unexpected IKE version: {}", header.version);
        let flags = header.flags()?;
        ensure!(
            !flags.contains(IkeFlags::RESPONSE),
            "inbound informational packet must be a request"
        );
        let request_message_id = header.message_id.to_native();
        ensure!(request_message_id > 0, "inbound IKE informational request missing message-id");
        Ok((request_message_id, payloads))
    }

    fn find_inbound_request_response(
        &self,
        request_message_id: u32,
    ) -> Option<&crate::InboundRequestResponse> {
        self.sa
            .inbound_request_history
            .iter()
            .find(|response| response.message_id == request_message_id)
    }

    fn validate_new_inbound_request_message_id(&self, request_message_id: u32) -> Result<()> {
        if let Some(latest) = self.sa.inbound_request_history.back() {
            ensure!(
                request_message_id > latest.message_id,
                "stale inbound IKE informational request message-id {} after {}",
                request_message_id,
                latest.message_id
            );
        }
        Ok(())
    }

    fn process_informational_request_payloads(
        &mut self,
        payloads: Vec<Payload>,
    ) -> Result<InboundControlOutcome> {
        if payloads.is_empty() {
            crate::debug_fmt::log_udp("recv", "empty informational request accepted");
            return Ok(InboundControlOutcome::Continue);
        }
        self.handle_delete_request(self.extract_single_delete_payload(payloads)?)
    }

    fn extract_single_delete_payload(&self, payloads: Vec<Payload>) -> Result<DeletePayload> {
        let mut delete_payloads = Vec::new();
        for payload in payloads {
            match payload.payload_type {
                PAYLOAD_TYPE_DELETE => delete_payloads.push(payload.body),
                _ => bail!("unexpected payload in inbound IKE control packet"),
            }
        }
        ensure!(!delete_payloads.is_empty(), "inbound IKE control packet missing DELETE payload");
        ensure!(
            delete_payloads.len() == 1,
            "inbound IKE control packet has multiple DELETE payloads"
        );
        Self::decode_delete_payload(delete_payloads.pop().unwrap().as_ref())
    }

    fn handle_delete_request(&mut self, delete: DeletePayload) -> Result<InboundControlOutcome> {
        match delete.protocol_id {
            crate::consts::DELETE_PROTOCOL_ID_IKE => {
                ensure!(delete.spis.is_empty(), "IKE delete must not carry SPI values");
                self.sa.state = IkeSaState::Stopped;
                Ok(InboundControlOutcome::PeerShutdownRequested)
            }
            PROTOCOL_ID_ESP => {
                let child_spi = self
                    .sa
                    .active_child_sa
                    .as_ref()
                    .map(|child| child.install.outbound_spi)
                    .context("received CHILD_SA delete without active child SA")?;
                ensure!(delete.spis.len() == 1, "CHILD_SA delete must carry one SPI");
                ensure!(delete.spis[0] == child_spi, "unexpected CHILD_SA delete SPI");
                self.sa.active_child_sa = None;
                Ok(InboundControlOutcome::Continue)
            }
            other => bail!("unsupported DELETE protocol {other}"),
        }
    }

    fn build_informational_empty_response(&self, request_message_id: u32) -> Result<Vec<Bytes>> {
        self.build_protected_message_packets(
            crate::consts::EXCHANGE_TYPE_INFORMATIONAL,
            request_message_id,
            crate::payload::PAYLOAD_TYPE_NONE,
            BytesMut::new(),
        )
    }

    fn remember_inbound_request_response(
        &mut self,
        request_message_id: u32,
        response_packets: Vec<Bytes>,
    ) {
        if self.sa.inbound_request_history.len() == MAX_INBOUND_REQUEST_HISTORY {
            self.sa.inbound_request_history.pop_front();
        }
        self.sa.inbound_request_history.push_back(crate::InboundRequestResponse {
            message_id: request_message_id,
            response_packets,
        });
    }

    fn handle_inbound_control_response(&mut self, packet: Bytes) -> Result<InboundControlOutcome> {
        let expected = self
            .sa
            .expected_response_message_id
            .context("unexpected informational response without outstanding request")?;
        match self.parse_response_protected(
            packet,
            crate::consts::EXCHANGE_TYPE_INFORMATIONAL,
            expected,
        )? {
            Some(_payloads) => Ok(InboundControlOutcome::Continue),
            None => Ok(InboundControlOutcome::Continue),
        }
    }
}
