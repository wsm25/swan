use anyhow::{Context, Result, bail, ensure};
use bytemuck::bytes_of;
use bytes::Bytes;
use futures::{FutureExt, StreamExt, pin_mut};
use std::time::Duration;

use super::{Ikev2Routine, InboundResponseDisposition};
use crate::{
    UdpConn,
    consts::EXCHANGE_TYPE_IKE_SA_INIT,
    payload::{IkeFlags, IkeHeader, PAYLOAD_TYPE_NOTIFY, Payload, PayloadParser},
};

const INITIAL_RETRANSMIT_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_RETRANSMIT_ATTEMPTS: u8 = 5;

impl Ikev2Routine {
    pub(super) fn begin_request_exchange(&mut self) -> u32 {
        let message_id = self.sa.next_request_message_id;
        self.sa.expected_response_message_id = Some(message_id);
        self.sa.next_request_message_id = self.sa.next_request_message_id.saturating_add(1);
        message_id
    }

    pub(super) async fn run_protected_request(
        &mut self,
        udp_conn: &mut dyn UdpConn,
        step: &str,
        exchange_type: u8,
        packets: Vec<Bytes>,
    ) -> Result<(u32, Vec<Payload>)> {
        let message_id = self.begin_request_exchange();
        self.send_request_packets(udp_conn, message_id, packets).await?;
        let payloads = self
            .recv_response_protected(udp_conn, step, exchange_type, message_id)
            .await?;
        self.sa.expected_response_message_id = None;
        Ok((message_id, payloads))
    }

    pub(super) async fn recv_packet(
        &mut self,
        udp_conn: &mut dyn UdpConn,
        step: &str,
    ) -> Result<Bytes> {
        let mut timeout = INITIAL_RETRANSMIT_TIMEOUT;
        let mut retransmits = 0u8;
        loop {
            let next_packet = udp_conn.next().fuse();
            let delay = futures_timer::Delay::new(timeout).fuse();
            pin_mut!(next_packet, delay);
            match futures::future::select(next_packet, delay).await {
                futures::future::Either::Left((packet, _)) => {
                    let packet = packet.with_context(|| {
                        format!("udp connection closed while waiting for {step}")
                    })?;
                    let Some(packet) = self.decode_inbound_ike_packet(packet)? else {
                        continue;
                    };
                    match self.classify_inbound_response(packet.clone())? {
                        InboundResponseDisposition::Expected => return Ok(packet),
                        InboundResponseDisposition::DuplicateOrStale => continue,
                        InboundResponseDisposition::Ignore => continue,
                    }
                }
                futures::future::Either::Right((_, _)) => {
                    self.retransmit_current_request(
                        udp_conn,
                        step,
                        &mut timeout,
                        &mut retransmits,
                    )
                    .await?;
                }
            }
        }
    }

    pub(super) async fn recv_response_protected(
        &mut self,
        udp_conn: &mut dyn UdpConn,
        step: &str,
        exchange_type: u8,
        message_id: u32,
    ) -> Result<Vec<Payload>> {
        loop {
            let packet = self.recv_packet(udp_conn, step).await?;
            if let Some(payloads) = self.parse_response_protected(packet, exchange_type, message_id)? {
                return Ok(payloads);
            }
        }
    }

    pub(super) fn validate_expected_response_message_id(&self, message_id: u32) -> Result<()> {
        if let Some(expected) = self.sa.expected_response_message_id {
            ensure!(expected == message_id, "unexpected response wait state");
        }
        Ok(())
    }

    pub(super) fn validate_response_header(
        &mut self,
        header: IkeHeader,
        exchange_type: u8,
        message_id: u32,
    ) -> Result<()> {
        self.validate_response_envelope(header)?;
        ensure!(header.exchange_type == exchange_type, "unexpected exchange type");
        ensure!(header.message_id.to_native() == message_id, "unexpected message-id");
        let responder_spi = u64::from_be_bytes(bytes_of(&header.responder_spi).try_into().unwrap());
        if exchange_type == EXCHANGE_TYPE_IKE_SA_INIT {
            if responder_spi == 0 {
                ensure!(
                    header.next_payload == PAYLOAD_TYPE_NOTIFY,
                    "IKE_SA_INIT without responder SPI must start with NOTIFY"
                );
            }
            if responder_spi != 0 {
                self.sa.responder_spi = responder_spi;
            }
        } else {
            ensure!(responder_spi == self.sa.responder_spi, "responder SPI mismatch");
        }
        Ok(())
    }

    async fn retransmit_current_request(
        &mut self,
        udp_conn: &mut dyn UdpConn,
        step: &str,
        timeout: &mut Duration,
        retransmits: &mut u8,
    ) -> Result<()> {
        let request = self
            .sa
            .outbound_request
            .as_ref()
            .context("timed out without outbound request checkpoint")?;
        if let Some(expected) = self.sa.expected_response_message_id {
            ensure!(request.message_id == expected, "outbound request checkpoint mismatch");
        }
        ensure!(
            *retransmits < MAX_RETRANSMIT_ATTEMPTS,
            "timed out waiting for {step} after {} retransmits",
            MAX_RETRANSMIT_ATTEMPTS
        );
        self.sa.inbound_fragments = None;
        *retransmits = retransmits.saturating_add(1);
        self.send_packets(udp_conn, request.packets.clone()).await?;
        *timeout = timeout.saturating_mul(2);
        Ok(())
    }

    fn classify_inbound_response(&self, packet: Bytes) -> Result<InboundResponseDisposition> {
        let expected = self
            .sa
            .expected_response_message_id
            .context("missing expected response message-id while receiving packet")?;
        let (header, _) = PayloadParser::split_header(packet)
            .context("parse inbound IKE header while waiting")?;
        let initiator_spi = u64::from_be_bytes(bytes_of(&header.initiator_spi).try_into().unwrap());
        if initiator_spi != self.sa.initiator_spi {
            return Ok(InboundResponseDisposition::Ignore);
        }
        let responder_spi = u64::from_be_bytes(bytes_of(&header.responder_spi).try_into().unwrap());
        if self.sa.responder_spi != 0 && responder_spi != self.sa.responder_spi {
            return Ok(InboundResponseDisposition::Ignore);
        }
        self.validate_response_envelope(header)?;
        let message_id = header.message_id.to_native();
        if message_id == expected {
            return Ok(InboundResponseDisposition::Expected);
        }
        if message_id < expected
            && self.sa.last_completed_response_message_id.is_some_and(|last| message_id <= last)
        {
            return Ok(InboundResponseDisposition::DuplicateOrStale);
        }
        if message_id < expected {
            bail!("received stale response message-id {message_id} while waiting for {expected}");
        }
        bail!("received future response message-id {message_id} while waiting for {expected}");
    }

    fn validate_response_envelope(&self, header: IkeHeader) -> Result<()> {
        ensure!(header.version == 0x20, "unexpected IKE version: {}", header.version);
        let flags = header.flags()?;
        ensure!(flags.contains(IkeFlags::RESPONSE), "expected IKE response flag");
        ensure!(!flags.contains(IkeFlags::INITIATOR), "unexpected initiator flag in response");
        let initiator_spi = u64::from_be_bytes(bytes_of(&header.initiator_spi).try_into().unwrap());
        ensure!(initiator_spi == self.sa.initiator_spi, "initiator SPI mismatch");
        let responder_spi = u64::from_be_bytes(bytes_of(&header.responder_spi).try_into().unwrap());
        if self.sa.responder_spi != 0 {
            ensure!(responder_spi == self.sa.responder_spi, "responder SPI mismatch");
        }
        Ok(())
    }
}
