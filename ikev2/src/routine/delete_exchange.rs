use anyhow::{Context, Result, bail, ensure};
use bytemuck::{Pod, Zeroable, pod_read_unaligned};
use bytes::Bytes;

use super::{CloseOutcome, Ikev2Routine};
use crate::{
    IkeSaState, UdpConn,
    consts::{DELETE_PROTOCOL_ID_ESP, DELETE_PROTOCOL_ID_IKE},
};

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
struct DeleteHeader {
    protocol_id: u8,
    spi_size: u8,
    num_spis: rend::u16_be,
}

pub(super) struct DeletePayload {
    pub protocol_id: u8,
    pub spis: Box<[u32]>,
}

impl Ikev2Routine {
    pub(crate) async fn close(&mut self, udp_conn: &mut dyn UdpConn) -> Result<CloseOutcome> {
        if self.sa.responder_spi == 0 || matches!(self.sa.state, IkeSaState::Stopped) {
            return Ok(CloseOutcome::AlreadyClosed);
        }

        if let Some(child_sa) = self.sa.active_child_sa.as_ref() {
            self.run_delete_exchange(
                udp_conn,
                "CHILD_SA delete",
                self.build_delete_child_sa_request(
                    self.sa.next_request_message_id,
                    child_sa.install.outbound_spi,
                )?,
            )
            .await?;
        }

        self.run_delete_exchange(
            udp_conn,
            "IKE_SA delete",
            self.build_delete_ike_sa_request(self.sa.next_request_message_id)?,
        )
        .await?;
        self.cleanup_session();
        Ok(CloseOutcome::Closed)
    }

    pub(crate) fn build_delete_child_sa_request(
        &self,
        message_id: u32,
        child_spi: u32,
    ) -> Result<Vec<Bytes>> {
        let delete = Self::encode_delete_payload(DELETE_PROTOCOL_ID_ESP, &[child_spi]);
        self.build_single_protected_payload_packets_for_exchange(
            crate::consts::EXCHANGE_TYPE_INFORMATIONAL,
            message_id,
            crate::payload::PAYLOAD_TYPE_DELETE,
            delete.as_ref(),
        )
    }

    pub(crate) fn build_delete_ike_sa_request(&self, message_id: u32) -> Result<Vec<Bytes>> {
        let delete = Self::encode_delete_payload(DELETE_PROTOCOL_ID_IKE, &[]);
        self.build_single_protected_payload_packets_for_exchange(
            crate::consts::EXCHANGE_TYPE_INFORMATIONAL,
            message_id,
            crate::payload::PAYLOAD_TYPE_DELETE,
            delete.as_ref(),
        )
    }

    pub(crate) fn process_delete_response(
        &mut self,
        packet: Bytes,
        exchange_type: u8,
        message_id: u32,
    ) -> Result<()> {
        let _ = self
            .parse_response_protected(packet, exchange_type, message_id)?
            .context("delete response missing protected payloads")?;
        Ok(())
    }

    pub(super) fn decode_delete_payload(payload: &[u8]) -> Result<DeletePayload> {
        ensure!(payload.len() >= std::mem::size_of::<DeleteHeader>(), "invalid DELETE payload");
        let header =
            pod_read_unaligned::<DeleteHeader>(&payload[..std::mem::size_of::<DeleteHeader>()]);
        let protocol_id = header.protocol_id;
        let spi_size = header.spi_size;
        let spi_count = header.num_spis.to_native() as usize;
        match protocol_id {
            DELETE_PROTOCOL_ID_IKE => {
                ensure!(spi_size == 0, "IKE delete must not carry SPI values");
                ensure!(spi_count == 0, "IKE delete must not carry SPI count");
            }
            DELETE_PROTOCOL_ID_ESP => {
                ensure!(spi_size == 4, "ESP delete must carry 4-byte SPIs");
                ensure!(spi_count > 0, "ESP delete must carry at least one SPI");
            }
            other => bail!("unsupported DELETE protocol {other}"),
        }
        let spi_len = spi_size as usize;
        let expected_len = std::mem::size_of::<DeleteHeader>() + spi_count * spi_len;
        ensure!(payload.len() == expected_len, "invalid DELETE payload length");

        let mut spis = Vec::with_capacity(spi_count);
        for chunk in payload[std::mem::size_of::<DeleteHeader>()..].chunks_exact(4) {
            spis.push(bytemuck::pod_read_unaligned::<rend::u32_be>(chunk).to_native());
        }

        Ok(DeletePayload { protocol_id, spis: spis.into_boxed_slice() })
    }

    async fn run_delete_exchange(
        &mut self,
        udp_conn: &mut dyn UdpConn,
        step: &str,
        packets: Vec<Bytes>,
    ) -> Result<()> {
        let message_id = self.sa.next_request_message_id;
        self.begin_request_exchange();
        self.send_request_packets(udp_conn, message_id, packets).await?;
        let packet = self.recv_packet(udp_conn, step).await?;
        self.process_delete_response(
            packet,
            crate::consts::EXCHANGE_TYPE_INFORMATIONAL,
            message_id,
        )?;
        self.sa.expected_response_message_id = None;
        Ok(())
    }
}
