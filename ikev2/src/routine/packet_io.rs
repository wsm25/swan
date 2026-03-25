use anyhow::{Context, Result};
use bytemuck::pod_read_unaligned;
use bytes::{Bytes, BytesMut};

use super::{Ikev2Routine, InboundUdpPacket, OutboundUdpPacket};
use crate::{UdpConn, UdpPacket};

impl Ikev2Routine {
    pub(crate) fn process_inbound_udp_packet(
        &mut self,
        packet: UdpPacket,
    ) -> Result<InboundUdpPacket> {
        self.decode_inbound_udp_packet(packet)
    }

    pub(super) async fn send_packet(
        &mut self,
        udp_conn: &mut dyn UdpConn,
        packet: Bytes,
    ) -> Result<()> {
        crate::debug_fmt::log_ike("send", &packet);
        let dst =
            self.transport.as_ref().context("missing transport for outbound IKE packet")?.peer_addr;
        let packet = self.encode_outbound_udp_packet(OutboundUdpPacket::Ike { packet, dst })?;
        futures::SinkExt::send(udp_conn, packet).await.context("send udp packet")
    }

    pub(super) async fn send_packets(
        &mut self,
        udp_conn: &mut dyn UdpConn,
        packets: Vec<Bytes>,
    ) -> Result<()> {
        for packet in packets {
            self.send_packet(udp_conn, packet).await?;
        }
        Ok(())
    }

    pub(super) async fn send_request_packets(
        &mut self,
        udp_conn: &mut dyn UdpConn,
        message_id: u32,
        packets: Vec<Bytes>,
    ) -> Result<()> {
        self.sa.set_outbound_request(message_id, packets.clone());
        self.send_packets(udp_conn, packets).await
    }

    pub(crate) fn encode_outbound_udp_packet(
        &self,
        packet: OutboundUdpPacket,
    ) -> Result<UdpPacket> {
        let local_addr = self
            .transport
            .as_ref()
            .context("missing transport for outbound UDP packet")?
            .local_addr;
        if !self.transport.as_ref().is_some_and(|transport| transport.natt_active) {
            return match packet {
                OutboundUdpPacket::Ike { packet, dst } | OutboundUdpPacket::Esp { packet, dst } => {
                    Ok(UdpPacket { src: local_addr, dst, payload: packet })
                }
            };
        }
        match packet {
            OutboundUdpPacket::Ike { packet, dst } => {
                let mut out = BytesMut::with_capacity(4 + packet.len());
                out.extend_from_slice(&[0, 0, 0, 0]);
                out.extend_from_slice(&packet);
                Ok(UdpPacket { src: local_addr, dst, payload: out.freeze() })
            }
            OutboundUdpPacket::Esp { packet, dst } => {
                Ok(UdpPacket { src: local_addr, dst, payload: packet })
            }
        }
    }

    fn decode_inbound_udp_packet(&mut self, udp_packet: UdpPacket) -> Result<InboundUdpPacket> {
        let UdpPacket { src, dst, payload: packet } = udp_packet;
        self.update_transport_on_inbound(src, dst);
        if !self.transport.as_ref().is_some_and(|transport| transport.natt_active) {
            crate::debug_fmt::log_udp("recv", "udp packet classified as IKE");
            return Ok(InboundUdpPacket::Ike { packet });
        }
        if Self::is_natt_keepalive(&packet) {
            crate::debug_fmt::log_udp("recv", "udp packet classified as NAT-T keepalive");
            return Ok(InboundUdpPacket::NatKeepalive);
        }
        if Self::has_non_esp_marker(&packet) {
            crate::debug_fmt::log_udp("recv", "udp packet classified as IKE/non-ESP marker");
            return Ok(InboundUdpPacket::Ike { packet: packet.slice(4..) });
        }
        crate::debug_fmt::log_udp("recv", "udp packet classified as ESP");
        Ok(InboundUdpPacket::Esp { packet })
    }

    pub(super) fn decode_inbound_ike_packet(&mut self, packet: UdpPacket) -> Result<Option<Bytes>> {
        match self.decode_inbound_udp_packet(packet)? {
            InboundUdpPacket::Ike { packet } => {
                crate::debug_fmt::log_ike("recv", &packet);
                Ok(Some(packet))
            }
            InboundUdpPacket::Esp { .. } => {
                crate::debug_fmt::log_udp("recv", "ignoring ESP packet while waiting for IKE");
                Ok(None)
            }
            InboundUdpPacket::NatKeepalive => {
                crate::debug_fmt::log_udp("recv", "ignoring NAT-T keepalive while waiting for IKE");
                Ok(None)
            }
        }
    }

    fn has_non_esp_marker(packet: &Bytes) -> bool {
        packet.len() >= 4 && pod_read_unaligned::<rend::u32_be>(&packet[..4]).to_native() == 0
    }

    fn is_natt_keepalive(packet: &Bytes) -> bool {
        packet.len() == 1 && packet[0] == 0xff
    }
}
