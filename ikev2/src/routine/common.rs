use bytes::Bytes;
use bytemuck::{Pod, Zeroable};
use openssl::hash::MessageDigest;
use openssl::pkey::Id;
use std::net::SocketAddr;

const_variant!(
    u8:
    PROTOCOL_ID_ESP = 3u8;
);

pub(super) const CERT_ENCODING_X509_SIGNATURE: u8 = 4;
pub(super) const ID_PAYLOAD_FIXED_FIELDS_LEN: usize = 4;
pub(super) const TRAFFIC_SELECTOR_TYPE_IPV4_ADDR_RANGE: u8 = 7;
pub(super) const TRAFFIC_SELECTOR_TYPE_IPV6_ADDR_RANGE: u8 = 8;

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub(super) struct KeHeader {
    pub dh_group: rend::u16_be,
    pub reserved: rend::u16_be,
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub(crate) struct NotifyHeader {
    pub protocol_id: u8,
    pub spi_size: u8,
    pub notify_type: rend::u16_be,
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub(crate) struct ProposalHeader {
    pub last_substructure: u8,
    pub reserved: u8,
    pub proposal_length: rend::u16_be,
    pub proposal_num: u8,
    pub protocol_id: u8,
    pub spi_size: u8,
    pub num_transforms: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub(super) struct TransformHeader {
    pub last_substructure: u8,
    pub reserved: u8,
    pub transform_length: rend::u16_be,
    pub transform_type: u8,
    pub transform_reserved: u8,
    pub transform_id: rend::u16_be,
}

pub(super) struct ParsedProposal {
    pub proposal_num: u8,
    pub spi: Option<u32>,
    pub encryption: Option<&'static crate::cipher::EncryptionAlg>,
    pub integrity: Option<&'static crate::cipher::IntegrityAlg>,
    pub prf: Option<&'static crate::cipher::PrfAlg>,
    pub dh: Option<&'static crate::cipher::DhAlg>,
    pub esn: Option<u16>,
}

pub(super) struct NotifyPayload<'a> {
    pub protocol_id: u8,
    pub spi: &'a [u8],
    pub notify_type: u16,
    pub data: &'a [u8],
}

pub(super) struct ParsedSignatureAuth<'a> {
    pub hash_algorithm: u16,
    pub digest: MessageDigest,
    pub public_key_type: Id,
    pub signature: &'a [u8],
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub(crate) struct TrafficSelectorPayloadHeader {
    pub count: u8,
    pub reserved: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub(super) struct TrafficSelectorHeader {
    pub ts_type: u8,
    pub ip_protocol_id: u8,
    pub selector_length: rend::u16_be,
    pub start_port: rend::u16_be,
    pub end_port: rend::u16_be,
}

pub(crate) enum InboundResponseDisposition {
    Expected,
    DuplicateOrStale,
    Ignore,
}

pub(crate) enum InboundControlOutcome {
    Continue,
    PeerShutdownRequested,
}

pub(crate) enum InboundUdpPacket {
    Ike { packet: Bytes },
    Esp { packet: Bytes },
    NatKeepalive,
}

pub(crate) enum OutboundUdpPacket {
    Ike { packet: Bytes, dst: SocketAddr },
    Esp { packet: Bytes, dst: SocketAddr },
}
