//! IKEv2 payload parsing and message building helpers, including `SK`/`SKF`
//! unwrap and protected payload encoding.

use anyhow::{Context, Result, anyhow, ensure};
use bitflags::bitflags;
use bytemuck::{Pod, Zeroable, bytes_of, pod_read_unaligned};
use bytes::{Buf, Bytes, BytesMut};
use openssl::rand::rand_bytes;
use rend::{u16_be, u32_be};
use std::{
    mem::{offset_of, take},
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{Ikev2EapHandshake, InboundFragmentReassembly};

pub const IKEV2_VERSION: u8 = 0x20;
pub const IKE_HEADER_LEN: usize = 28;
pub const PAYLOAD_HEADER_LEN: usize = 4;

bitflags! {
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct IkeFlags: u8 {
        const INITIATOR = 0b0000_1000;
        const VERSION   = 0b0001_0000;
        const RESPONSE  = 0b0010_0000;
    }
}

const_variant! {
    PAYLOAD_TYPE_NAMES, u8, (&'static str, &'static str):
    (PAYLOAD_TYPE_NONE, 0u8, ("", "None")),
    (PAYLOAD_TYPE_SA, 33u8, ("SA", "Security Association")),
    (PAYLOAD_TYPE_KE, 34u8, ("KE", "Key Exchange")),
    (PAYLOAD_TYPE_IDI, 35u8, ("IDi", "Initiator Identification")),
    (PAYLOAD_TYPE_IDR, 36u8, ("IDr", "Responder Identification")),
    (PAYLOAD_TYPE_CERT, 37u8, ("CERT", "Certificate")),
    (PAYLOAD_TYPE_AUTH, 39u8, ("AUTH", "Authentication")),
    (PAYLOAD_TYPE_NONCE, 40u8, ("Ni", "Nonce")),
    (PAYLOAD_TYPE_NOTIFY, 41u8, ("N", "Notify")),
    (PAYLOAD_TYPE_DELETE, 42u8, ("D", "Delete")),
    (PAYLOAD_TYPE_TSI, 44u8, ("TSi", "Traffic Selector - Initiator")),
    (PAYLOAD_TYPE_TSR, 45u8, ("TSr", "Traffic Selector - Responder")),
    (PAYLOAD_TYPE_SK, 46u8, ("SK", "Encrypted and Authenticated")),
    (PAYLOAD_TYPE_CP, 47u8, ("CP", "Configuration")),
    (PAYLOAD_TYPE_EAP, 48u8, ("EAP", "Extensible Authentication")),
    (PAYLOAD_TYPE_SKF, 53u8, ("EF", "Encrypted Fragment")),
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct PayloadHeader {
    pub next_payload: u8,
    pub critical_reserved: u8,
    pub payload_length: u16_be,
}

impl PayloadHeader {
    pub fn new(next_payload: u8, is_critical: bool, payload_length: u16) -> Self {
        Self {
            next_payload,
            critical_reserved: if is_critical { 0x80 } else { 0x00 },
            payload_length: payload_length.into(),
        }
    }

    pub fn is_critical(&self) -> bool {
        (self.critical_reserved & 0x80) != 0
    }
}

pub enum PayloadParseResult {
    Done { header: IkeHeader, payloads: Vec<Payload> },
    NeedMore { header: IkeHeader },
}

pub struct Payload {
    pub payload_type: u8,
    pub next_payload: u8,
    pub critical: bool,
    pub body: Bytes,
}

pub struct PayloadParser {
    payloads: Vec<Payload>,
    reassembly: Option<InboundFragmentReassembly>,
    h: Arc<Ikev2EapHandshake>,
}

impl PayloadParser {
    pub fn new(
        context: Arc<Ikev2EapHandshake>,
        reassembly: Option<InboundFragmentReassembly>,
    ) -> Self {
        Self { h: context, payloads: Vec::new(), reassembly }
    }

    pub fn into_reassembly(self) -> Option<InboundFragmentReassembly> {
        self.reassembly
    }

    /// Parses one full IKE packet.
    ///
    /// This parses the outer payload chain first. If the last outer payload is
    /// `SK` or `SKF`, it is unwrapped exactly once and the contained plaintext
    /// payload chain is parsed next. `SKF` reassembly state is kept across calls.
    pub fn parse_packet(&mut self, packet: Bytes) -> Result<PayloadParseResult> {
        let (header, payloads) = Self::split_header(packet.clone())?;
        let parsed = self.parse_payloads(payloads, header.next_payload, header)?;
        let PayloadParseResult::Done { header, mut payloads } = parsed else { unreachable!() };
        let Some(last) = payloads.pop() else {
            return Ok(PayloadParseResult::Done { header, payloads });
        };

        match last.payload_type {
            PAYLOAD_TYPE_SK => {
                self.payloads = payloads;
                self.reassembly = None;
                self.handle_sk(last, packet, header)
            }
            PAYLOAD_TYPE_SKF => {
                if self.reassembly.is_none() {
                    self.payloads = payloads;
                } else {
                    ensure!(
                        payloads.is_empty(),
                        "unexpected plaintext payloads before continued SKF"
                    );
                }
                self.handle_skf(last, packet, header)
            }
            _ => {
                payloads.push(last);
                Ok(PayloadParseResult::Done { header, payloads })
            }
        }
    }

    pub fn split_header(packet: Bytes) -> Result<(IkeHeader, Bytes)> {
        ensure!(
            packet.len() >= IKE_HEADER_LEN,
            "IKE packet too short: expected at least {IKE_HEADER_LEN} bytes, got {}",
            packet.len()
        );

        let header = pod_read_unaligned::<IkeHeader>(&packet[..IKE_HEADER_LEN]);
        let declared_len = header.length.to_native() as usize;
        ensure!(
            declared_len >= IKE_HEADER_LEN && declared_len <= packet.len(),
            "invalid IKE packet length: declared {declared_len}, available {}",
            packet.len()
        );
        header.flags()?;
        Ok((header, packet.slice(IKE_HEADER_LEN..declared_len)))
    }

    fn parse_payloads(
        &mut self,
        mut buf: Bytes,
        mut next_payload: u8,
        header: IkeHeader,
    ) -> Result<PayloadParseResult> {
        let declared_len = buf.len();
        while next_payload != PAYLOAD_TYPE_NONE {
            let remaining = buf.remaining();
            ensure!(
                remaining >= PAYLOAD_HEADER_LEN,
                "payload type {next_payload} too short for header: {remaining} bytes",
            );

            let payload_header = pod_read_unaligned::<PayloadHeader>(&buf[..PAYLOAD_HEADER_LEN]);
            let payload_next = payload_header.next_payload;
            let critical = payload_header.is_critical();
            let payload_len = payload_header.payload_length.to_native() as usize;

            ensure!(
                payload_len >= PAYLOAD_HEADER_LEN && payload_len <= remaining,
                "payload type {next_payload} length out of bounds: declared {payload_len}, available {remaining}",
            );

            buf.advance(PAYLOAD_HEADER_LEN);
            let body_len = payload_len - PAYLOAD_HEADER_LEN;
            let body = buf.split_to(body_len);
            let payload_type = next_payload;

            self.payloads.push(Payload {
                payload_type,
                next_payload: payload_next,
                critical,
                body,
            });

            if matches!(payload_type, PAYLOAD_TYPE_SK | PAYLOAD_TYPE_SKF) {
                ensure!(
                    buf.remaining() == 0,
                    "{payload_type} payload must terminate the outer payload chain"
                );
                break;
            }

            next_payload = payload_next;
        }

        ensure!(
            buf.remaining() == 0,
            "invalid IKE packet length: declared {declared_len}, parsed {}",
            declared_len - buf.remaining()
        );

        Ok(PayloadParseResult::Done { header, payloads: take(&mut self.payloads) })
    }

    fn handle_sk(
        &mut self,
        payload: Payload,
        packet: Bytes,
        header: IkeHeader,
    ) -> Result<PayloadParseResult> {
        let plaintext = self.decrypt_protected_payload(payload.body, &packet)?;
        self.parse_payloads(plaintext, payload.next_payload, header)
    }

    fn handle_skf(
        &mut self,
        payload: Payload,
        packet: Bytes,
        ike_header: IkeHeader,
    ) -> Result<PayloadParseResult> {
        let now = Instant::now();
        if self.reassembly.as_ref().is_some_and(|reassembly| reassembly.expires_at <= now) {
            self.reassembly = None;
        }
        let mut buf = payload.body;
        ensure!(buf.remaining() >= SKF_HEADER_LEN);
        let header = pod_read_unaligned::<SkfHeader>(&buf[..SKF_HEADER_LEN]);
        let fragment_number = header.fragment_number.to_native() as usize;
        let total_fragments = header.total_fragments.to_native() as usize;
        let slot = fragment_number - 1;
        ensure!(fragment_number != 0 && total_fragments != 0 && fragment_number <= total_fragments);
        if fragment_number != 1 {
            ensure!(
                payload.next_payload == PAYLOAD_TYPE_NONE,
                "non-initial SKF fragment must not carry next-payload"
            );
        }

        buf.advance(SKF_HEADER_LEN);
        let plaintext = self.decrypt_protected_payload(buf, &packet)?;
        let message_id = ike_header.message_id.to_native();
        let reset_reassembly = self.reassembly.as_ref().is_some_and(|reassembly| {
            reassembly.exchange_type == ike_header.exchange_type
                && reassembly.message_id == message_id
                && total_fragments > reassembly.fragments.len()
        });
        if reset_reassembly {
            self.reassembly = None;
        }
        let reassembly = self.reassembly.get_or_insert_with(|| InboundFragmentReassembly {
            exchange_type: ike_header.exchange_type,
            message_id,
            first_inner_payload: None,
            fragments: std::iter::repeat_with(|| None).take(total_fragments).collect(),
            expires_at: now + SKF_REASSEMBLY_TIMEOUT,
        });
        ensure!(reassembly.exchange_type == ike_header.exchange_type, "SKF exchange mismatch");
        ensure!(reassembly.message_id == message_id, "SKF message-id mismatch");
        reassembly.expires_at = now + SKF_REASSEMBLY_TIMEOUT;
        if total_fragments < reassembly.fragments.len() {
            return Ok(PayloadParseResult::NeedMore { header: ike_header });
        }
        if fragment_number == 1 {
            if let Some(existing) = reassembly.first_inner_payload {
                ensure!(existing == payload.next_payload, "SKF first-fragment payload mismatch");
            } else {
                reassembly.first_inner_payload = Some(payload.next_payload);
            }
        }
        if reassembly.fragments[slot].is_none() {
            reassembly.fragments[slot] = Some(plaintext);
        }

        if reassembly.fragments.iter().any(Option::is_none) {
            return Ok(PayloadParseResult::NeedMore { header: ike_header });
        }

        let next_payload =
            reassembly.first_inner_payload.context("SKF reassembly missing first fragment")?;
        let total_len = reassembly.fragments.iter().flatten().map(Bytes::len).sum();
        let mut joined = BytesMut::with_capacity(total_len);
        for fragment in take(&mut reassembly.fragments) {
            joined.extend_from_slice(&fragment.unwrap());
        }
        self.reassembly = None;
        self.parse_payloads(joined.freeze(), next_payload, ike_header)
    }

    fn decrypt_protected_payload(&self, buf: Bytes, packet: &Bytes) -> Result<Bytes> {
        let proposal = self.h.ike_proposal.as_ref().context("SKF decode before proposal")?;
        let keys = self.h.ike_keys.as_ref().context("SKF decode before KE")?;
        let enc = proposal.encryption;
        let integ = proposal.integrity;
        let (sk_e, sk_a) = if self.h.context.is_initiator {
            (&keys.sk_er, &keys.sk_ar)
        } else {
            (&keys.sk_ei, &keys.sk_ai)
        };

        // verify ICV over the exact inbound wire image through Pad Length
        let icv_len = integ.output_len;
        let iv_len = enc.iv_len;
        ensure!(buf.len() >= iv_len + icv_len);
        let crypt_len = buf.len() - iv_len;
        let body_len = buf.len();
        ensure!(crypt_len >= icv_len && (crypt_len - icv_len).is_multiple_of(enc.block_len));
        // SAFETY: `buf` is expected to share the same allocation as the inbound packet.
        let body_offset = unsafe { buf.as_ptr().offset_from(packet.as_ptr()) } as usize;
        let packet_without_icv_len = body_offset + body_len - icv_len;
        ensure!(packet_without_icv_len <= packet.len());
        let mac = (integ.sign)(sk_a.as_ref(), &packet[..packet_without_icv_len])?;
        ensure!(mac.len() >= icv_len && mac[..icv_len] == buf[body_len - icv_len..]);

        // decrypt
        let (iv, rest) = buf.split_at(iv_len);
        let ciphertext = &rest[..rest.len() - icv_len];
        let plaintext = (enc.decrypt)(sk_e.as_ref(), iv, ciphertext)?;
        ensure!(!plaintext.is_empty(), "empty SKF fragment plaintext");
        let pad_len = plaintext[plaintext.len() - 1] as usize;
        ensure!(plaintext.len() > pad_len, "invalid SKF padding length");
        let inner_len = plaintext.len() - 1 - pad_len;

        let mut inner = Bytes::from(plaintext);
        inner.truncate(inner_len);
        Ok(inner)
    }
}

/// Two use case:
/// 1. build ike packet: new with 4B 00 || header; fill first_payload in header
///    afterwards
/// 2. build sk/skf payload: new with empty, encrypt and
pub struct IkeMessageBuilder {
    pub buffer: BytesMut,
    last_offset: usize,
    pub first_payload: u8,
}

impl IkeMessageBuilder {
    pub fn new(buffer: BytesMut) -> Self {
        Self { buffer, last_offset: usize::MAX, first_payload: PAYLOAD_TYPE_NONE }
    }

    /// Appends one ordinary outer payload.
    ///
    /// The closure writes only the payload body. This function fills the generic
    /// payload header, updates outer payload chaining, and appends the result to
    /// `self.buffer`.
    pub fn push_payload(
        &mut self,
        payload_type: u8,
        is_critical: bool,
        f: impl FnOnce(&mut BytesMut) -> Result<()>,
    ) -> Result<&mut Self> {
        let start = self.buffer.len();
        self.buffer.resize(start + PAYLOAD_HEADER_LEN, 0);
        if let Err(e) = f(&mut self.buffer) {
            self.buffer.truncate(start);
            return Err(e);
        }
        let payload_len = self.buffer.len() - start;
        let length = payload_len
            .try_into()
            .with_context(|| format!("payload too long ({payload_len})"))?;
        if self.last_offset == usize::MAX {
            self.first_payload = payload_type
        } else {
            self.buffer[self.last_offset] = payload_type;
        }
        self.last_offset = start + offset_of!(PayloadHeader, next_payload);
        self.buffer[start..start + PAYLOAD_HEADER_LEN]
            .copy_from_slice(bytes_of(&PayloadHeader::new(PAYLOAD_TYPE_NONE, is_critical, length)));
        Ok(self)
    }

    /// Appends a terminal `SK` or `SKF` payload into the final IKE packet buffer.
    ///
    /// Use this only when `self.buffer` already contains the full outer packet prefix
    /// (typically the IKE header and any cleartext outer payloads), because the ICV is
    /// computed over the whole packet up to the protected payload's Pad Length.
    ///
    /// The closure must write the plaintext payload bytes to protect. For `SKF`, that
    /// plaintext must already be the chosen fragment chunk; this function does not do
    /// fragmentation.
    ///
    /// `next_payload` is the inner payload type carried by the protected payload:
    /// for `SK`, it is the first inner payload type; for `SKF`, use the first inner
    /// payload type on fragment 1 and `PAYLOAD_TYPE_NONE` on non-first fragments.
    ///
    /// Set `skf_fragment` to `None` for `SK`, or `Some((fragment_number, total_fragments))`
    /// for `SKF`.
    pub fn push_encrypt(
        &mut self,
        next_payload: u8,
        skf_fragment: Option<(u16, u16)>,
        h: &Ikev2EapHandshake,
        is_critical: bool,
        mut plaintext: BytesMut,
    ) -> Result<&mut Self> {
        // check input
        let payload_type = if skf_fragment.is_some() { PAYLOAD_TYPE_SKF } else { PAYLOAD_TYPE_SK };
        ensure!(
            self.buffer.len() >= IKE_HEADER_LEN,
            "push_encrypt requires the final IKE packet buffer"
        );

        // load cipher setting
        let proposal = h.ike_proposal.as_ref().context("message encrypt")?;
        let keys = h.ike_keys.as_ref().context("message encrypt")?;
        let enc = proposal.encryption;
        let integ = proposal.integrity;
        let (sk_e, sk_a) = if h.context.is_initiator {
            (&keys.sk_ei, &keys.sk_ai)
        } else {
            (&keys.sk_er, &keys.sk_ar)
        };

        // plaintext
        let base = plaintext.len() + 1;
        let pad_len = (enc.block_len - (base % enc.block_len)) % enc.block_len;
        plaintext.extend((1..=pad_len).map(|v| v as u8));
        plaintext.extend_from_slice(&[pad_len as u8]);
        let padding_start = plaintext.len() - (pad_len + 1);
        crate::debug_fmt::log_ike_padding(
            "outbound ike padding",
            pad_len,
            &plaintext[padding_start..],
        );
        crate::debug_fmt::log_ike_bytes("outbound ike plaintext+padded", plaintext.as_ref());

        // encrypt
        let mut iv = vec![0_u8; enc.iv_len];
        rand_bytes(&mut iv).context("generate IKE IV")?;
        crate::debug_fmt::log_ike_bytes("outbound ike iv", iv.as_ref());
        let ciphertext = (enc.encrypt)(sk_e, &iv, &plaintext).context("encrypt payload")?;
        crate::debug_fmt::log_ike_bytes("outbound ike ciphertext", ciphertext.as_ref());

        let icv_len = integ.output_len;
        self.push_payload(payload_type, is_critical, |buf| {
            if let Some((fragment_number, total_fragments)) = skf_fragment {
                ensure!(
                    fragment_number != 0
                        && total_fragments != 0
                        && fragment_number <= total_fragments
                );
                let skf = SkfHeader {
                    fragment_number: fragment_number.into(),
                    total_fragments: total_fragments.into(),
                };
                buf.extend_from_slice(bytes_of(&skf));
            }
            buf.extend_from_slice(&iv);
            buf.extend_from_slice(&ciphertext);
            buf.resize(buf.len() + icv_len, 0);
            Ok(())
        })?;
        self.buffer[self.last_offset] = next_payload;

        // The ICV must cover the final outer IKE header bytes.
        self.buffer[16] = self.first_payload;
        let packet_len = self.buffer.len() as u32;
        self.buffer[24..28].copy_from_slice(&packet_len.to_be_bytes());

        // icv
        let icv_start = self.buffer.len() - icv_len;
        let packet_without_icv = &self.buffer[..icv_start];
        let mac = (integ.sign)(sk_a, packet_without_icv).context("compute ICV")?;
        ensure!(mac.len() >= icv_len, "integrity output too short");
        self.buffer[icv_start..].copy_from_slice(&mac[..icv_len]);
        crate::debug_fmt::log_ike_bytes("outbound ike icv", &self.buffer[icv_start..]);
        crate::debug_fmt::log_ike_bytes("outbound ike packet", self.buffer.as_ref());
        Ok(self)
    }
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(transparent)]
pub struct Spi([u8; 8]);

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct IkeHeader {
    pub initiator_spi: Spi,
    pub responder_spi: Spi,
    pub next_payload: u8,
    pub version: u8,
    pub exchange_type: u8,
    pub flags: u8,
    pub message_id: u32_be,
    pub length: u32_be,
}

impl IkeHeader {
    pub fn new(
        initiator_spi: u64,
        responder_spi: u64,
        exchange_type: u8,
        flags: IkeFlags,
        message_id: u32,
    ) -> Self {
        Self {
            initiator_spi: Spi(initiator_spi.to_be_bytes()),
            responder_spi: Spi(responder_spi.to_be_bytes()),
            next_payload: PAYLOAD_TYPE_NONE,
            version: IKEV2_VERSION,
            exchange_type,
            flags: flags.bits(),
            message_id: message_id.into(),
            length: (IKE_HEADER_LEN as u32).into(),
        }
    }

    pub fn flags(&self) -> Result<IkeFlags> {
        IkeFlags::from_bits(self.flags)
            .ok_or_else(|| anyhow!("invalid IKE flags: 0x{:02x}", self.flags))
    }
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
struct SkfHeader {
    fragment_number: u16_be,
    total_fragments: u16_be,
}
const SKF_HEADER_LEN: usize = 4;
const SKF_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(15);
