use anyhow::{Result, ensure};
use bytemuck::{Pod, Zeroable, pod_read_unaligned};
use bytes::{Buf, Bytes, BytesMut};
use std::fmt::{self, Display, Formatter};

use crate::{
    ChildSaInstall, ChildSaKeyMaterial,
    config::CipherSuiteSelection,
    consts::{
        CP_ATTR_NAMES, EXCHANGE_TYPE_NAMES, ID_TYPE_NAMES, NOTIFY_TYPE_NAMES,
        TRANSFORM_TYPE_LAST, TRANSFORM_TYPE_MORE, TRANSFORM_TYPE_NAMES,
    },
    eap::{
        EAP_CODE_NAMES, EAP_TYPE_NAMES, EAP_TYPE_PEAP,
        peap::{PEAP_FLAG_LENGTH_INCLUDED, PEAP_FLAG_MORE_FRAGMENTS, PEAP_FLAG_START},
    },
    payload::{
        IkeFlags, IkeHeader, PAYLOAD_HEADER_LEN, PAYLOAD_TYPE_CP, PAYLOAD_TYPE_EAP,
        PAYLOAD_TYPE_IDI, PAYLOAD_TYPE_IDR, PAYLOAD_TYPE_NAMES, PAYLOAD_TYPE_NONE,
        PAYLOAD_TYPE_NOTIFY, PAYLOAD_TYPE_SA, PAYLOAD_TYPE_SK, PAYLOAD_TYPE_SKF, PAYLOAD_TYPE_TSI,
        PAYLOAD_TYPE_TSR, Payload, PayloadHeader, PayloadParser,
    },
    routine::common::{NotifyHeader, ProposalHeader, TrafficSelectorPayloadHeader},
};

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
struct TransformHeader {
    last_substructure: u8,
    reserved: u8,
    transform_length: rend::u16_be,
    transform_type: u8,
    transform_reserved: u8,
    transform_id: rend::u16_be,
}

struct FmtIkePacket<'a>(&'a Bytes);
struct FmtParsedIke<'a> {
    header: IkeHeader,
    payloads: &'a [Payload],
}
struct FmtPlaintextIke<'a> {
    exchange_type: u8,
    message_id: u32,
    first_payload: u8,
    plaintext: &'a BytesMut,
}
struct FmtPayload<'a>(&'a Payload);
struct FmtEapPacket<'a>(&'a Bytes);

pub(crate) fn ike_enabled() -> bool {
    env_enabled("SWAN_DEBUG_IKE")
}

pub(crate) fn eap_enabled() -> bool {
    env_enabled("SWAN_DEBUG_EAP")
}

pub(crate) fn log_udp(direction: &str, summary: &str) {
    if ike_enabled() {
        log::debug!("[IKE] {direction} {summary}");
    }
}

pub(crate) fn log_ike(direction: &str, packet: &Bytes) {
    if ike_enabled() {
        log::debug!("[IKE] {direction} {}", FmtIkePacket(packet));
    }
}

pub(crate) fn log_ike_parsed(direction: &str, header: IkeHeader, payloads: &[Payload]) {
    if ike_enabled() {
        log::debug!("[IKE] {direction} {}", FmtParsedIke { header, payloads });
    }
}

pub(crate) fn log_ike_plaintext(
    direction: &str,
    exchange_type: u8,
    message_id: u32,
    first_payload: u8,
    plaintext: &BytesMut,
) {
    if ike_enabled() {
        log::debug!(
            "[IKE] {direction} plaintext {}",
            FmtPlaintextIke { exchange_type, message_id, first_payload, plaintext }
        );
        log_byte_dump("IKE", direction, plaintext.as_ref());
    }
}

pub(crate) fn log_eap(direction: &str, packet: &Bytes) {
    if eap_enabled() {
        log::debug!("[EAP] {direction} {}", FmtEapPacket(packet));
        log_byte_dump("EAP", direction, packet.as_ref());
    }
}

pub(crate) fn log_auth_bytes(label: &str, bytes: &[u8]) {
    if ike_enabled() {
        log_byte_dump("IKE", label, bytes);
    }
}

pub(crate) fn log_ike_bytes(label: &str, bytes: &[u8]) {
    if ike_enabled() {
        log_byte_dump("IKE", label, bytes);
    }
}

pub(crate) fn log_ike_padding(label: &str, pad_len: usize, padding: &[u8]) {
    if ike_enabled() {
        log::debug!("[IKE] {label} pad_len={pad_len}");
        log_byte_dump("IKE", label, padding);
    }
}

pub(crate) fn log_child_sa_runtime(
    child_sa: &ChildSaInstall,
    keys: &ChildSaKeyMaterial,
    selection: &CipherSuiteSelection,
) {
    if ike_enabled() {
        log::debug!(
            "[IKE] run child-sa inbound_spi=0x{:08x} outbound_spi=0x{:08x} enc={} key_len={} iv_len={} block_len={} integ={} integ_key_len={} icv_len={} child_keys(ei={}, ai={}, er={}, ar={})",
            child_sa.inbound_spi,
            child_sa.outbound_spi,
            selection.encryption.name,
            selection.encryption.key_len,
            selection.encryption.iv_len,
            selection.encryption.block_len,
            selection.integrity.name,
            selection.integrity.key_len_hint,
            selection.integrity.output_len,
            keys.sk_ei.len(),
            keys.sk_ai.len(),
            keys.sk_er.len(),
            keys.sk_ar.len(),
        );
    }
}

fn env_enabled(key: &str) -> bool {
    std::env::var_os(key).is_some_and(|value| {
        value.to_str().is_some_and(|raw| {
            matches!(raw.trim(), "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON")
        })
    })
}

impl Display for FmtIkePacket<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match PayloadParser::split_header(self.0.clone()) {
            Ok((header, payload_bytes)) => match parse_payload_chain(payload_bytes, header.next_payload) {
                Ok(payloads) => fmt_header_and_payloads(header, payloads.as_slice(), f),
                Err(err) => {
                    fmt_header(header, f)?;
                    write!(
                        f,
                        " payload-parse-error={err} declared_len={} payload_bytes={}",
                        header.length.to_native(),
                        self.0.len().saturating_sub(crate::payload::IKE_HEADER_LEN)
                    )
                }
            },
            Err(err) => write!(f, "invalid-ike-packet len={} error={err}", self.0.len()),
        }
    }
}

impl Display for FmtParsedIke<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt_header_and_payloads(self.header, self.payloads, f)
    }
}

impl Display for FmtPlaintextIke<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} msgid={} [",
            name_u8_pair(&EXCHANGE_TYPE_NAMES, self.exchange_type),
            self.message_id
        )?;
        match parse_payload_chain(Bytes::copy_from_slice(self.plaintext.as_ref()), self.first_payload) {
            Ok(payloads) => fmt_payload_slice(payloads.as_slice(), f)?,
            Err(err) => write!(f, " payload-parse-error={err}")?,
        }
        write!(f, " ]")
    }
}

impl Display for FmtPayload<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt_payload(self.0, f)
    }
}

impl Display for FmtEapPacket<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt_eap_packet(self.0, f)
    }
}

fn log_byte_dump(tag: &str, label: &str, bytes: &[u8]) {
    log::debug!(
        "[{tag}] {label}: => {} bytes @ {:p}",
        bytes.len(),
        bytes.as_ptr()
    );
    for (offset, chunk) in bytes.chunks(16).enumerate() {
        log::debug!(
            "[{tag}] {:>4}: {}  {}",
            offset * 16,
            FmtHexdumpBytes(chunk),
            FmtHexdumpAscii(chunk),
        );
    }
}

struct FmtHexdumpBytes<'a>(&'a [u8]);
struct FmtHexdumpAscii<'a>(&'a [u8]);

impl Display for FmtHexdumpBytes<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if index != 0 {
                write!(f, " ")?;
            }
            write!(f, "{byte:02X}")?;
        }
        for index in self.0.len()..16 {
            if index != 0 {
                write!(f, " ")?;
            }
            write!(f, "  ")?;
        }
        Ok(())
    }
}

impl Display for FmtHexdumpAscii<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            let ch = if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '.'
            };
            write!(f, "{ch}")?;
        }
        Ok(())
    }
}

fn fmt_header_and_payloads(header: IkeHeader, payloads: &[Payload], f: &mut Formatter<'_>) -> fmt::Result {
    fmt_header(header, f)?;
    write!(f, " [")?;
    if !payloads.is_empty() {
        fmt_payload_slice(payloads, f)?;
    }
    write!(f, " ]")
}

fn fmt_payload_slice(payloads: &[Payload], f: &mut Formatter<'_>) -> fmt::Result {
    for (index, payload) in payloads.iter().enumerate() {
        if index != 0 {
            write!(f, " ")?;
        }
        write!(f, "{}", FmtPayload(payload))?;
    }
    Ok(())
}

fn fmt_header(header: IkeHeader, f: &mut Formatter<'_>) -> fmt::Result {
    let flags = match header.flags() {
        Ok(flags) => FmtFlags(Some(flags), header.flags),
        Err(_) => FmtFlags(None, header.flags),
    };
    write!(
        f,
        "{} msgid={} flags={} spi_i={:016x} spi_r={:016x}",
        name_u8_pair(&EXCHANGE_TYPE_NAMES, header.exchange_type),
        header.message_id.to_native(),
        flags,
        u64::from_be_bytes(bytemuck::bytes_of(&header.initiator_spi).try_into().unwrap()),
        u64::from_be_bytes(bytemuck::bytes_of(&header.responder_spi).try_into().unwrap()),
    )
}

struct FmtFlags(Option<IkeFlags>, u8);

impl Display for FmtFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Some(flags) = self.0 else {
            return write!(f, "0x{:02x}", self.1);
        };
        let mut first = true;
        for (present, name) in [
            (flags.contains(IkeFlags::INITIATOR), "I"),
            (flags.contains(IkeFlags::RESPONSE), "R"),
            (flags.contains(IkeFlags::VERSION), "V"),
        ] {
            if present {
                if !first {
                    write!(f, "|")?;
                }
                first = false;
                write!(f, "{name}")?;
            }
        }
        Ok(())
    }
}

fn fmt_payload(payload: &Payload, f: &mut Formatter<'_>) -> fmt::Result {
    match payload.payload_type {
        PAYLOAD_TYPE_NOTIFY => fmt_notify(payload.body.as_ref(), f),
        PAYLOAD_TYPE_EAP => {
            write!(f, "EAP/")?;
            fmt_eap_packet(&payload.body, f)
        }
        PAYLOAD_TYPE_IDI | PAYLOAD_TYPE_IDR => fmt_id(payload.payload_type, payload.body.as_ref(), f),
        PAYLOAD_TYPE_SA => fmt_sa(payload.body.as_ref(), f),
        PAYLOAD_TYPE_CP => fmt_cp(payload.body.as_ref(), f),
        PAYLOAD_TYPE_TSI | PAYLOAD_TYPE_TSR => fmt_ts(payload.payload_type, payload.body.as_ref(), f),
        PAYLOAD_TYPE_SKF => fmt_skf(payload.body.as_ref(), f),
        _ => write!(f, "{}", name_u8_pair(&PAYLOAD_TYPE_NAMES, payload.payload_type)),
    }
}

fn fmt_notify(body: &[u8], f: &mut Formatter<'_>) -> fmt::Result {
    if body.len() < std::mem::size_of::<NotifyHeader>() {
        return write!(f, "N(invalid)");
    }
    let header = pod_read_unaligned::<NotifyHeader>(&body[..std::mem::size_of::<NotifyHeader>()]);
    write!(f, "N({})", name_u16_pair(&NOTIFY_TYPE_NAMES, header.notify_type.to_native()))
}

fn fmt_id(payload_type: u8, body: &[u8], f: &mut Formatter<'_>) -> fmt::Result {
    if body.len() < 4 {
        return write!(f, "{}", name_u8_pair(&PAYLOAD_TYPE_NAMES, payload_type));
    }
    write!(
        f,
        "{}({})",
        name_u8_pair(&PAYLOAD_TYPE_NAMES, payload_type),
        name_u8_pair(&ID_TYPE_NAMES, body[0])
    )
}

fn fmt_sa(body: &[u8], f: &mut Formatter<'_>) -> fmt::Result {
    if body.len() < std::mem::size_of::<ProposalHeader>() {
        return write!(f, "SA");
    }
    write!(f, "SA(")?;
    let mut proposal_offset = 0usize;
    let mut proposal_index = 0usize;
    while proposal_offset + std::mem::size_of::<ProposalHeader>() <= body.len() {
        let header = pod_read_unaligned::<ProposalHeader>(
            &body[proposal_offset..proposal_offset + std::mem::size_of::<ProposalHeader>()],
        );
        let proposal_len = header.proposal_length.to_native() as usize;
        if proposal_index != 0 {
            write!(f, "; ")?;
        }
        if proposal_len < std::mem::size_of::<ProposalHeader>()
            || proposal_offset + proposal_len > body.len()
        {
            write!(
                f,
                "invalid-proposal(num={} len={} rem={})",
                header.proposal_num,
                proposal_len,
                body.len().saturating_sub(proposal_offset),
            )?;
            break;
        }
        let proposal = &body[proposal_offset..proposal_offset + proposal_len];
        fmt_proposal(proposal, f)?;
        proposal_index += 1;
        proposal_offset += proposal_len;
        if header.last_substructure == TRANSFORM_TYPE_LAST {
            break;
        }
    }
    write!(f, ")")
}

fn fmt_proposal(body: &[u8], f: &mut Formatter<'_>) -> fmt::Result {
    let header = pod_read_unaligned::<ProposalHeader>(&body[..std::mem::size_of::<ProposalHeader>()]);
    write!(
        f,
        "prop#{} proto={} spi_size={} xforms={}",
        header.proposal_num,
        header.protocol_id,
        header.spi_size,
        header.num_transforms
    )?;
    if header.spi_size != 0 {
        let spi_start = std::mem::size_of::<ProposalHeader>();
        let spi_end = spi_start + header.spi_size as usize;
        if spi_end <= body.len() {
            write!(f, " spi=")?;
            fmt_hex(&body[spi_start..spi_end], f)?;
        }
    }
    write!(f, "[")?;
    let mut transform_offset = std::mem::size_of::<ProposalHeader>() + header.spi_size as usize;
    let mut transform_index = 0usize;
    while transform_offset + std::mem::size_of::<TransformHeader>() <= body.len() {
        let header = pod_read_unaligned::<TransformHeader>(
            &body[transform_offset..transform_offset + std::mem::size_of::<TransformHeader>()],
        );
        let transform_len = header.transform_length.to_native() as usize;
        if transform_index != 0 {
            write!(f, ", ")?;
        }
        if transform_len < std::mem::size_of::<TransformHeader>()
            || transform_offset + transform_len > body.len()
        {
            write!(
                f,
                "invalid-xform(type={} len={} rem={})",
                header.transform_type,
                transform_len,
                body.len().saturating_sub(transform_offset),
            )?;
            break;
        }
        fmt_transform(&body[transform_offset..transform_offset + transform_len], f)?;
        transform_index += 1;
        transform_offset += transform_len;
        if header.last_substructure == TRANSFORM_TYPE_LAST {
            break;
        }
        if header.last_substructure != TRANSFORM_TYPE_MORE {
            write!(f, ", invalid-chain={}", header.last_substructure)?;
            break;
        }
    }
    write!(f, "]")
}

fn fmt_transform(body: &[u8], f: &mut Formatter<'_>) -> fmt::Result {
    let header = pod_read_unaligned::<TransformHeader>(&body[..std::mem::size_of::<TransformHeader>()]);
    write!(
        f,
        "{}={}",
        name_u8_pair(&TRANSFORM_TYPE_NAMES, header.transform_type),
        header.transform_id.to_native()
    )?;
    let attrs = &body[std::mem::size_of::<TransformHeader>()..];
    if !attrs.is_empty() {
        write!(f, "/")?;
        fmt_hex(attrs, f)?;
    }
    Ok(())
}

fn fmt_hex(bytes: &[u8], f: &mut Formatter<'_>) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

fn fmt_cp(body: &[u8], f: &mut Formatter<'_>) -> fmt::Result {
    if body.len() < 4 {
        return write!(f, "CP");
    }
    write!(f, "CP")?;
    let mut offset = 4usize;
    let mut wrote_any = false;
    let mut shown = 0usize;
    while offset + 4 <= body.len() && shown < 4 {
        let attr_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let attr_len = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
        if !wrote_any {
            write!(f, "(")?;
        } else {
            write!(f, ",")?;
        }
        wrote_any = true;
        shown += 1;
        write!(f, "{}", name_u16_pair(&CP_ATTR_NAMES, attr_type))?;
        offset = offset.saturating_add(4 + attr_len);
    }
    if wrote_any {
        write!(f, ")")?;
    }
    Ok(())
}

fn fmt_ts(payload_type: u8, body: &[u8], f: &mut Formatter<'_>) -> fmt::Result {
    if body.len() < std::mem::size_of::<TrafficSelectorPayloadHeader>() {
        return write!(f, "{}", name_u8_pair(&PAYLOAD_TYPE_NAMES, payload_type));
    }
    let header = pod_read_unaligned::<TrafficSelectorPayloadHeader>(
        &body[..std::mem::size_of::<TrafficSelectorPayloadHeader>()],
    );
    write!(f, "{}(count={})", name_u8_pair(&PAYLOAD_TYPE_NAMES, payload_type), header.count)
}

fn fmt_skf(body: &[u8], f: &mut Formatter<'_>) -> fmt::Result {
    if body.len() < 4 {
        return write!(f, "EF");
    }
    let fragment_number = u16::from_be_bytes([body[0], body[1]]);
    let total_fragments = u16::from_be_bytes([body[2], body[3]]);
    write!(f, "EF({fragment_number}/{total_fragments})")
}

fn parse_payload_chain(mut buf: Bytes, mut next_payload: u8) -> Result<Vec<Payload>> {
    let mut payloads = Vec::new();
    while next_payload != PAYLOAD_TYPE_NONE {
        ensure!(buf.remaining() >= PAYLOAD_HEADER_LEN, "payload too short");
        let payload_header = pod_read_unaligned::<PayloadHeader>(&buf[..PAYLOAD_HEADER_LEN]);
        let payload_len = payload_header.payload_length.to_native() as usize;
        ensure!(
            payload_len >= PAYLOAD_HEADER_LEN && payload_len <= buf.remaining(),
            "payload length out of bounds"
        );
        buf.advance(PAYLOAD_HEADER_LEN);
        let body = buf.split_to(payload_len - PAYLOAD_HEADER_LEN);
        let payload_type = next_payload;
        next_payload = payload_header.next_payload;
        payloads.push(Payload {
            payload_type,
            next_payload,
            critical: payload_header.is_critical(),
            body,
        });
        if matches!(payload_type, PAYLOAD_TYPE_SK | PAYLOAD_TYPE_SKF) {
            ensure!(buf.remaining() == 0, "{payload_type} payload must terminate the outer payload chain");
            break;
        }
    }
    Ok(payloads)
}

fn fmt_eap_packet(packet: &Bytes, f: &mut Formatter<'_>) -> fmt::Result {
    if packet.len() < 4 {
        return write!(f, "invalid len={}", packet.len());
    }
    let code = name_u8_pair(&EAP_CODE_NAMES, packet[0]);
    let identifier = packet[1];
    let declared_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if declared_len != packet.len() {
        return write!(f, "{code} id=0x{identifier:02x} len={} declared={declared_len}", packet.len());
    }
    if packet.len() == 4 {
        return write!(f, "{code} id=0x{identifier:02x}");
    }
    let ty = packet[4];
    if ty == EAP_TYPE_PEAP {
        return fmt_peap_packet(packet.as_ref(), f);
    }
    write!(f, "{code} id=0x{identifier:02x} type={}", name_u8_pair(&EAP_TYPE_NAMES, ty))
}

fn fmt_peap_packet(packet: &[u8], f: &mut Formatter<'_>) -> fmt::Result {
    if packet.len() < 6 {
        return write!(f, "UNKNOWN id=0x00 type=PEAP invalid");
    }
    let code = name_u8_pair(&EAP_CODE_NAMES, packet[0]);
    let identifier = packet[1];
    let flags = packet[5];
    write!(f, "{code} id=0x{identifier:02x} type=PEAP flags=")?;
    fmt_peap_flags(flags, f)?;
    let mut offset = 6usize;
    let tls_len = if (flags & PEAP_FLAG_LENGTH_INCLUDED) != 0 && packet.len() >= 10 {
        offset = 10;
        Some(u32::from_be_bytes([packet[6], packet[7], packet[8], packet[9]]))
    } else {
        None
    };
    write!(
        f,
        " ver={} tls_len={} data_len={}",
        flags & 0x07,
        tls_len.map_or_else(|| "-".to_string(), |v| v.to_string()),
        packet.len().saturating_sub(offset),
    )
}

fn fmt_peap_flags(flags: u8, f: &mut Formatter<'_>) -> fmt::Result {
    let mut first = true;
    for (present, name) in [
        ((flags & PEAP_FLAG_START) != 0, "START"),
        ((flags & PEAP_FLAG_MORE_FRAGMENTS) != 0, "MORE"),
        ((flags & PEAP_FLAG_LENGTH_INCLUDED) != 0, "LEN"),
    ] {
        if present {
            if !first {
                write!(f, "|")?;
            }
            first = false;
            write!(f, "{name}")?;
        }
    }
    if first {
        write!(f, "0")?;
    }
    Ok(())
}

fn name_u8_pair(map: &phf::Map<u8, (&'static str, &'static str)>, value: u8) -> &'static str {
    map.get(&value).map(|v| v.0).unwrap_or("UNKNOWN")
}

fn name_u16_pair(map: &phf::Map<u16, (&'static str, &'static str)>, value: u16) -> &'static str {
    map.get(&value).map(|v| v.0).unwrap_or("UNKNOWN")
}
