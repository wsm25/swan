use super::*;
use anyhow::ensure;
use bytes::BytesMut;
pub enum InboundEapPacket<'a> {
    Identity { identifier: u8 },
    Request { identifier: u8, eap_type: u8, payload: &'a [u8] },
    Success { identifier: u8 },
    Failure { identifier: u8 },
}

pub fn parse_eap<'a>(packet: &'a [u8]) -> Result<InboundEapPacket<'a>> {
    // header: code | id | len(2)
    ensure!(packet.len() >= 4, "eap packet too short");
    let identifier = packet[1];
    let length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    ensure!(length == packet.len(), "eap length mismatch");
    match packet[0] {
        EAP_CODE_REQUEST => {}
        EAP_CODE_SUCCESS => return Ok(InboundEapPacket::Success { identifier }),
        EAP_CODE_FAILURE => return Ok(InboundEapPacket::Failure { identifier }),
        other => bail!("unsupported outer eap code {other} for peap"),
    }
    ensure!(length >= 5, "eap request missing type");
    match packet[4] {
        EAP_TYPE_IDENTITY => Ok(InboundEapPacket::Identity { identifier }),
        _ => {
            Ok(InboundEapPacket::Request { identifier, eap_type: packet[4], payload: &packet[5..] })
        }
    }
}

pub fn build_eap_response(
    identifier: u8,
    eap_type: u8,
    length_hint: usize,
    f: impl FnOnce(&mut BytesMut) -> Result<()>,
) -> Result<Bytes> {
    let mut resp = BytesMut::with_capacity(length_hint + 5);
    resp.resize(5, 0);
    resp[0] = EAP_CODE_RESPONSE;
    resp[1] = identifier;
    resp[4] = eap_type;
    let mut body = resp.split_off(5);
    f(&mut body)?;
    resp.unsplit(body);
    let len: u16 = resp.len().try_into().context("eap payload too long")?;
    resp[2..4].copy_from_slice(&len.to_be_bytes());
    Ok(resp.freeze())
}

pub fn build_identity_response(identifier: u8, identity: &[u8]) -> Result<Bytes> {
    build_eap_response(identifier, EAP_TYPE_IDENTITY, identity.len(), |out| {
        out.extend_from_slice(identity);
        Ok(())
    })
}

pub fn build_nak_response(identifier: u8, eap_methods: &[u8]) -> Result<Bytes> {
    build_eap_response(identifier, EAP_TYPE_NAK, eap_methods.len(), |out| {
        out.extend_from_slice(eap_methods);
        Ok(())
    })
}
