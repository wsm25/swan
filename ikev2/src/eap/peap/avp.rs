use anyhow::{Context, Result, anyhow, bail, ensure};
use bytes::Bytes;

use super::super::{
    EAP_CODE_FAILURE, EAP_CODE_REQUEST, EAP_CODE_RESPONSE, EAP_CODE_SUCCESS, EAP_TYPE_IDENTITY,
};

const EAP_TYPE_MSTLV: u8 = 33;
const MS_AVP_SUCCESS: [u8; 6] = [0x80, 0x03, 0x00, 0x02, 0x00, 0x01];
const MS_AVP_FAILURE: [u8; 6] = [0x80, 0x03, 0x00, 0x02, 0x00, 0x02];

pub(crate) fn decode_peer_request(tls_data: &[u8], identifier: u8) -> Result<Bytes> {
    let len = tls_data.len();
    if len > 4 {
        let code = tls_data[0];
        let packet_len = u16::from_be_bytes([tls_data[2], tls_data[3]]) as usize;
        if code == EAP_CODE_REQUEST && packet_len == len {
            if len == 5 && tls_data[4] == EAP_TYPE_IDENTITY {
                return Ok(Bytes::copy_from_slice(tls_data));
            }
            if len == 11 && tls_data[4] == EAP_TYPE_MSTLV {
                if tls_data[5..] == MS_AVP_SUCCESS {
                    return Ok(Bytes::from(vec![EAP_CODE_SUCCESS, tls_data[1], 0, 4]));
                }
                if tls_data[5..] == MS_AVP_FAILURE {
                    return Ok(Bytes::from(vec![EAP_CODE_FAILURE, tls_data[1], 0, 4]));
                }
                bail!("unknown ms-avp message");
            }
            return Ok(Bytes::copy_from_slice(tls_data));
        }
    }

    let total_len =
        4usize.checked_add(len).ok_or_else(|| anyhow!("inner eap packet length overflow"))?;
    let total_len = u16::try_from(total_len).context("inner eap packet too large")?;
    let mut out = Vec::with_capacity(total_len as usize);
    out.push(EAP_CODE_REQUEST);
    out.push(identifier);
    out.extend_from_slice(&total_len.to_be_bytes());
    out.extend_from_slice(tls_data);
    Ok(Bytes::from(out))
}

pub(crate) fn encode_peer_response(inner_eap: &[u8]) -> Result<Bytes> {
    ensure!(inner_eap.len() >= 4, "inner eap packet too short");
    let code = inner_eap[0];
    let identifier = inner_eap[1];
    let len = u16::from_be_bytes([inner_eap[2], inner_eap[3]]) as usize;
    ensure!(len == inner_eap.len(), "inner eap length mismatch");

    if code == EAP_CODE_SUCCESS || code == EAP_CODE_FAILURE {
        let avp_data =
            if code == EAP_CODE_SUCCESS { &MS_AVP_SUCCESS[..] } else { &MS_AVP_FAILURE[..] };
        let mut out = Vec::with_capacity(11);
        out.push(EAP_CODE_RESPONSE);
        out.push(identifier);
        out.extend_from_slice(&(11u16).to_be_bytes());
        out.push(EAP_TYPE_MSTLV);
        out.extend_from_slice(avp_data);
        return Ok(Bytes::from(out));
    }

    ensure!(len >= 5, "inner eap packet missing type");
    Ok(Bytes::copy_from_slice(&inner_eap[4..]))
}
