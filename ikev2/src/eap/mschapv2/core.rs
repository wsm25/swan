use anyhow::{Context, Result, anyhow, ensure};
use bytes::{BufMut, Bytes};

use crate::cipher::{Sha1, des_encrypt_block, rand_bytes};
use crate::eap::mschapv2::md4;
use crate::eap::{EAP_TYPE_MSCHAPV2, build_eap_response};

const MAGIC1: &[u8] = b"Magic server to client signing constant";
const MAGIC2: &[u8] = b"Pad to make it do more than one iteration";
const MSK_MAGIC1: &[u8] = b"This is the MPPE Master Key";
const MSK_MAGIC2: &[u8] =
    b"On the client side, this is the send key; on the server side, it is the receive key.";
const MSK_MAGIC3: &[u8] =
    b"On the client side, this is the receive key; on the server side, it is the send key.";
const SHAPAD1: [u8; 40] = [0x00; 40];
const SHAPAD2: [u8; 40] = [0xF2; 40];
const AUTH_STRING_HEX_LEN: usize = 40;

pub(crate) const OPCODE_CHALLENGE: u8 = 1;
pub(crate) const OPCODE_RESPONSE: u8 = 2;
pub(crate) const OPCODE_SUCCESS: u8 = 3;
pub(crate) const OPCODE_FAILURE: u8 = 4;
pub(crate) const CHALLENGE_LEN: usize = 16;
const NT_RESPONSE_LEN: usize = 24;
const VALUE_SIZE: u8 = 49;

pub(crate) struct Mschapv2State {
    mschap_id: u8,
    pub expecting_success: bool,
    expected_auth_response: String,
    pub msk: Box<[u8]>,
}

pub(crate) enum Mschapv2Step {
    Outbound(Bytes),
    Failure(String),
}

pub(crate) fn on_request(
    state: &mut Option<Mschapv2State>,
    eap_identifier: u8,
    payload: &[u8],
    identity: &str,
    password: &str,
) -> Result<Mschapv2Step> {
    let parsed = parse(payload)?;
    match parsed.opcode {
        OPCODE_CHALLENGE => {
            if let Some(current) = state.as_ref() {
                ensure!(
                    !current.expecting_success,
                    "received unexpected mschapv2 challenge while waiting for success"
                );
            }
            ensure!(parsed.data.len() > CHALLENGE_LEN + 1, "mschapv2 challenge payload too short");
            let value_size = parsed.data[0] as usize;
            ensure!(
                value_size == CHALLENGE_LEN,
                "unsupported mschapv2 challenge size {}",
                value_size
            );
            let challenge = &parsed.data[1..1 + CHALLENGE_LEN];
            let mut auth_challenge = [0u8; CHALLENGE_LEN];
            auth_challenge.copy_from_slice(challenge);

            let mut peer_challenge = [0u8; CHALLENGE_LEN];
            rand_bytes(&mut peer_challenge);

            let username = extract_username(identity);
            let nt_response = generate_nt_response(
                &peer_challenge,
                &auth_challenge,
                username.as_bytes(),
                password,
            )?;
            let expected_auth_response = generate_authenticator_response(
                &peer_challenge,
                &auth_challenge,
                username.as_bytes(),
                password,
                &nt_response,
            )?;
            let msk = generate_msk(password, &nt_response)?;

            *state = Some(Mschapv2State {
                mschap_id: parsed.mschap_id,
                expecting_success: true,
                expected_auth_response,
                msk,
            });
            Ok(Mschapv2Step::Outbound(encode_response(
                eap_identifier,
                parsed.mschap_id,
                &peer_challenge,
                &nt_response,
                identity.as_bytes(),
            )?))
        }
        OPCODE_SUCCESS => {
            let current = state
                .as_ref()
                .ok_or_else(|| anyhow!("mschapv2 success without prior challenge"))?;
            ensure!(current.expecting_success, "unexpected mschapv2 success in current state");
            ensure!(
                current.mschap_id == parsed.mschap_id,
                "mschapv2 id mismatch: expected {}, got {}",
                current.mschap_id,
                parsed.mschap_id
            );
            verify_success(parsed.data.as_ref(), &current.expected_auth_response)?;
            *state = Some(Mschapv2State {
                mschap_id: parsed.mschap_id,
                expecting_success: false,
                expected_auth_response: current.expected_auth_response.clone(),
                msk: current.msk.clone(),
            });
            Ok(Mschapv2Step::Outbound(encode_success(eap_identifier)?))
        }
        OPCODE_FAILURE => {
            let current = state
                .as_ref()
                .ok_or_else(|| anyhow!("mschapv2 failure without prior challenge"))?;
            ensure!(current.expecting_success, "unexpected mschapv2 failure in current state");
            ensure!(
                current.mschap_id == parsed.mschap_id,
                "mschapv2 id mismatch: expected {}, got {}",
                current.mschap_id,
                parsed.mschap_id
            );
            parse_failure_tokens(parsed.data.as_ref())?;
            *state = Some(Mschapv2State {
                mschap_id: parsed.mschap_id,
                expecting_success: false,
                expected_auth_response: current.expected_auth_response.clone(),
                msk: current.msk.clone(),
            });
            Ok(Mschapv2Step::Failure("inner mschapv2 authentication failed".to_string()))
        }
        other => Ok(Mschapv2Step::Failure(format!("unsupported mschapv2 opcode {other}"))),
    }
}

struct ParsedMschapv2 {
    opcode: u8,
    mschap_id: u8,
    data: Bytes,
}

fn parse(payload: &[u8]) -> Result<ParsedMschapv2> {
    ensure!(payload.len() >= 4, "mschapv2 payload too short");
    let opcode = payload[0];
    let mschap_id = payload[1];
    let len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    ensure!(len >= 4, "invalid mschapv2 length");
    ensure!(len == payload.len(), "invalid mschapv2 length");
    Ok(ParsedMschapv2 { opcode, mschap_id, data: Bytes::copy_from_slice(&payload[4..]) })
}

fn extract_username(identity: &str) -> &str {
    identity.split_once('\\').map(|(_, user)| user).unwrap_or(identity)
}

fn encode_response(
    eap_identifier: u8,
    mschap_id: u8,
    peer_challenge: &[u8; CHALLENGE_LEN],
    nt_response: &[u8; NT_RESPONSE_LEN],
    identity: &[u8],
) -> Result<Bytes> {
    let length_hint = 4 + 1 + 16 + 8 + 24 + 1 + identity.len();
    build_eap_response(eap_identifier, EAP_TYPE_MSCHAPV2, length_hint, |body| {
        body.put_u8(OPCODE_RESPONSE);
        body.put_u8(mschap_id);
        body.extend_from_slice(&[0, 0]);
        body.put_u8(VALUE_SIZE);
        body.extend_from_slice(peer_challenge);
        body.extend_from_slice(&[0u8; 8]);
        body.extend_from_slice(nt_response);
        body.put_u8(0);
        body.extend_from_slice(identity);
        let len: u16 = body.len().try_into()?;
        body[2..4].copy_from_slice(&len.to_be_bytes());
        Ok(())
    })
}

fn encode_success(eap_identifier: u8) -> Result<Bytes> {
    build_eap_response(eap_identifier, EAP_TYPE_MSCHAPV2, 1, |b| {
        b.put_u8(OPCODE_SUCCESS);
        Ok(())
    })
}

fn parse_failure_tokens(payload: &[u8]) -> Result<()> {
    ensure!(payload.len() >= 3, "mschapv2 failure payload too short");
    let text = std::str::from_utf8(payload).context("mschapv2 failure payload is not utf8")?;
    let mut has_error_code = false;
    let mut has_retry_flag = false;
    let mut has_challenge = false;
    for token in text.split_whitespace() {
        let (key, value) =
            token.split_once('=').ok_or_else(|| anyhow!("mschapv2 failure has malformed token"))?;
        match key {
            "E" => {
                ensure!(!value.is_empty(), "mschapv2 failure has invalid E code");
                let _ = value.parse::<u32>().context("mschapv2 failure has invalid E code")?;
                has_error_code = true;
            }
            "R" => {
                ensure!(matches!(value, "0" | "1"), "mschapv2 failure has invalid R token");
                has_retry_flag = true;
            }
            "C" => {
                ensure!(
                    value.len() == CHALLENGE_LEN * 2,
                    "mschapv2 failure has invalid challenge length"
                );
                ensure!(
                    value.chars().all(|ch| ch.is_ascii_hexdigit()),
                    "mschapv2 failure has invalid challenge encoding"
                );
                has_challenge = true;
            }
            "V" => {
                ensure!(
                    !value.is_empty() && value.chars().all(|ch| ch.is_ascii_digit()),
                    "mschapv2 failure has invalid V token"
                );
            }
            "M" => ensure!(!value.is_empty(), "mschapv2 failure has invalid M token"),
            _ => anyhow::bail!("mschapv2 failure has unsupported token"),
        }
    }
    ensure!(has_error_code, "mschapv2 failure payload missing E token");
    ensure!(has_retry_flag, "mschapv2 failure payload missing R token");
    ensure!(has_challenge, "mschapv2 failure payload missing C token");
    Ok(())
}

fn utf16le(input: &str) -> Vec<u8> {
    input.encode_utf16().flat_map(|value| value.to_le_bytes()).collect()
}

fn odd_parity(byte: u8) -> u8 {
    let mut byte = byte & 0xFE;
    if byte.count_ones().is_multiple_of(2) {
        byte |= 1;
    }
    byte
}

fn expand_des_key(key7: &[u8; 7]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0] = key7[0] & 0xFE;
    out[1] = ((key7[0] << 7) | (key7[1] >> 1)) & 0xFE;
    out[2] = ((key7[1] << 6) | (key7[2] >> 2)) & 0xFE;
    out[3] = ((key7[2] << 5) | (key7[3] >> 3)) & 0xFE;
    out[4] = ((key7[3] << 4) | (key7[4] >> 4)) & 0xFE;
    out[5] = ((key7[4] << 3) | (key7[5] >> 5)) & 0xFE;
    out[6] = ((key7[5] << 2) | (key7[6] >> 6)) & 0xFE;
    out[7] = (key7[6] << 1) & 0xFE;
    for byte in &mut out {
        *byte = odd_parity(*byte);
    }
    out
}

fn challenge_hash(
    peer_challenge: &[u8; CHALLENGE_LEN],
    auth_challenge: &[u8; CHALLENGE_LEN],
    username: &[u8],
) -> Result<[u8; 8]> {
    let digest = Sha1::begin()
        .chain_update(peer_challenge)
        .chain_update(auth_challenge)
        .chain_update(username)
        .finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    Ok(out)
}

fn generate_nt_response(
    peer_challenge: &[u8; CHALLENGE_LEN],
    auth_challenge: &[u8; CHALLENGE_LEN],
    username: &[u8],
    password: &str,
) -> Result<[u8; NT_RESPONSE_LEN]> {
    let challenge = challenge_hash(peer_challenge, auth_challenge, username)?;
    let password_hash = md4(&utf16le(password));
    ensure!(password_hash.len() == 16, "invalid password hash length");
    let mut zpwd = [0u8; 21];
    zpwd[..16].copy_from_slice(&password_hash);

    let mut response = [0u8; NT_RESPONSE_LEN];
    for i in 0..3 {
        let mut key7 = [0u8; 7];
        key7.copy_from_slice(&zpwd[i * 7..(i + 1) * 7]);
        let key8 = expand_des_key(&key7);
        let block = des_encrypt_block(&key8, &challenge)?;
        response[i * 8..(i + 1) * 8].copy_from_slice(&block);
    }
    Ok(response)
}

fn generate_authenticator_response(
    peer_challenge: &[u8; CHALLENGE_LEN],
    auth_challenge: &[u8; CHALLENGE_LEN],
    username: &[u8],
    password: &str,
    nt_response: &[u8; NT_RESPONSE_LEN],
) -> Result<String> {
    let password_hash = md4(&utf16le(password));
    let password_hash_hash = md4(&password_hash);

    let first = Sha1::begin()
        .chain_update(password_hash_hash)
        .chain_update(nt_response)
        .chain_update(MAGIC1)
        .finalize();
    let challenge = challenge_hash(peer_challenge, auth_challenge, username)?;
    let second =
        Sha1::begin().chain_update(first).chain_update(challenge).chain_update(MAGIC2).finalize();
    Ok(hex::encode_upper(second))
}

fn generate_msk(password: &str, nt_response: &[u8; NT_RESPONSE_LEN]) -> Result<Box<[u8]>> {
    let password_hash = md4(&utf16le(password));
    let password_hash_hash = md4(&password_hash);

    let master_key = Sha1::begin()
        .chain_update(password_hash_hash)
        .chain_update(nt_response)
        .chain_update(MSK_MAGIC1)
        .finalize();
    let master = &master_key[..16];

    let recv = Sha1::begin()
        .chain_update(master)
        .chain_update(SHAPAD1)
        .chain_update(MSK_MAGIC2)
        .chain_update(SHAPAD2)
        .finalize();

    let send = Sha1::begin()
        .chain_update(master)
        .chain_update(SHAPAD1)
        .chain_update(MSK_MAGIC3)
        .chain_update(SHAPAD2)
        .finalize();

    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&recv[..16]);
    out.extend_from_slice(&send[..16]);
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&[0u8; 16]);
    Ok(out.into_boxed_slice())
}

fn verify_success(payload: &[u8], expected_auth_response: &str) -> Result<()> {
    ensure!(payload.len() >= 2 + AUTH_STRING_HEX_LEN, "mschapv2 success payload too short");
    let text = std::str::from_utf8(payload).context("mschapv2 success payload is not utf8")?;
    let sig = text
        .split_whitespace()
        .find_map(|token| token.strip_prefix("S="))
        .ok_or_else(|| anyhow!("mschapv2 success missing authenticator response"))?;
    ensure!(sig.len() == AUTH_STRING_HEX_LEN, "mschapv2 success invalid auth string length");
    ensure!(
        sig.chars().all(|ch| ch.is_ascii_hexdigit()),
        "mschapv2 success invalid auth string encoding"
    );
    ensure!(
        sig.eq_ignore_ascii_case(expected_auth_response),
        "mschapv2 success authenticator response mismatch"
    );
    Ok(())
}
