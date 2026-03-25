use anyhow::{Context, Result, anyhow, ensure};
use bytes::Bytes;
use openssl::hash::{MessageDigest, hash};
use openssl::provider::Provider;
use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, Crypter, Mode};
use std::sync::OnceLock;

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
    expecting_success: bool,
    expected_auth_response: String,
    msk: Box<[u8]>,
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
            rand_bytes(&mut peer_challenge).context("generate mschapv2 peer challenge")?;

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
            )))
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
            Ok(Mschapv2Step::Outbound(encode_success(eap_identifier)))
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

pub(crate) fn msk(state: &Option<Mschapv2State>) -> Option<Box<[u8]>> {
    state.as_ref().map(|value| value.msk.clone())
}

pub(crate) fn expecting_success(state: &Option<Mschapv2State>) -> bool {
    state.as_ref().is_some_and(|value| value.expecting_success)
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
) -> Bytes {
    let mut body = Vec::with_capacity(4 + 1 + 16 + 8 + 24 + 1 + identity.len());
    body.push(OPCODE_RESPONSE);
    body.push(mschap_id);
    body.extend_from_slice(&[0, 0]);
    body.push(VALUE_SIZE);
    body.extend_from_slice(peer_challenge);
    body.extend_from_slice(&[0u8; 8]);
    body.extend_from_slice(nt_response);
    body.push(0);
    body.extend_from_slice(identity);
    let len = body.len() as u16;
    body[2..4].copy_from_slice(&len.to_be_bytes());

    let total_len = 5 + body.len();
    let mut out = Vec::with_capacity(total_len);
    out.push(2);
    out.push(eap_identifier);
    out.extend_from_slice(&(total_len as u16).to_be_bytes());
    out.push(26);
    out.extend_from_slice(&body);
    Bytes::from(out)
}

fn encode_success(eap_identifier: u8) -> Bytes {
    let mut out = Vec::with_capacity(6);
    out.push(2);
    out.push(eap_identifier);
    out.extend_from_slice(&(6u16).to_be_bytes());
    out.push(26);
    out.push(OPCODE_SUCCESS);
    Bytes::from(out)
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

fn ensure_legacy_provider_loaded() {
    static LEGACY_PROVIDER: OnceLock<Option<Provider>> = OnceLock::new();
    let _ = LEGACY_PROVIDER.get_or_init(|| Provider::try_load(None, "legacy", true).ok());
}

fn md4(input: &[u8]) -> Result<Vec<u8>> {
    ensure_legacy_provider_loaded();
    let md = MessageDigest::from_name("MD4").ok_or_else(|| anyhow!("md4 digest is unavailable"))?;
    Ok(hash(md, input).context("md4")?.to_vec())
}

fn sha1_bytes(input: &[u8]) -> Result<Vec<u8>> {
    Ok(hash(MessageDigest::sha1(), input).context("sha1")?.to_vec())
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

fn des_encrypt_block(key8: &[u8; 8], block8: &[u8; 8]) -> Result<[u8; 8]> {
    ensure_legacy_provider_loaded();
    let cipher = Cipher::des_ecb();
    let mut crypter =
        Crypter::new(cipher, Mode::Encrypt, key8, None).context("create des crypter")?;
    crypter.pad(false);
    let mut out = [0u8; 16];
    let count = crypter.update(block8, &mut out).context("des update")?;
    let rest = crypter.finalize(&mut out[count..]).context("des finalize")?;
    ensure!(count + rest == 8, "unexpected des block output length");
    let mut block = [0u8; 8];
    block.copy_from_slice(&out[..8]);
    Ok(block)
}

fn challenge_hash(
    peer_challenge: &[u8; CHALLENGE_LEN],
    auth_challenge: &[u8; CHALLENGE_LEN],
    username: &[u8],
) -> Result<[u8; 8]> {
    let mut data = Vec::with_capacity(32 + username.len());
    data.extend_from_slice(peer_challenge);
    data.extend_from_slice(auth_challenge);
    data.extend_from_slice(username);
    let digest = sha1_bytes(&data)?;
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
    let password_hash = md4(&utf16le(password))?;
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
    let password_hash = md4(&utf16le(password))?;
    let password_hash_hash = md4(&password_hash)?;

    let mut first = Vec::with_capacity(password_hash_hash.len() + nt_response.len() + MAGIC1.len());
    first.extend_from_slice(&password_hash_hash);
    first.extend_from_slice(nt_response);
    first.extend_from_slice(MAGIC1);
    let first = sha1_bytes(&first)?;

    let challenge = challenge_hash(peer_challenge, auth_challenge, username)?;
    let mut second = Vec::with_capacity(first.len() + challenge.len() + MAGIC2.len());
    second.extend_from_slice(&first);
    second.extend_from_slice(&challenge);
    second.extend_from_slice(MAGIC2);
    let second = sha1_bytes(&second)?;

    Ok(second.iter().map(|byte| format!("{byte:02X}")).collect())
}

fn generate_msk(password: &str, nt_response: &[u8; NT_RESPONSE_LEN]) -> Result<Box<[u8]>> {
    let password_hash = md4(&utf16le(password))?;
    let password_hash_hash = md4(&password_hash)?;

    let mut master_input =
        Vec::with_capacity(password_hash_hash.len() + nt_response.len() + MSK_MAGIC1.len());
    master_input.extend_from_slice(&password_hash_hash);
    master_input.extend_from_slice(nt_response);
    master_input.extend_from_slice(MSK_MAGIC1);
    let master_key = sha1_bytes(&master_input)?;
    let master = &master_key[..16];

    let mut recv_input =
        Vec::with_capacity(master.len() + SHAPAD1.len() + MSK_MAGIC2.len() + SHAPAD2.len());
    recv_input.extend_from_slice(master);
    recv_input.extend_from_slice(&SHAPAD1);
    recv_input.extend_from_slice(MSK_MAGIC2);
    recv_input.extend_from_slice(&SHAPAD2);
    let recv = sha1_bytes(&recv_input)?;

    let mut send_input =
        Vec::with_capacity(master.len() + SHAPAD1.len() + MSK_MAGIC3.len() + SHAPAD2.len());
    send_input.extend_from_slice(master);
    send_input.extend_from_slice(&SHAPAD1);
    send_input.extend_from_slice(MSK_MAGIC3);
    send_input.extend_from_slice(&SHAPAD2);
    let send = sha1_bytes(&send_input)?;

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
