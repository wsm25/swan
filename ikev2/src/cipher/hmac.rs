use crate::cipher::hash::{self, HashKind};
use anyhow::{Result, ensure};
use ring::hmac;

fn algorithm(kind: HashKind) -> &'static hmac::Algorithm {
    match kind {
        HashKind::Sha1 => &hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        HashKind::Sha256 => &hmac::HMAC_SHA256,
        HashKind::Sha384 => &hmac::HMAC_SHA384,
        HashKind::Sha512 => &hmac::HMAC_SHA512,
    }
}

fn hmac_sign(kind: HashKind, key: &[u8], data: &[u8], output: &mut [u8]) -> Result<()> {
    let signature = hmac::sign(&hmac::Key::new(*algorithm(kind), key), data);
    ensure!(output.len() <= signature.as_ref().len(), "invalid HMAC output length");
    output.copy_from_slice(&signature.as_ref()[..output.len()]);
    Ok(())
}

pub type MacFn = fn(key: &[u8], data: &[u8], output: &mut [u8]) -> Result<()>;

pub fn sha1_hmac(key: &[u8], data: &[u8], output: &mut [u8]) -> Result<()> {
    hmac_sign(hash::SHA1_HASHER.kind(), key, data, output)
}

pub fn sha256_hmac(key: &[u8], data: &[u8], output: &mut [u8]) -> Result<()> {
    hmac_sign(hash::SHA256_HASHER.kind(), key, data, output)
}

pub fn sha384_hmac(key: &[u8], data: &[u8], output: &mut [u8]) -> Result<()> {
    hmac_sign(hash::SHA384_HASHER.kind(), key, data, output)
}

pub fn sha512_hmac(key: &[u8], data: &[u8], output: &mut [u8]) -> Result<()> {
    hmac_sign(hash::SHA512_HASHER.kind(), key, data, output)
}
