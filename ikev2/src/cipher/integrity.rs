use anyhow::Result;

use crate::cipher::{MacFn, sha1_hmac, sha256_hmac, sha512_hmac};

pub type IntegrityAlgID = u16;
pub struct IntegrityAlg {
    pub transform_id: u16,
    pub name: &'static str,
    pub key_len_hint: usize,
    pub output_len: usize,
    pub sign: MacFn,
}

impl IntegrityAlg {
    pub fn sign_vec(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; self.output_len];
        (self.sign)(key, data, &mut out)?;
        Ok(out)
    }
}
const_variant!(IntegrityAlg:
    AUTH_NONE_ALG = IntegrityAlg {
        transform_id: AUTH_NONE,
        name: "",
        key_len_hint: 0,
        output_len: 0,
        sign: dummy_sign,
    };
    AUTH_HMAC_SHA1_96_ALG = IntegrityAlg {
        transform_id: AUTH_HMAC_SHA1_96,
        name: "sha1",
        key_len_hint: 20,
        output_len: 12,
        sign: sha1_hmac,
    };
    AUTH_HMAC_SHA2_256_128_ALG = IntegrityAlg {
        transform_id: AUTH_HMAC_SHA2_256_128,
        name: "sha2_256",
        key_len_hint: 32,
        output_len: 16,
        sign: sha256_hmac,
    };
    AUTH_HMAC_SHA2_512_256_ALG = IntegrityAlg {
        transform_id: AUTH_HMAC_SHA2_512_256,
        name: "sha2_512",
        key_len_hint: 64,
        output_len: 32,
        sign: sha512_hmac,
    };
);

const_variant!(
    INTEGRITY_ALGS,
    IntegrityAlgID,
    IntegrityAlg:
    (
        AUTH_NONE,
        0u16,
        AUTH_NONE_ALG
    ),
    (
        AUTH_HMAC_SHA1_96,
        2u16,
        AUTH_HMAC_SHA1_96_ALG
    ),
    (
        AUTH_HMAC_SHA2_256_128,
        12u16,
        AUTH_HMAC_SHA2_256_128_ALG
    ),
    (
        AUTH_HMAC_SHA2_512_256,
        14u16,
        AUTH_HMAC_SHA2_512_256_ALG
    ),
);

fn dummy_sign(_: &[u8], _: &[u8], _: &mut [u8]) -> Result<()> {
    super::dummy()
}
