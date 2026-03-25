use anyhow::Result;

use crate::cipher::{MacFn, sha1_hmac, sha256_hmac, sha512_hmac};

pub type PrfAlgID = u16;
pub struct PrfAlg {
    pub transform_id: u16,
    pub name: &'static str,
    pub key_len_hint: usize,
    pub output_len: usize,
    pub gen_prf: MacFn,
}

impl PrfAlg {
    pub fn gen_prf_vec(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; self.output_len];
        (self.gen_prf)(key, data, &mut out)?;
        Ok(out)
    }
}

const_variant!(PrfAlg:
    PRF_NONE_ALG = PrfAlg {
        transform_id: PRF_NONE,
        name: "",
        key_len_hint: 0,
        output_len: 0,
        gen_prf: dummy_prf,
    };
    PRF_HMAC_SHA1_ALG = PrfAlg {
        transform_id: PRF_HMAC_SHA1,
        name: "prfsha1",
        key_len_hint: 20,
        output_len: 20,
        gen_prf: sha1_hmac,
    };
    PRF_HMAC_SHA2_256_ALG = PrfAlg {
        transform_id: PRF_HMAC_SHA2_256,
        name: "prfsha2_256",
        key_len_hint: 32,
        output_len: 32,
        gen_prf: sha256_hmac,
    };
    PRF_HMAC_SHA2_512_ALG = PrfAlg {
        transform_id: PRF_HMAC_SHA2_512,
        name: "prfsha2_512",
        key_len_hint: 64,
        output_len: 64,
        gen_prf: sha512_hmac,
    };
);

const_variant!(
    PRF_ALGS,
    PrfAlgID,
    PrfAlg:
    (
        PRF_NONE,
        0u16,
        PRF_NONE_ALG
    ),
    (
        PRF_HMAC_SHA1,
        2u16,
        PRF_HMAC_SHA1_ALG
    ),
    (
        PRF_HMAC_SHA2_256,
        5u16,
        PRF_HMAC_SHA2_256_ALG
    ),
    (
        PRF_HMAC_SHA2_512,
        7u16,
        PRF_HMAC_SHA2_512_ALG
    ),
);

fn dummy_prf(_: &[u8], _: &[u8], _: &mut [u8]) -> Result<()> {
    super::dummy()
}
