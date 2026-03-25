use anyhow::{Context, Result, bail, ensure};
use hex_literal::hex;
use openssl::bn::{BigNum, BigNumContext};
use openssl::derive::Deriver;
use openssl::dh::Dh;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use openssl::symm::{Cipher, Crypter, Mode};
pub type EncryptionAlgID = (u16, u16);
pub type IntegrityAlgID = u16;
pub type PrfAlgID = u16;
pub type DhAlgID = u16;

// keys

pub struct IkeKeyMaterial {
    pub sk_d: Box<[u8]>,
    pub sk_ai: Box<[u8]>,
    pub sk_ar: Box<[u8]>,
    pub sk_ei: Box<[u8]>,
    pub sk_er: Box<[u8]>,
    pub sk_pi: Box<[u8]>,
    pub sk_pr: Box<[u8]>,
}

// symm encrypt

type CipherFn = fn(key: &[u8], iv: &[u8], payload: &[u8]) -> Result<Vec<u8>>;

pub struct EncryptionAlg {
    pub transform_id: u16,
    pub name: &'static str,
    pub key_len: usize,
    pub iv_len: usize,
    pub block_len: usize,
    pub encrypt: CipherFn,
    pub decrypt: CipherFn,
}

const_variant!(
    u16:
    ENCR_NONE = 0u16;
    ENCR_AES_CBC = 12u16;
);

const_variant!(
    ENCRYPTION_ALGS,
    EncryptionAlgID,
    EncryptionAlg:
    (
        ENCR_NONE_,
        (0u16, 0u16),
        EncryptionAlg {
            transform_id: ENCR_NONE,
            name: "",
            key_len: 0,
            iv_len: 0,
            block_len: 0,
            encrypt: dummy_cipher,
            decrypt: dummy_cipher,
        }
    ),
    (
        ENCR_AES128_CBC,
        (12u16, 16u16),
        EncryptionAlg {
            transform_id: ENCR_AES_CBC,
            name: "aes128",
            key_len: 16,
            iv_len: 16,
            block_len: 16,
            encrypt: aes128_cbc_encrypt,
            decrypt: aes128_cbc_decrypt,
        }
    ),
    (
        ENCR_AES256_CBC,
        (12u16, 32u16),
        EncryptionAlg {
            transform_id: ENCR_AES_CBC,
            name: "aes256",
            key_len: 32,
            iv_len: 16,
            block_len: 16,
            encrypt: aes256_cbc_encrypt,
            decrypt: aes256_cbc_decrypt,
        }
    ),
);

fn aes_cbc_crypt(
    cipher: Cipher,
    mode: Mode,
    key: &[u8],
    iv: &[u8],
    input: &[u8],
) -> Result<Vec<u8>> {
    let block_len = cipher.block_size();
    ensure!(key.len() == cipher.key_len(), "invalid key length");
    ensure!(iv.len() == cipher.iv_len().unwrap_or(0), "invalid iv length");
    if !input.len().is_multiple_of(block_len) {
        bail!("input length must be a multiple of block size");
    }

    let mut crypter = Crypter::new(cipher, mode, key, Some(iv)).context("create crypter")?;
    crypter.pad(false);

    let mut out = vec![0_u8; input.len() + block_len];
    let mut count = crypter.update(input, &mut out).context("cipher update failed")?;
    count += crypter.finalize(&mut out[count..]).context("cipher finalize failed")?;
    out.truncate(count);
    Ok(out)
}

fn aes128_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    aes_cbc_crypt(Cipher::aes_128_cbc(), Mode::Encrypt, key, iv, plaintext)
}

fn aes128_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    aes_cbc_crypt(Cipher::aes_128_cbc(), Mode::Decrypt, key, iv, ciphertext)
}

fn aes256_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    aes_cbc_crypt(Cipher::aes_256_cbc(), Mode::Encrypt, key, iv, plaintext)
}

fn aes256_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    aes_cbc_crypt(Cipher::aes_256_cbc(), Mode::Decrypt, key, iv, ciphertext)
}

fn dummy_cipher(_: &[u8], _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
    dummy()
}

// integrity

pub struct IntegrityAlg {
    pub transform_id: u16,
    pub name: &'static str,
    pub key_len_hint: usize,
    pub output_len: usize,
    pub sign: fn(key: &[u8], data: &[u8]) -> Result<Vec<u8>>,
}

const_variant!(
    INTEGRITY_ALGS,
    IntegrityAlgID,
    IntegrityAlg:
    (
        AUTH_NONE,
        0u16,
        IntegrityAlg {
            transform_id: AUTH_NONE,
            name: "",
            key_len_hint: 0,
            output_len: 0,
            sign: dummy_sign,
        }
    ),
    (
        AUTH_HMAC_SHA1_96,
        2u16,
        IntegrityAlg {
            transform_id: AUTH_HMAC_SHA1_96,
            name: "sha1",
            key_len_hint: 20,
            output_len: 12,
            sign: sha1_sign,
        }
    ),
    (
        AUTH_HMAC_SHA2_256_128,
        12u16,
        IntegrityAlg {
            transform_id: AUTH_HMAC_SHA2_256_128,
            name: "sha2_256",
            key_len_hint: 32,
            output_len: 16,
            sign: sha256_sign,
        }
    ),
    (
        AUTH_HMAC_SHA2_512_256,
        14u16,
        IntegrityAlg {
            transform_id: AUTH_HMAC_SHA2_512_256,
            name: "sha2_512",
            key_len_hint: 64,
            output_len: 32,
            sign: sha512_sign,
        }
    ),
);

fn hmac(md: MessageDigest, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let pkey = PKey::hmac(key).context("create HMAC key")?;
    let mut signer = Signer::new(md, &pkey).context("create HMAC signer")?;
    signer.update(data).context("update HMAC input")?;
    signer.sign_to_vec().context("finalize HMAC")
}

fn dummy_sign(_: &[u8], _: &[u8]) -> Result<Vec<u8>> {
    dummy()
}

fn sha1_sign(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hmac(MessageDigest::sha1(), key, data)
}

fn sha256_sign(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hmac(MessageDigest::sha256(), key, data)
}

fn sha512_sign(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hmac(MessageDigest::sha512(), key, data)
}
// prf

pub struct PrfAlg {
    pub transform_id: u16,
    pub name: &'static str,
    pub key_len_hint: usize,
    pub output_len: usize,
    pub gen_prf: fn(key: &[u8], seed: &[u8]) -> Result<Vec<u8>>,
}

const_variant!(
    PRF_ALGS,
    PrfAlgID,
    PrfAlg:
    (
        PRF_NONE,
        0u16,
        PrfAlg {
            transform_id: PRF_NONE,
            name: "",
            key_len_hint: 0,
            output_len: 0,
            gen_prf: dummy_sign,
        }
    ),
    (
        PRF_HMAC_SHA1,
        2u16,
        PrfAlg {
            transform_id: PRF_HMAC_SHA1,
            name: "prfsha1",
            key_len_hint: 20,
            output_len: 20,
            gen_prf: sha1_sign,
        }
    ),
    (
        PRF_HMAC_SHA2_256,
        5u16,
        PrfAlg {
            transform_id: PRF_HMAC_SHA2_256,
            name: "prfsha2_256",
            key_len_hint: 32,
            output_len: 32,
            gen_prf: sha256_sign,
        }
    ),
    (
        PRF_HMAC_SHA2_512,
        7u16,
        PrfAlg {
            transform_id: PRF_HMAC_SHA2_512,
            name: "prfsha2_512",
            key_len_hint: 64,
            output_len: 64,
            gen_prf: sha512_sign,
        }
    ),
);

// dh

pub enum DhKeyPair {
    Modp1024(Dh<Private>),
    Curve25519(PKey<Private>),
}

pub struct DhAlg {
    pub transform_id: u16,
    pub name: &'static str,
    pub generate_keypair: fn() -> Result<DhKeyPair>,
    pub public_key: fn(keypair: &DhKeyPair) -> Result<Box<[u8]>>,
    #[allow(clippy::type_complexity)]
    pub shared_secret: fn(keypair: &DhKeyPair, peer_public: &[u8]) -> Result<Box<[u8]>>,
}

const_variant!(
    DH_ALGS,
    DhAlgID,
    DhAlg:
    (
        DH_NONE,
        0u16,
        DhAlg {
            transform_id: DH_NONE,
            name: "",
            generate_keypair: dummy_generate_keypair,
            public_key: dummy_public_key,
            shared_secret: dummy_shared_secret,
        }
    ),
    (
        DH_MODP_1024,
        2u16,
        DhAlg {
            transform_id: DH_MODP_1024,
            name: "modp1024",
            generate_keypair: modp1024_generate_keypair,
            public_key: modp1024_public_key,
            shared_secret: modp1024_shared_secret,
        }
    ),
    (
        DH_CURVE_25519,
        31u16,
        DhAlg {
            transform_id: DH_CURVE_25519,
            name: "curve25519",
            generate_keypair: curve25519_generate_keypair,
            public_key: curve25519_public_key,
            shared_secret: curve25519_shared_secret,
        }
    ),
);

fn modp1024_generate_keypair() -> Result<DhKeyPair> {
    const MODP1024_GROUP2_PRIME_HEX: [u8; 128] = hex!(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"
    );
    let p = BigNum::from_slice(&MODP1024_GROUP2_PRIME_HEX).context("parse MODP1024 group prime")?;
    let g = BigNum::from_u32(2).context("build MODP1024 generator")?;
    let key = Dh::from_pqg(p, None, g)
        .context("load MODP1024 parameters")?
        .generate_key()
        .context("generate MODP1024 keypair")?;
    Ok(DhKeyPair::Modp1024(key))
}

fn modp1024_public_key(keypair: &DhKeyPair) -> Result<Box<[u8]>> {
    let DhKeyPair::Modp1024(keypair) = keypair else {
        bail!("unexpected DH keypair kind for MODP1024");
    };
    let p_len = keypair.prime_p().num_bytes();
    let public = keypair.public_key().to_vec_padded(p_len).context("encode MODP1024 public key")?;
    Ok(public.into_boxed_slice())
}

fn modp1024_shared_secret(keypair: &DhKeyPair, peer_public: &[u8]) -> Result<Box<[u8]>> {
    let DhKeyPair::Modp1024(keypair) = keypair else {
        bail!("unexpected DH keypair kind for MODP1024");
    };
    let peer_public = BigNum::from_slice(peer_public).context("parse peer MODP1024 public key")?;
    let mut ctx = BigNumContext::new().context("create BigNum context")?;
    let mut shared_secret = BigNum::new().context("allocate DH shared secret")?;
    shared_secret
        .mod_exp(&peer_public, keypair.private_key(), keypair.prime_p(), &mut ctx)
        .context("derive MODP1024 shared secret")?;
    let shared_secret = shared_secret
        .to_vec_padded(keypair.prime_p().num_bytes())
        .context("encode MODP1024 shared secret")?;
    Ok(shared_secret.into_boxed_slice())
}

fn curve25519_generate_keypair() -> Result<DhKeyPair> {
    Ok(DhKeyPair::Curve25519(PKey::generate_x25519().context("generate X25519 keypair")?))
}

fn curve25519_public_key(keypair: &DhKeyPair) -> Result<Box<[u8]>> {
    let DhKeyPair::Curve25519(keypair) = keypair else {
        bail!("unexpected DH keypair kind for CURVE25519");
    };
    Ok(keypair.raw_public_key().context("encode X25519 public key")?.into_boxed_slice())
}

fn curve25519_shared_secret(keypair: &DhKeyPair, peer_public: &[u8]) -> Result<Box<[u8]>> {
    let DhKeyPair::Curve25519(keypair) = keypair else {
        bail!("unexpected DH keypair kind for CURVE25519");
    };
    let peer_public = PKey::public_key_from_raw_bytes(peer_public, openssl::pkey::Id::X25519)
        .context("parse X25519 peer public key")?;
    let mut deriver = Deriver::new(keypair).context("create X25519 deriver")?;
    deriver.set_peer(&peer_public).context("set X25519 peer public key")?;
    Ok(deriver.derive_to_vec().context("derive X25519 shared secret")?.into_boxed_slice())
}

fn dummy_generate_keypair() -> Result<DhKeyPair> {
    dummy()
}

fn dummy_public_key(_: &DhKeyPair) -> Result<Box<[u8]>> {
    dummy()
}

fn dummy_shared_secret(_: &DhKeyPair, _: &[u8]) -> Result<Box<[u8]>> {
    dummy()
}

#[cold]
fn dummy<T>() -> Result<T> {
    bail!("call dummy implement unexpectedly")
}
