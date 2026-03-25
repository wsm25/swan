use anyhow::{Context, Result, bail, ensure};
use openssl::provider::Provider;
use openssl::symm::{Cipher, Crypter, Mode};
use std::sync::OnceLock;

pub type EncryptionAlgID = (u16, u16);
type CipherFn =
    fn(alg: &EncryptionAlg, key: &[u8], iv: &[u8], aad: &[u8], payload: &[u8]) -> Result<Vec<u8>>;

pub struct EncryptionAlg {
    pub transform_id: u16,
    pub name: &'static str,
    pub transform_key_len: usize,
    pub key_len: usize,
    pub salt_len: usize,
    pub iv_len: usize,
    pub block_len: usize,
    pub icv_len: usize,
    pub is_aead: bool,
    pub encrypt: CipherFn,
    pub decrypt: CipherFn,
}

impl EncryptionAlg {
    pub fn encrypt_vec(&self, key: &[u8], iv: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        (self.encrypt)(self, key, iv, aad, plaintext)
    }

    pub fn decrypt_vec(
        &self,
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        (self.decrypt)(self, key, iv, aad, ciphertext)
    }
}

const_variant!(
    ENCRYPTION_ALGS,
    EncryptionAlgID,
    EncryptionAlg:
    (
        ENCR_NONE,
        (0u16, 0u16),
        EncryptionAlg {
            transform_id: ENCR_NONE.0,
            name: "",
            transform_key_len: 0,
            key_len: 0,
            salt_len: 0,
            iv_len: 0,
            block_len: 0,
            icv_len: 0,
            is_aead: false,
            encrypt: dummy_cipher,
            decrypt: dummy_cipher,
        }
    ),
    (
        ENCR_AES128_CBC,
        (12u16, 16u16),
        EncryptionAlg {
            transform_id: ENCR_AES128_CBC.0,
            name: "aes128",
            transform_key_len: 16,
            key_len: 16,
            salt_len: 0,
            iv_len: 16,
            block_len: 16,
            icv_len: 0,
            is_aead: false,
            encrypt: aes128_cbc_encrypt,
            decrypt: aes128_cbc_decrypt,
        }
    ),
    (
        ENCR_AES256_CBC,
        (12u16, 32u16),
        EncryptionAlg {
            transform_id: ENCR_AES256_CBC.0,
            name: "aes256",
            transform_key_len: 32,
            key_len: 32,
            salt_len: 0,
            iv_len: 16,
            block_len: 16,
            icv_len: 0,
            is_aead: false,
            encrypt: aes256_cbc_encrypt,
            decrypt: aes256_cbc_decrypt,
        }
    ),
    (
        ENCR_AES128_CCM_8,
        (14u16, 16u16),
        EncryptionAlg {
            transform_id: ENCR_AES128_CCM_8.0,
            name: "aes128ccm8",
            transform_key_len: 16,
            key_len: 19,
            salt_len: 3,
            iv_len: 8,
            block_len: 1,
            icv_len: 8,
            is_aead: true,
            encrypt: aes_ccm_encrypt,
            decrypt: aes_ccm_decrypt,
        }
    ),
    (
        ENCR_AES256_CCM_8,
        (14u16, 32u16),
        EncryptionAlg {
            transform_id: ENCR_AES256_CCM_8.0,
            name: "aes256ccm8",
            transform_key_len: 32,
            key_len: 35,
            salt_len: 3,
            iv_len: 8,
            block_len: 1,
            icv_len: 8,
            is_aead: true,
            encrypt: aes_ccm_encrypt,
            decrypt: aes_ccm_decrypt,
        }
    ),
    (
        ENCR_AES128_CCM_12,
        (15u16, 16u16),
        EncryptionAlg {
            transform_id: ENCR_AES128_CCM_12.0,
            name: "aes128ccm12",
            transform_key_len: 16,
            key_len: 19,
            salt_len: 3,
            iv_len: 8,
            block_len: 1,
            icv_len: 12,
            is_aead: true,
            encrypt: aes_ccm_encrypt,
            decrypt: aes_ccm_decrypt,
        }
    ),
    (
        ENCR_AES256_CCM_12,
        (15u16, 32u16),
        EncryptionAlg {
            transform_id: ENCR_AES256_CCM_12.0,
            name: "aes256ccm12",
            transform_key_len: 32,
            key_len: 35,
            salt_len: 3,
            iv_len: 8,
            block_len: 1,
            icv_len: 12,
            is_aead: true,
            encrypt: aes_ccm_encrypt,
            decrypt: aes_ccm_decrypt,
        }
    ),
    (
        ENCR_AES128_CCM_16,
        (16u16, 16u16),
        EncryptionAlg {
            transform_id: ENCR_AES128_CCM_16.0,
            name: "aes128ccm16",
            transform_key_len: 16,
            key_len: 19,
            salt_len: 3,
            iv_len: 8,
            block_len: 1,
            icv_len: 16,
            is_aead: true,
            encrypt: aes_ccm_encrypt,
            decrypt: aes_ccm_decrypt,
        }
    ),
    (
        ENCR_AES256_CCM_16,
        (16u16, 32u16),
        EncryptionAlg {
            transform_id: ENCR_AES256_CCM_16.0,
            name: "aes256ccm16",
            transform_key_len: 32,
            key_len: 35,
            salt_len: 3,
            iv_len: 8,
            block_len: 1,
            icv_len: 16,
            is_aead: true,
            encrypt: aes_ccm_encrypt,
            decrypt: aes_ccm_decrypt,
        }
    ),
    (
        ENCR_AES128_GCM_8,
        (18u16, 16u16),
        EncryptionAlg {
            transform_id: ENCR_AES128_GCM_8.0,
            name: "aes128gcm8",
            transform_key_len: 16,
            key_len: 20,
            salt_len: 4,
            iv_len: 8,
            block_len: 1,
            icv_len: 8,
            is_aead: true,
            encrypt: aes_gcm_encrypt,
            decrypt: aes_gcm_decrypt,
        }
    ),
    (
        ENCR_AES256_GCM_8,
        (18u16, 32u16),
        EncryptionAlg {
            transform_id: ENCR_AES256_GCM_8.0,
            name: "aes256gcm8",
            transform_key_len: 32,
            key_len: 36,
            salt_len: 4,
            iv_len: 8,
            block_len: 1,
            icv_len: 8,
            is_aead: true,
            encrypt: aes_gcm_encrypt,
            decrypt: aes_gcm_decrypt,
        }
    ),
    (
        ENCR_AES128_GCM_12,
        (19u16, 16u16),
        EncryptionAlg {
            transform_id: ENCR_AES128_GCM_12.0,
            name: "aes128gcm12",
            transform_key_len: 16,
            key_len: 20,
            salt_len: 4,
            iv_len: 8,
            block_len: 1,
            icv_len: 12,
            is_aead: true,
            encrypt: aes_gcm_encrypt,
            decrypt: aes_gcm_decrypt,
        }
    ),
    (
        ENCR_AES256_GCM_12,
        (19u16, 32u16),
        EncryptionAlg {
            transform_id: ENCR_AES256_GCM_12.0,
            name: "aes256gcm12",
            transform_key_len: 32,
            key_len: 36,
            salt_len: 4,
            iv_len: 8,
            block_len: 1,
            icv_len: 12,
            is_aead: true,
            encrypt: aes_gcm_encrypt,
            decrypt: aes_gcm_decrypt,
        }
    ),
    (
        ENCR_AES128_GCM_16,
        (20u16, 16u16),
        EncryptionAlg {
            transform_id: ENCR_AES128_GCM_16.0,
            name: "aes128gcm16",
            transform_key_len: 16,
            key_len: 20,
            salt_len: 4,
            iv_len: 8,
            block_len: 1,
            icv_len: 16,
            is_aead: true,
            encrypt: aes_gcm_encrypt,
            decrypt: aes_gcm_decrypt,
        }
    ),
    (
        ENCR_AES256_GCM_16,
        (20u16, 32u16),
        EncryptionAlg {
            transform_id: ENCR_AES256_GCM_16.0,
            name: "aes256gcm16",
            transform_key_len: 32,
            key_len: 36,
            salt_len: 4,
            iv_len: 8,
            block_len: 1,
            icv_len: 16,
            is_aead: true,
            encrypt: aes_gcm_encrypt,
            decrypt: aes_gcm_decrypt,
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

fn aes128_cbc_encrypt(
    _: &EncryptionAlg,
    key: &[u8],
    iv: &[u8],
    _: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    aes_cbc_crypt(Cipher::aes_128_cbc(), Mode::Encrypt, key, iv, plaintext)
}

fn aes128_cbc_decrypt(
    _: &EncryptionAlg,
    key: &[u8],
    iv: &[u8],
    _: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    aes_cbc_crypt(Cipher::aes_128_cbc(), Mode::Decrypt, key, iv, ciphertext)
}

fn aes256_cbc_encrypt(
    _: &EncryptionAlg,
    key: &[u8],
    iv: &[u8],
    _: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    aes_cbc_crypt(Cipher::aes_256_cbc(), Mode::Encrypt, key, iv, plaintext)
}

fn aes256_cbc_decrypt(
    _: &EncryptionAlg,
    key: &[u8],
    iv: &[u8],
    _: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    aes_cbc_crypt(Cipher::aes_256_cbc(), Mode::Decrypt, key, iv, ciphertext)
}

fn aes_gcm_encrypt(
    alg: &EncryptionAlg,
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let (cipher, nonce) = aead_cipher_nonce(alg, key, iv, AeadKind::Gcm)?;
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, nonce.key, Some(&nonce.nonce))
        .context("create gcm crypter")?;
    crypter.pad(false);
    crypter.aad_update(aad).context("gcm aad update failed")?;

    let mut out = vec![0u8; plaintext.len() + cipher.block_size()];
    let mut count = crypter.update(plaintext, &mut out).context("gcm update failed")?;
    count += crypter.finalize(&mut out[count..]).context("gcm finalize failed")?;
    out.truncate(count);

    let mut tag = vec![0u8; alg.icv_len];
    crypter.get_tag(&mut tag).context("gcm get tag failed")?;
    out.extend_from_slice(&tag);
    Ok(out)
}

fn aes_gcm_decrypt(
    alg: &EncryptionAlg,
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    ensure!(ciphertext.len() >= alg.icv_len, "truncated gcm ciphertext");
    let (cipher, nonce) = aead_cipher_nonce(alg, key, iv, AeadKind::Gcm)?;
    let data_len = ciphertext.len() - alg.icv_len;
    let (data, tag) = ciphertext.split_at(data_len);
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, nonce.key, Some(&nonce.nonce))
        .context("create gcm crypter")?;
    crypter.pad(false);
    crypter.aad_update(aad).context("gcm aad update failed")?;
    crypter.set_tag(tag).context("gcm set tag failed")?;

    let mut out = vec![0u8; data.len() + cipher.block_size()];
    let mut count = crypter.update(data, &mut out).context("gcm update failed")?;
    count += crypter.finalize(&mut out[count..]).context("gcm finalize failed")?;
    out.truncate(count);
    Ok(out)
}

fn aes_ccm_encrypt(
    alg: &EncryptionAlg,
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let (cipher, nonce) = aead_cipher_nonce(alg, key, iv, AeadKind::Ccm)?;
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, nonce.key, Some(&nonce.nonce))
        .context("create ccm crypter")?;
    crypter.pad(false);
    crypter.set_tag_len(alg.icv_len).context("ccm set tag length failed")?;
    crypter.set_data_len(plaintext.len()).context("ccm set data length failed")?;
    crypter.aad_update(aad).context("ccm aad update failed")?;

    let mut out = vec![0u8; plaintext.len() + cipher.block_size()];
    let mut count = crypter.update(plaintext, &mut out).context("ccm update failed")?;
    count += crypter.finalize(&mut out[count..]).context("ccm finalize failed")?;
    out.truncate(count);

    let mut tag = vec![0u8; alg.icv_len];
    crypter.get_tag(&mut tag).context("ccm get tag failed")?;
    out.extend_from_slice(&tag);
    Ok(out)
}

fn aes_ccm_decrypt(
    alg: &EncryptionAlg,
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    ensure!(ciphertext.len() >= alg.icv_len, "truncated ccm ciphertext");
    let (cipher, nonce) = aead_cipher_nonce(alg, key, iv, AeadKind::Ccm)?;
    let data_len = ciphertext.len() - alg.icv_len;
    let (data, tag) = ciphertext.split_at(data_len);
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, nonce.key, Some(&nonce.nonce))
        .context("create ccm crypter")?;
    crypter.pad(false);
    crypter.set_tag(tag).context("ccm set tag failed")?;
    crypter.set_data_len(data.len()).context("ccm set data length failed")?;
    crypter.aad_update(aad).context("ccm aad update failed")?;

    let mut out = vec![0u8; data.len() + cipher.block_size()];
    let mut count = crypter.update(data, &mut out).context("ccm update failed")?;
    count += crypter.finalize(&mut out[count..]).context("ccm finalize failed")?;
    out.truncate(count);
    Ok(out)
}

pub fn des_encrypt_block(key8: &[u8; 8], block8: &[u8; 8]) -> Result<[u8; 8]> {
    ensure_legacy_provider_loaded();
    let cipher = Cipher::des_ecb();
    ensure!(cipher.key_len() == key8.len(), "unexpected des key length");

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

enum AeadKind {
    Gcm,
    Ccm,
}

struct AeadNonce<'a> {
    key: &'a [u8],
    nonce: Vec<u8>,
}

fn aead_cipher_nonce<'a>(
    alg: &EncryptionAlg,
    key: &'a [u8],
    iv: &[u8],
    kind: AeadKind,
) -> Result<(Cipher, AeadNonce<'a>)> {
    ensure!(alg.is_aead, "AEAD helper used with non-AEAD cipher");
    ensure!(key.len() == alg.key_len, "invalid AEAD key length");
    ensure!(iv.len() == alg.iv_len, "invalid AEAD iv length");
    ensure!(alg.transform_key_len + alg.salt_len == alg.key_len, "invalid AEAD key layout");
    let (cipher_key, salt) = key.split_at(alg.transform_key_len);
    let mut nonce = Vec::with_capacity(salt.len() + iv.len());
    nonce.extend_from_slice(salt);
    nonce.extend_from_slice(iv);
    let cipher = match (kind, alg.transform_key_len) {
        (AeadKind::Gcm, 16) => Cipher::aes_128_gcm(),
        (AeadKind::Gcm, 32) => Cipher::aes_256_gcm(),
        (AeadKind::Ccm, 16) => Cipher::aes_128_ccm(),
        (AeadKind::Ccm, 32) => Cipher::aes_256_ccm(),
        _ => bail!("unsupported AEAD key size {}", alg.transform_key_len),
    };
    Ok((cipher, AeadNonce { key: cipher_key, nonce }))
}

fn dummy_cipher(_: &EncryptionAlg, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
    super::dummy()
}

fn ensure_legacy_provider_loaded() {
    static LEGACY_PROVIDER: OnceLock<Option<Provider>> = OnceLock::new();
    LEGACY_PROVIDER.get_or_init(|| Provider::try_load(None, "legacy", true).ok());
}
