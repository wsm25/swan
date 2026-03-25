use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime};
use webpki::{EndEntityCert, KeyUsage, anchor_from_trusted_cert};

use crate::cipher;

pub use rustls::{RustlsTlsBackend, rustls_tls_backend};
pub(crate) use verify::{cert_sha256_hex, env_enabled, verify_tls_server_cert};

mod rustls;
mod verify;

const ID_PAYLOAD_FIXED_FIELDS_LEN: usize = 4;

#[derive(Copy, Clone)]
pub enum TlsExporterMode {
    Rfc,
    StrongswanCompat,
}

pub struct TlsClientConfig {
    pub server_name: ServerName<'static>,
    pub exporter_mode: TlsExporterMode,
}

pub struct TlsStartedSession {
    pub session: Box<dyn TlsSession>,
    pub outbound: Bytes,
}

pub enum TlsHandshakeResult {
    NeedMoreData,
    Outbound(Bytes),
    Established { outbound: Bytes },
}

pub trait TlsBackend: Send + Sync {
    fn start_session(&self, config: &TlsClientConfig) -> Result<TlsStartedSession>;
}

pub trait TlsSession: Send {
    fn on_record(&mut self, record: &[u8]) -> Result<TlsHandshakeResult>;
    fn is_established(&self) -> bool;
    fn verify_server_identity(&self, expected_server_name: &ServerName<'_>) -> Result<()>;
    fn protect_application_data(&mut self, plaintext: &[u8]) -> Result<Bytes>;
    fn unprotect_application_data(&mut self, record: &[u8]) -> Result<Bytes>;
    fn export_eap_msk(&self) -> Result<Option<Box<[u8]>>>;
}

pub fn verify_peer_auth_signature(
    cert_chain_der: &[CertificateDer<'_>],
    idr_payload: &[u8],
    octets: &[u8],
    signature: &[u8],
    hash: &cipher::Hasher,
    expected_key_kind: Option<super::PKeyKind>,
    skip_cert_chain_verify: bool,
) -> Result<()> {
    let (leaf, intermediates) = split_cert_chain(cert_chain_der)?;
    verify_peer_certificate_chain(leaf, intermediates, skip_cert_chain_verify)?;
    verify_peer_certificate_identity(leaf, idr_payload)?;
    verify_peer_signature(leaf, hash, expected_key_kind, octets, signature)?;
    Ok(())
}

pub fn build_peer_cert_chain(
    peer_cert_der: Option<&Bytes>,
    peer_cert_chain: &[Bytes],
) -> Vec<CertificateDer<'static>> {
    if peer_cert_chain.is_empty() {
        peer_cert_der.into_iter().map(|cert| CertificateDer::from(cert.to_vec())).collect()
    } else {
        peer_cert_chain.iter().map(|cert| CertificateDer::from(cert.to_vec())).collect()
    }
}

fn split_cert_chain<'a>(
    cert_chain_der: &'a [CertificateDer<'a>],
) -> Result<(&'a CertificateDer<'a>, &'a [CertificateDer<'a>])> {
    let Some((leaf, intermediates)) = cert_chain_der.split_first() else {
        bail!("responder AUTH used certificate signature without CERT payload");
    };
    Ok((leaf, intermediates))
}

fn verify_peer_certificate_chain(
    leaf: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    skip_cert_chain_verify: bool,
) -> Result<()> {
    if skip_cert_chain_verify {
        return Ok(());
    }
    let anchors = load_system_trust_anchors()?;
    let leaf = EndEntityCert::try_from(leaf).context("parse responder leaf certificate")?;
    leaf.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &anchors,
        intermediates,
        unix_time_now()?,
        KeyUsage::server_auth(),
        None,
        None,
    )
    .context("verify responder certificate chain")?;
    Ok(())
}

fn verify_peer_certificate_identity(leaf: &CertificateDer<'_>, idr_payload: &[u8]) -> Result<()> {
    ensure!(
        idr_payload.len() >= ID_PAYLOAD_FIXED_FIELDS_LEN,
        "invalid IDr payload for certificate identity verification"
    );
    let leaf = EndEntityCert::try_from(leaf).context("parse responder leaf certificate")?;
    let id_type = idr_payload[0];
    let id_value = &idr_payload[ID_PAYLOAD_FIXED_FIELDS_LEN..];
    match id_type {
        crate::consts::ID_TYPE_FQDN => {
            let expected = std::str::from_utf8(id_value).context("IDr FQDN is not valid UTF-8")?;
            let expected = ServerName::try_from(expected.to_owned())
                .map_err(|_| anyhow::anyhow!("invalid IDr FQDN {expected}"))?;
            leaf.verify_is_valid_for_subject_name(&expected).with_context(|| {
                format!("responder certificate does not match IDr FQDN {expected:?}")
            })?;
        }
        crate::consts::ID_TYPE_RFC822_ADDR => {
            let expected =
                std::str::from_utf8(id_value).context("IDr RFC822 address is not valid UTF-8")?;
            bail!("certificate identity verification does not support RFC822 IDr {expected}");
        }
        crate::consts::ID_TYPE_IPV4_ADDR | crate::consts::ID_TYPE_IPV6_ADDR => {
            let expected = match id_value {
                [a, b, c, d] => {
                    ServerName::IpAddress(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)).into())
                }
                bytes if bytes.len() == 16 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(bytes);
                    ServerName::IpAddress(IpAddr::V6(Ipv6Addr::from(octets)).into())
                }
                _ => bail!("invalid IDr IP address length {}", id_value.len()),
            };
            leaf.verify_is_valid_for_subject_name(&expected)
                .context("responder certificate does not match IDr IP address")?;
        }
        crate::consts::ID_TYPE_KEY_ID => {
            bail!("certificate identity verification does not support KEY_ID IDr for MVP");
        }
        other => bail!("unsupported IDr type {other} for certificate identity verification"),
    }
    Ok(())
}

fn verify_peer_signature(
    leaf: &CertificateDer<'_>,
    hash: &cipher::Hasher,
    expected_key_kind: Option<super::PKeyKind>,
    octets: &[u8],
    signature: &[u8],
) -> Result<()> {
    let cert = EndEntityCert::try_from(leaf).context("parse responder leaf certificate")?;
    for &alg in signature_verification_algs(hash, expected_key_kind) {
        if cert.verify_signature(alg, octets, signature).is_ok() {
            return Ok(());
        }
    }
    bail!("AUTH signature verification failed")
}

fn signature_verification_algs(
    hash: &cipher::Hasher,
    expected_key_kind: Option<super::PKeyKind>,
) -> &'static [&'static dyn rustls_pki_types::SignatureVerificationAlgorithm] {
    static EMPTY: [&dyn rustls_pki_types::SignatureVerificationAlgorithm; 0] = [];
    static RSA_SHA256: [&dyn rustls_pki_types::SignatureVerificationAlgorithm; 2] = [
        webpki::ring::RSA_PKCS1_2048_8192_SHA256,
        webpki::ring::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
    ];
    static RSA_SHA384: [&dyn rustls_pki_types::SignatureVerificationAlgorithm; 2] = [
        webpki::ring::RSA_PKCS1_2048_8192_SHA384,
        webpki::ring::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
    ];
    static RSA_SHA512: [&dyn rustls_pki_types::SignatureVerificationAlgorithm; 2] = [
        webpki::ring::RSA_PKCS1_2048_8192_SHA512,
        webpki::ring::RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
    ];
    static ECDSA_SHA256: [&dyn rustls_pki_types::SignatureVerificationAlgorithm; 2] =
        [webpki::ring::ECDSA_P256_SHA256, webpki::ring::ECDSA_P384_SHA256];
    static ECDSA_SHA384: [&dyn rustls_pki_types::SignatureVerificationAlgorithm; 2] =
        [webpki::ring::ECDSA_P256_SHA384, webpki::ring::ECDSA_P384_SHA384];

    if expected_key_kind == Some(super::PKEY_KIND_RSA) && hash.kind() == cipher::HashKind::Sha1 {
        &EMPTY
    } else if expected_key_kind == Some(super::PKEY_KIND_RSA)
        && hash.kind() == cipher::HashKind::Sha256
    {
        &RSA_SHA256
    } else if expected_key_kind == Some(super::PKEY_KIND_RSA)
        && hash.kind() == cipher::HashKind::Sha384
    {
        &RSA_SHA384
    } else if expected_key_kind == Some(super::PKEY_KIND_RSA)
        && hash.kind() == cipher::HashKind::Sha512
    {
        &RSA_SHA512
    } else if expected_key_kind == Some(super::PKEY_KIND_EC)
        && hash.kind() == cipher::HashKind::Sha256
    {
        &ECDSA_SHA256
    } else if expected_key_kind == Some(super::PKEY_KIND_EC)
        && hash.kind() == cipher::HashKind::Sha384
    {
        &ECDSA_SHA384
    } else {
        &EMPTY
    }
}

fn load_system_trust_anchors() -> Result<Vec<TrustAnchor<'static>>> {
    let mut anchors = Vec::new();
    let certs =
        CertificateDer::pem_file_iter("/etc/ssl/cert.pem").context("read /etc/ssl/cert.pem")?;
    for cert in certs {
        let der = cert.context("read PEM certificate from /etc/ssl/cert.pem")?;
        let anchor =
            anchor_from_trusted_cert(&der).context("parse trust anchor from /etc/ssl/cert.pem")?;
        anchors.push(anchor.to_owned());
    }
    ensure!(!anchors.is_empty(), "no trust anchors loaded from /etc/ssl/cert.pem");
    Ok(anchors)
}

fn unix_time_now() -> Result<UnixTime> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("system clock before unix epoch")?;
    Ok(UnixTime::since_unix_epoch(Duration::from_secs(now.as_secs())))
}
