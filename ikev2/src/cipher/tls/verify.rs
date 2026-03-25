use anyhow::{Context, Result, anyhow, ensure};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

pub(crate) const GLOBAL_SKIP_CERT_VERIFY_ENV: &str =
    "SWAN_INSECURE_SKIP_PEER_CERT_CHAIN_VERIFY";
pub(crate) const PEAP_CERT_SHA256_PIN_ENV: &str = "SWAN_PEAP_SERVER_CERT_SHA256";
pub(crate) const PEAP_SKIP_CERT_VERIFY_ENV: &str = "SWAN_PEAP_INSECURE_SKIP_CERT_VERIFY";

pub(crate) fn normalize_hex_pin(value: &str) -> Option<String> {
    let compact: String = value.chars().filter(|ch| ch.is_ascii_hexdigit()).collect();
    if compact.is_empty() || !compact.len().is_multiple_of(2) {
        return None;
    }
    Some(compact.to_ascii_lowercase())
}

pub(crate) fn cert_sha256_hex(cert_der: &[u8]) -> String {
    use crate::cipher::Sha256;
    hex::encode(Sha256::digest(cert_der))
}

pub(crate) fn skip_cert_verify_enabled() -> Result<bool> {
    Ok(env_enabled(PEAP_SKIP_CERT_VERIFY_ENV)? || env_enabled(GLOBAL_SKIP_CERT_VERIFY_ENV)?)
}

pub(crate) fn env_enabled(key: &str) -> Result<bool> {
    let Some(raw) = std::env::var_os(key) else {
        return Ok(false);
    };
    let raw = raw.to_str().ok_or_else(|| anyhow!("{key} contains non-utf8 bytes"))?;
    let value = raw.trim();
    if matches!(value, "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON") {
        return Ok(true);
    }
    if matches!(value, "0" | "false" | "FALSE" | "no" | "NO" | "off" | "OFF") {
        return Ok(false);
    }
    Err(anyhow!("{key} must be one of: 1/0, true/false, yes/no, on/off"))
}

pub(crate) fn verify_tls_server_cert(
    cert_der: &[u8],
    expected_server_name: &ServerName<'_>,
) -> Result<()> {
    verify_cert_pin(cert_der)?;
    let cert_der = CertificateDer::from(cert_der);
    let cert =
        webpki::EndEntityCert::try_from(&cert_der).context("parse tls peer certificate")?;
    cert.verify_is_valid_for_subject_name(expected_server_name)
        .context("verify tls peer certificate subject name")
}

pub(super) fn load_root_store() -> Result<RootCertStore> {
    let certs =
        CertificateDer::pem_file_iter("/etc/ssl/cert.pem").context("read /etc/ssl/cert.pem")?;
    let mut store = RootCertStore::empty();
    let (added, _) = store.add_parsable_certificates(certs.filter_map(Result::ok));
    ensure!(added != 0, "no trust anchors loaded from /etc/ssl/cert.pem");
    Ok(store)
}

pub(super) fn verifier() -> Result<Arc<dyn ServerCertVerifier>> {
    if skip_cert_verify_enabled()? {
        return Ok(Arc::new(SkipServerCertVerifier));
    }

    let root_store = Arc::new(load_root_store()?);
    let inner = rustls::client::WebPkiServerVerifier::builder(root_store)
        .build()
        .context("build rustls webpki server verifier")?;
    Ok(Arc::new(PinnedServerCertVerifier { inner }))
}

struct PinnedServerCertVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
}

impl Debug for PinnedServerCertVerifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("PinnedServerCertVerifier")
    }
}

impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        verify_cert_pin(end_entity.as_ref()).map_err(|err| rustls::Error::General(err.to_string()))?;
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

struct SkipServerCertVerifier;

impl Debug for SkipServerCertVerifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("SkipServerCertVerifier")
    }
}

impl ServerCertVerifier for SkipServerCertVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn verify_cert_pin(cert_der: &[u8]) -> Result<()> {
    let Some(expected_raw) = std::env::var_os(PEAP_CERT_SHA256_PIN_ENV) else {
        return Ok(());
    };
    let expected_raw = expected_raw
        .to_str()
        .ok_or_else(|| anyhow!("{PEAP_CERT_SHA256_PIN_ENV} contains non-utf8 bytes"))?;
    let expected = normalize_hex_pin(expected_raw).ok_or_else(|| {
        anyhow!("{PEAP_CERT_SHA256_PIN_ENV} must be a SHA-256 hex string (colons optional)")
    })?;
    let actual = cert_sha256_hex(cert_der);
    ensure!(
        actual == expected,
        "tls server certificate pin mismatch: expected {expected}, got {actual}"
    );
    Ok(())
}
