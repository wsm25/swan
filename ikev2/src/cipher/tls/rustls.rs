use anyhow::{Context, Result, anyhow, bail, ensure};
use bytes::Bytes;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, ProtocolVersion};
use std::io::{Cursor, ErrorKind, Read, Write};
use std::sync::Arc;

use super::{
    TlsBackend, TlsClientConfig, TlsExporterMode, TlsHandshakeResult, TlsSession, TlsStartedSession,
    cert_sha256_hex, env_enabled, verify::verifier, verify_tls_server_cert,
};

const PEAP_ALLOW_LEGACY_RENEGOTIATION_ENV: &str = "SWAN_PEAP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION";

pub fn rustls_tls_backend() -> Result<Box<dyn TlsBackend>> {
    Ok(Box::new(RustlsTlsBackend::new()?))
}

pub struct RustlsTlsBackend {
    config: Arc<ClientConfig>,
}

pub struct RustlsTlsSession {
    exporter_mode: TlsExporterMode,
    conn: ClientConnection,
}

impl RustlsTlsBackend {
    fn new() -> Result<Self> {
        if env_enabled(PEAP_ALLOW_LEGACY_RENEGOTIATION_ENV)? {
            bail!("SWAN_PEAP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION is unsupported by rustls");
        }

        let provider = rustls::crypto::ring::default_provider();
        let config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .context("configure rustls protocol versions")?
            .dangerous()
            .with_custom_certificate_verifier(verifier()?)
            .with_no_client_auth();
        Ok(Self { config: Arc::new(config) })
    }
}

impl TlsBackend for RustlsTlsBackend {
    fn start_session(&self, config: &TlsClientConfig) -> Result<TlsStartedSession> {
        let ServerName::DnsName(server_name) = &config.server_name else {
            bail!("rustls tls backend only supports DNS server names for client handshake");
        };
        ensure!(!server_name.as_ref().is_empty(), "peap server name must not be empty");

        let mut conn = ClientConnection::new(self.config.clone(), config.server_name.clone())
            .with_context(|| format!("create rustls client connection for {}", server_name.as_ref()))?;
        let outbound = take_outbound(&mut conn)?;
        Ok(TlsStartedSession {
            outbound,
            session: Box::new(RustlsTlsSession { exporter_mode: config.exporter_mode, conn }),
        })
    }
}

impl TlsSession for RustlsTlsSession {
    fn on_record(&mut self, record: &[u8]) -> Result<TlsHandshakeResult> {
        self.conn
            .read_tls(&mut Cursor::new(record))
            .context("read inbound peap tls record")?;
        self.conn.process_new_packets().context("process inbound peap tls record")?;
        let outbound = take_outbound(&mut self.conn)?;
        if self.conn.is_handshaking() {
            if outbound.is_empty() {
                Ok(TlsHandshakeResult::NeedMoreData)
            } else {
                Ok(TlsHandshakeResult::Outbound(outbound))
            }
        } else {
            Ok(TlsHandshakeResult::Established { outbound })
        }
    }

    fn is_established(&self) -> bool {
        !self.conn.is_handshaking()
    }

    fn verify_server_identity(&self, expected_server_name: &ServerName<'_>) -> Result<()> {
        let certs = self
            .conn
            .peer_certificates()
            .ok_or_else(|| anyhow!("missing tls peer certificate"))?;
        let cert = certs
            .first()
            .ok_or_else(|| anyhow!("missing tls peer certificate"))?;
        verify_tls_server_cert(cert.as_ref(), expected_server_name)
    }

    fn protect_application_data(&mut self, plaintext: &[u8]) -> Result<Bytes> {
        if self.conn.is_handshaking() {
            bail!("peap tls tunnel is not ready");
        }
        self.conn
            .writer()
            .write_all(plaintext)
            .context("peap tls write failed")?;
        take_outbound(&mut self.conn)
    }

    fn unprotect_application_data(&mut self, record: &[u8]) -> Result<Bytes> {
        if self.conn.is_handshaking() {
            bail!("peap tls tunnel is not ready");
        }
        self.conn
            .read_tls(&mut Cursor::new(record))
            .context("read inbound peap tls application data")?;
        self.conn
            .process_new_packets()
            .context("process inbound peap tls application data")?;

        let mut plaintext = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match self.conn.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => plaintext.extend_from_slice(&buf[..n]),
                Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                Err(err) => return Err(anyhow!("peap tls read failed: {err}")),
            }
        }
        Ok(Bytes::from(plaintext))
    }

    fn export_eap_msk(&self) -> Result<Option<Box<[u8]>>> {
        if self.conn.is_handshaking() {
            return Ok(None);
        }

        if crate::debug_fmt::ike_enabled() {
            if let Some(version) = self.conn.protocol_version() {
                log::debug!("[IKE] peap tls version {}", protocol_version_name(version));
            }
            if let Some(cipher_suite) = self.conn.negotiated_cipher_suite() {
                log::debug!("[IKE] peap tls cipher {:?}", cipher_suite.suite());
            }
            if let Some(certs) = self.conn.peer_certificates()
                && let Some(cert) = certs.first()
            {
                log::debug!("[IKE] peap tls peer cert sha256 {}", cert_sha256_hex(cert.as_ref()));
            }
        }

        let msk = match self.conn.protocol_version() {
            Some(ProtocolVersion::TLSv1_3) => match self.exporter_mode {
                TlsExporterMode::Rfc => {
                    log::debug!("[IKE] peap tls13 exporter mode rfc");
                    export_tls13_eap_msk(&self.conn)?
                }
                TlsExporterMode::StrongswanCompat => {
                    log::debug!("[IKE] peap tls13 exporter mode strongswan-compat");
                    export_tls13_eap_msk_strongswan_compat(&self.conn)?
                }
            },
            _ => export_tls12_eap_msk(&self.conn)?,
        };
        crate::debug_fmt::log_auth_bytes("peap exported msk =>", msk.as_ref());
        Ok(Some(msk))
    }
}

fn take_outbound(conn: &mut ClientConnection) -> Result<Bytes> {
    let mut out = Vec::new();
    while conn.wants_write() {
        let written = conn.write_tls(&mut out).context("write outbound peap tls bytes")?;
        if written == 0 {
            break;
        }
    }
    Ok(Bytes::from(out))
}

fn export_tls12_eap_msk(conn: &ClientConnection) -> Result<Box<[u8]>> {
    let mut msk = [0u8; 64];
    conn.export_keying_material(&mut msk, b"client EAP encryption", None)
        .context("export TLS<=1.2 EAP-MSK")?;
    crate::debug_fmt::log_auth_bytes("peap tls12 exported keymat128 =>", &msk);
    Ok(msk.to_vec().into_boxed_slice())
}

fn export_tls13_eap_msk(conn: &ClientConnection) -> Result<Box<[u8]>> {
    let mut keymat = [0u8; 128];
    conn.export_keying_material(
        &mut keymat,
        b"EXPORTER_EAP_TLS_Key_Material",
        Some(&[25u8]),
    )
    .context("export TLS1.3 EAP keying material")?;
    crate::debug_fmt::log_auth_bytes("peap tls13 exported keymat128 =>", &keymat);
    Ok(keymat[..64].to_vec().into_boxed_slice())
}

fn export_tls13_eap_msk_strongswan_compat(conn: &ClientConnection) -> Result<Box<[u8]>> {
    let mut keymat = [0u8; 128];
    conn.export_keying_material(&mut keymat, b"client EAP encryption", None)
        .context("export TLS1.3 strongSwan-compatible EAP keying material")?;
    crate::debug_fmt::log_auth_bytes("peap tls13 strongswan keymat128 =>", &keymat);
    Ok(keymat[..64].to_vec().into_boxed_slice())
}

fn protocol_version_name(version: ProtocolVersion) -> &'static str {
    match version {
        ProtocolVersion::TLSv1_2 => "TLSv1.2",
        ProtocolVersion::TLSv1_3 => "TLSv1.3",
        _ => "unknown",
    }
}
