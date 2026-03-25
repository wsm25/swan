use anyhow::{Context, Result, anyhow, bail, ensure};
use bytes::Bytes;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::ssl::{
    HandshakeError, MidHandshakeSslStream, SslConnector, SslMethod, SslOptions, SslStream,
    SslVerifyMode,
};
use openssl::x509::X509Ref;
use std::collections::VecDeque;
use std::io::{Error as IoError, ErrorKind, Read, Write};

use super::identity::verify_presented_identity;

pub(crate) enum PeapTlsStep {
    NeedMoreData,
    Outbound(Bytes),
    TunnelReady,
}

pub(crate) trait PeapTlsBackend {
    fn start_client_hello(&mut self) -> Result<Bytes>;
    fn on_tls_record(&mut self, record: &[u8]) -> Result<PeapTlsStep>;
    fn is_tunnel_ready(&self) -> bool;
    fn verify_server_identity(&self, expected_aaa_identity: &str) -> Result<()>;
    fn protect_tunnel_data(&mut self, plaintext: &[u8]) -> Result<Bytes>;
    fn unprotect_tunnel_data(&mut self, record: &[u8]) -> Result<Bytes>;
    fn export_eap_msk(&self) -> Result<Option<Box<[u8]>>>;
    fn reset(&mut self);
}

#[derive(Debug, Default)]
struct PeapTlsIo {
    inbound: VecDeque<u8>,
    outbound: Vec<u8>,
}

impl PeapTlsIo {
    fn push_inbound(&mut self, data: &[u8]) {
        self.inbound.extend(data.iter().copied());
    }

    fn take_outbound(&mut self) -> Bytes {
        if self.outbound.is_empty() {
            return Bytes::new();
        }
        let mut out = Vec::new();
        std::mem::swap(&mut out, &mut self.outbound);
        Bytes::from(out)
    }
}

impl Read for PeapTlsIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.inbound.is_empty() {
            return Err(IoError::new(ErrorKind::WouldBlock, "no inbound tls bytes"));
        }
        let mut n = 0usize;
        while n < buf.len() {
            let Some(byte) = self.inbound.pop_front() else {
                break;
            };
            buf[n] = byte;
            n += 1;
        }
        Ok(n)
    }
}

impl Write for PeapTlsIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.outbound.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

enum OpenSslSessionState {
    Handshaking(MidHandshakeSslStream<PeapTlsIo>),
    Established(SslStream<PeapTlsIo>),
}

pub(crate) struct OpenSslPeapTlsBackend {
    connector: SslConnector,
    server_name: String,
    tls13_strongswan_compat: bool,
    state: Option<OpenSslSessionState>,
    ready_notified: bool,
}

impl OpenSslPeapTlsBackend {
    const GLOBAL_SKIP_CERT_VERIFY_ENV: &'static str = "SWAN_INSECURE_SKIP_PEER_CERT_CHAIN_VERIFY";
    const CERT_SHA256_PIN_ENV: &'static str = "SWAN_PEAP_SERVER_CERT_SHA256";
    const ALLOW_LEGACY_RENEGOTIATION_ENV: &'static str =
        "SWAN_PEAP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION";
    const SKIP_CERT_VERIFY_ENV: &'static str = "SWAN_PEAP_INSECURE_SKIP_CERT_VERIFY";

    pub(crate) fn new(server_name: String, tls13_strongswan_compat: bool) -> Result<Self> {
        let mut builder = SslConnector::builder(SslMethod::tls_client()).context("ssl init")?;
        if Self::skip_cert_verify_enabled()? {
            builder.set_verify(SslVerifyMode::NONE);
        } else {
            builder.set_verify(SslVerifyMode::PEER);
            builder.set_default_verify_paths().context("load default TLS verify paths")?;
            builder
                .set_ca_file("/etc/ssl/cert.pem")
                .context("load TLS CA file /etc/ssl/cert.pem")?;
        }
        if Self::env_enabled(Self::ALLOW_LEGACY_RENEGOTIATION_ENV)? {
            builder.set_options(SslOptions::ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
        }
        let connector = builder.build();
        let server_name = server_name.trim().trim_start_matches('@').to_string();
        ensure!(!server_name.is_empty(), "peap server name must not be empty");
        Ok(Self {
            connector,
            server_name,
            tls13_strongswan_compat,
            state: None,
            ready_notified: false,
        })
    }

    fn handle_handshake_error<S: std::fmt::Debug>(
        context: &str,
        err: HandshakeError<S>,
    ) -> anyhow::Error {
        anyhow!("{context}: {err}")
    }

    fn normalize_hex_pin(value: &str) -> Option<String> {
        let compact: String = value.chars().filter(|ch| ch.is_ascii_hexdigit()).collect();
        if compact.is_empty() || !compact.len().is_multiple_of(2) {
            return None;
        }
        Some(compact.to_ascii_lowercase())
    }

    fn env_enabled(key: &str) -> Result<bool> {
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

    fn cert_sha256_hex(cert: &X509Ref) -> Result<String> {
        let digest = cert.digest(MessageDigest::sha256()).context("compute cert SHA-256 digest")?;
        let mut out = String::with_capacity(digest.len() * 2);
        for byte in digest.as_ref() {
            use std::fmt::Write as _;
            let _ = write!(&mut out, "{byte:02x}");
        }
        Ok(out)
    }

    fn verify_cert_pin(cert: &X509Ref) -> Result<()> {
        let Some(expected_raw) = std::env::var_os(Self::CERT_SHA256_PIN_ENV) else {
            return Ok(());
        };
        let expected_raw = expected_raw
            .to_str()
            .ok_or_else(|| anyhow!("{} contains non-utf8 bytes", Self::CERT_SHA256_PIN_ENV))?;
        let expected = Self::normalize_hex_pin(expected_raw).ok_or_else(|| {
            anyhow!("{} must be a SHA-256 hex string (colons optional)", Self::CERT_SHA256_PIN_ENV)
        })?;
        let actual = Self::cert_sha256_hex(cert)?;
        ensure!(
            actual == expected,
            "tls server certificate pin mismatch: expected {expected}, got {actual}"
        );
        Ok(())
    }

    fn skip_cert_verify_enabled() -> Result<bool> {
        Ok(Self::env_enabled(Self::SKIP_CERT_VERIFY_ENV)?
            || Self::env_enabled(Self::GLOBAL_SKIP_CERT_VERIFY_ENV)?)
    }

    fn export_tls12_eap_msk(ssl: &openssl::ssl::SslRef) -> Result<Box<[u8]>> {
        let mut msk = [0u8; 64];
        ssl.export_keying_material(&mut msk, "client EAP encryption", None)
            .context("export TLS<=1.2 EAP-MSK")?;
        crate::debug_fmt::log_auth_bytes("peap tls12 exported keymat128 =>", &msk);
        Ok(msk.to_vec().into_boxed_slice())
    }

    fn export_tls13_eap_msk(ssl: &openssl::ssl::SslRef) -> Result<Box<[u8]>> {
        let mut keymat = [0u8; 128];
        let eap_type_context = [25u8];
        ssl.export_keying_material(
            &mut keymat,
            "EXPORTER_EAP_TLS_Key_Material",
            Some(&eap_type_context),
        )
        .context("export TLS1.3 EAP keying material")?;
        crate::debug_fmt::log_auth_bytes("peap tls13 exported keymat128 =>", &keymat);
        Ok(keymat[..64].to_vec().into_boxed_slice())
    }

    fn export_tls13_eap_msk_strongswan_compat(ssl: &openssl::ssl::SslRef) -> Result<Box<[u8]>> {
        let mut keymat = [0u8; 128];
        ssl.export_keying_material(&mut keymat, "client EAP encryption", None)
            .context("export TLS1.3 strongSwan-compatible EAP keying material")?;
        crate::debug_fmt::log_auth_bytes("peap tls13 strongswan keymat128 =>", &keymat);
        Ok(keymat[..64].to_vec().into_boxed_slice())
    }
}

impl PeapTlsBackend for OpenSslPeapTlsBackend {
    fn start_client_hello(&mut self) -> Result<Bytes> {
        ensure!(self.state.is_none(), "peap tls backend already started");
        let config = self.connector.configure().context("ssl configure")?;
        let ssl = config
            .into_ssl(&self.server_name)
            .with_context(|| format!("ssl create for {}", self.server_name))?;
        match ssl.connect(PeapTlsIo::default()) {
            Ok(mut stream) => {
                let outbound = stream.get_mut().take_outbound();
                self.state = Some(OpenSslSessionState::Established(stream));
                self.ready_notified = false;
                Ok(outbound)
            }
            Err(HandshakeError::WouldBlock(mut mid)) => {
                let outbound = mid.get_mut().take_outbound();
                self.state = Some(OpenSslSessionState::Handshaking(mid));
                self.ready_notified = false;
                Ok(outbound)
            }
            Err(err) => Err(Self::handle_handshake_error("peap tls handshake start failed", err)),
        }
    }

    fn on_tls_record(&mut self, record: &[u8]) -> Result<PeapTlsStep> {
        let state = self.state.take().ok_or_else(|| anyhow!("peap tls backend not started"))?;
        match state {
            OpenSslSessionState::Handshaking(mut mid) => {
                mid.get_mut().push_inbound(record);
                match mid.handshake() {
                    Ok(mut stream) => {
                        let outbound = stream.get_mut().take_outbound();
                        self.state = Some(OpenSslSessionState::Established(stream));
                        self.ready_notified = true;
                        if !outbound.is_empty() {
                            Ok(PeapTlsStep::Outbound(outbound))
                        } else {
                            Ok(PeapTlsStep::TunnelReady)
                        }
                    }
                    Err(HandshakeError::WouldBlock(mut mid)) => {
                        let outbound = mid.get_mut().take_outbound();
                        self.state = Some(OpenSslSessionState::Handshaking(mid));
                        if outbound.is_empty() {
                            Ok(PeapTlsStep::NeedMoreData)
                        } else {
                            Ok(PeapTlsStep::Outbound(outbound))
                        }
                    }
                    Err(err) => Err(Self::handle_handshake_error("peap tls handshake failed", err)),
                }
            }
            OpenSslSessionState::Established(mut stream) => {
                stream.get_mut().push_inbound(record);
                let outbound = stream.get_mut().take_outbound();
                self.state = Some(OpenSslSessionState::Established(stream));
                if !outbound.is_empty() {
                    Ok(PeapTlsStep::Outbound(outbound))
                } else if !self.ready_notified {
                    self.ready_notified = true;
                    Ok(PeapTlsStep::TunnelReady)
                } else {
                    Ok(PeapTlsStep::NeedMoreData)
                }
            }
        }
    }

    fn is_tunnel_ready(&self) -> bool {
        matches!(self.state, Some(OpenSslSessionState::Established(_)))
    }

    fn verify_server_identity(&self, expected_aaa_identity: &str) -> Result<()> {
        let state = self.state.as_ref().ok_or_else(|| anyhow!("peap tls backend not started"))?;
        let ssl = match state {
            OpenSslSessionState::Handshaking(mid) => mid.ssl(),
            OpenSslSessionState::Established(stream) => stream.ssl(),
        };
        let cert = ssl.peer_certificate().ok_or_else(|| anyhow!("missing tls peer certificate"))?;
        Self::verify_cert_pin(&cert)?;
        let dns_sans: Vec<String> = cert
            .subject_alt_names()
            .map(|names| {
                names.iter().filter_map(|name| name.dnsname().map(ToString::to_string)).collect()
            })
            .unwrap_or_default();
        let common_name = cert
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .and_then(|entry| entry.data().as_utf8().ok().map(|value| value.to_string()));
        verify_presented_identity(expected_aaa_identity, &dns_sans, common_name.as_deref())
    }

    fn protect_tunnel_data(&mut self, plaintext: &[u8]) -> Result<Bytes> {
        let state = self.state.as_mut().ok_or_else(|| anyhow!("peap tls backend not started"))?;
        let stream = match state {
            OpenSslSessionState::Handshaking(_) => bail!("peap tls tunnel is not ready"),
            OpenSslSessionState::Established(stream) => stream,
        };
        ensure!(self.ready_notified, "peap tls tunnel is not ready");
        stream.write_all(plaintext).context("peap tls write failed")?;
        Ok(stream.get_mut().take_outbound())
    }

    fn unprotect_tunnel_data(&mut self, record: &[u8]) -> Result<Bytes> {
        let state = self.state.as_mut().ok_or_else(|| anyhow!("peap tls backend not started"))?;
        let stream = match state {
            OpenSslSessionState::Handshaking(_) => bail!("peap tls tunnel is not ready"),
            OpenSslSessionState::Established(stream) => stream,
        };
        ensure!(self.ready_notified, "peap tls tunnel is not ready");
        stream.get_mut().push_inbound(record);
        let mut plaintext = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => plaintext.extend_from_slice(&buf[..n]),
                Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                Err(err) => return Err(anyhow!("peap tls read failed: {err}")),
            }
        }
        Ok(Bytes::from(plaintext))
    }

    fn export_eap_msk(&self) -> Result<Option<Box<[u8]>>> {
        if !self.ready_notified {
            return Ok(None);
        }
        let state = self.state.as_ref().ok_or_else(|| anyhow!("peap tls backend not started"))?;
        let ssl = match state {
            OpenSslSessionState::Handshaking(_) => bail!("peap tls tunnel is not ready"),
            OpenSslSessionState::Established(stream) => stream.ssl(),
        };
        if crate::debug_fmt::ike_enabled() {
            log::debug!("[IKE] peap tls version {}", ssl.version_str());
            if let Some(cipher) = ssl.current_cipher() {
                log::debug!("[IKE] peap tls cipher {}", cipher.name());
            }
        }
        let msk = if ssl.version_str() == "TLSv1.3" {
            if self.tls13_strongswan_compat {
                log::debug!("[IKE] peap tls13 exporter mode strongswan-compat");
                Self::export_tls13_eap_msk_strongswan_compat(ssl)?
            } else {
                log::debug!("[IKE] peap tls13 exporter mode rfc");
                Self::export_tls13_eap_msk(ssl)?
            }
        } else {
            Self::export_tls12_eap_msk(ssl)?
        };
        crate::debug_fmt::log_auth_bytes("peap exported msk =>", msk.as_ref());
        Ok(Some(msk))
    }

    fn reset(&mut self) {
        self.state = None;
        self.ready_notified = false;
    }
}
