use anyhow::Result;
use bytes::Bytes;
use rustls_pki_types::ServerName;

use crate::cipher::{
    TlsBackend, TlsClientConfig, TlsExporterMode, TlsHandshakeResult, TlsSession, rustls_tls_backend,
};

pub(crate) enum PeapTlsStep {
    NeedMoreData,
    Outbound(Bytes),
    TunnelReady,
}

pub(crate) trait PeapTlsBackend: Send {
    fn start_client_hello(&mut self) -> Result<Bytes>;
    fn on_tls_record(&mut self, record: &[u8]) -> Result<PeapTlsStep>;
    fn is_tunnel_ready(&self) -> bool;
    fn verify_server_identity(&self, expected_aaa_identity: &str) -> Result<()>;
    fn protect_tunnel_data(&mut self, plaintext: &[u8]) -> Result<Bytes>;
    fn unprotect_tunnel_data(&mut self, record: &[u8]) -> Result<Bytes>;
    fn export_eap_msk(&self) -> Result<Option<Box<[u8]>>>;
    fn reset(&mut self);
}

pub(crate) struct BackendPeapTls {
    backend: Box<dyn TlsBackend>,
    config: TlsClientConfig,
    session: Option<Box<dyn TlsSession>>,
}

impl BackendPeapTls {
    pub(crate) fn new(server_name: String, strongswan_compatible: bool) -> Result<Self> {
        let server_name = ServerName::try_from(server_name.trim().trim_start_matches('@').to_string())
            .map_err(|_| anyhow::anyhow!("invalid tls server name"))?;
        Ok(Self {
            backend: rustls_tls_backend()?,
            config: TlsClientConfig {
                server_name,
                exporter_mode: if strongswan_compatible {
                    TlsExporterMode::StrongswanCompat
                } else {
                    TlsExporterMode::Rfc
                },
            },
            session: None,
        })
    }

    fn session(&self) -> Result<&(dyn TlsSession + '_)> {
        match self.session.as_deref() {
            Some(session) => Ok(session),
            None => Err(anyhow::anyhow!("peap tls backend not started")),
        }
    }

    fn session_mut(&mut self) -> Result<&mut (dyn TlsSession + '_)> {
        match self.session.as_deref_mut() {
            Some(session) => Ok(session),
            None => Err(anyhow::anyhow!("peap tls backend not started")),
        }
    }
}

impl PeapTlsBackend for BackendPeapTls {
    fn start_client_hello(&mut self) -> Result<Bytes> {
        let started = self.backend.start_session(&self.config)?;
        self.session = Some(started.session);
        Ok(started.outbound)
    }

    fn on_tls_record(&mut self, record: &[u8]) -> Result<PeapTlsStep> {
        Ok(match self.session_mut()?.on_record(record)? {
            TlsHandshakeResult::NeedMoreData => PeapTlsStep::NeedMoreData,
            TlsHandshakeResult::Outbound(record) => PeapTlsStep::Outbound(record),
            TlsHandshakeResult::Established { outbound } => {
                if outbound.is_empty() {
                    PeapTlsStep::TunnelReady
                } else {
                    PeapTlsStep::Outbound(outbound)
                }
            }
        })
    }

    fn is_tunnel_ready(&self) -> bool {
        self.session.as_deref().is_some_and(TlsSession::is_established)
    }

    fn verify_server_identity(&self, expected_aaa_identity: &str) -> Result<()> {
        let expected =
            ServerName::try_from(expected_aaa_identity.trim().trim_start_matches('@').to_string())
                .map_err(|_| anyhow::anyhow!("invalid tls server name"))?;
        self.session()?.verify_server_identity(&expected)
    }

    fn protect_tunnel_data(&mut self, plaintext: &[u8]) -> Result<Bytes> {
        self.session_mut()?.protect_application_data(plaintext)
    }

    fn unprotect_tunnel_data(&mut self, record: &[u8]) -> Result<Bytes> {
        self.session_mut()?.unprotect_application_data(record)
    }

    fn export_eap_msk(&self) -> Result<Option<Box<[u8]>>> {
        self.session()?.export_eap_msk()
    }

    fn reset(&mut self) {
        self.session = None;
    }
}
