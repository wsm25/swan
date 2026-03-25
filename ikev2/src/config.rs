use crate::IKEV2_NAT_T_PORT;
use anyhow::{Result, anyhow, bail, ensure};
use phf::phf_map;
use smallvec::SmallVec;
use std::net::{IpAddr, SocketAddr};

use crate::cipher::*;

#[derive(Clone)]
pub enum PeerAddress {
    Ip(SocketAddr),
    Domain(String),
}

#[derive(Clone)]
pub struct Ikev2Config {
    pub ike_suite: Vec<CipherSuite>,
    pub esp_suite: Vec<CipherSuite>,
    pub peer: PeerAddress,
    pub idi: String,
    pub eap_identity: String,
    pub eap_password: String,
    pub eap_method: String,
    pub aaa_identity: String,
    pub peap_fragment_size: usize,
    pub peap_max_message_count: usize,
    pub peap_include_length: bool,
    pub peap_tls13_strongswan_compat: bool,
    // Expected responder IKE identity (strongSwan rightid / swanctl remote.id).
    // None means wildcard matching ("%any"-like behavior).
    pub rightid: Option<String>,
}

#[derive(Default)]
pub struct Ikev2ConfigBuilder {
    ike_suite: Option<Vec<CipherSuite>>,
    esp_suite: Option<Vec<CipherSuite>>,
    peer: Option<PeerAddress>,
    idi: Option<String>,
    eap_identity: Option<String>,
    eap_password: Option<String>,
    eap_method: Option<String>,
    aaa_identity: Option<String>,
    peap_fragment_size: Option<usize>,
    peap_max_message_count: Option<usize>,
    peap_include_length: Option<bool>,
    peap_tls13_strongswan_compat: Option<bool>,
    rightid: Option<String>,
}

impl Ikev2Config {
    pub fn builder() -> Ikev2ConfigBuilder {
        Ikev2ConfigBuilder::default()
    }
}

impl Ikev2ConfigBuilder {
    const DEFAULT_PEAP_FRAGMENT_SIZE: usize = 1024;
    const DEFAULT_PEAP_MAX_MESSAGE_COUNT: usize = 32;
    const DEFAULT_PEAP_INCLUDE_LENGTH: bool = false;
    const DEFAULT_PEAP_TLS13_STRONGSWAN_COMPAT: bool = false;
    const DEFAULT_EAP_METHOD: &'static str = "peap";

    pub fn ike_suite(mut self, suite: impl IntoIterator<Item = CipherSuite>) -> Self {
        let suite: Vec<CipherSuite> = suite.into_iter().collect();
        self.ike_suite = Some(suite);
        self
    }

    pub fn ike_suite_strongswan(mut self, suite: &str) -> Result<Self> {
        self.ike_suite = Some(CipherSuite::parse_strongswan_suites(suite)?);
        Ok(self)
    }

    pub fn esp_suite(mut self, suite: impl IntoIterator<Item = CipherSuite>) -> Self {
        let suite: Vec<CipherSuite> = suite.into_iter().collect();
        self.esp_suite = Some(suite);
        self
    }

    pub fn esp_suite_strongswan(mut self, suite: &str) -> Result<Self> {
        self.esp_suite = Some(CipherSuite::parse_strongswan_suites(suite)?);
        Ok(self)
    }

    pub fn peer_ip(mut self, ip: IpAddr) -> Self {
        self.peer = Some(PeerAddress::Ip(SocketAddr::new(ip, IKEV2_NAT_T_PORT)));
        self
    }

    pub fn peer_domain(mut self, domain: impl Into<String>) -> Result<Self> {
        let domain = domain.into();
        ensure!(!domain.is_empty(), "peer domain must not be empty");
        self.peer = Some(PeerAddress::Domain(domain));
        Ok(self)
    }

    pub fn idi(mut self, value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        ensure!(!value.is_empty(), "idi must not be empty");
        self.idi = Some(value);
        Ok(self)
    }

    pub fn eap_identity(mut self, value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        ensure!(!value.is_empty(), "eap_identity must not be empty");
        self.eap_identity = Some(value);
        Ok(self)
    }

    pub fn eap_password(mut self, value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        ensure!(!value.is_empty(), "eap_password must not be empty");
        self.eap_password = Some(value);
        Ok(self)
    }

    pub fn eap_method(mut self, value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let value = value.trim().to_ascii_lowercase();
        ensure!(!value.is_empty(), "eap_method must not be empty");
        ensure!(value == "peap", "fixed MVP profile requires eap_method=peap, got {value}");
        self.eap_method = Some(value);
        Ok(self)
    }

    pub fn aaa_identity(mut self, value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        ensure!(!value.is_empty(), "aaa_identity must not be empty");
        self.aaa_identity = Some(value);
        Ok(self)
    }

    pub fn peap_fragment_size(mut self, value: usize) -> Result<Self> {
        ensure!(value > 0, "peap_fragment_size must be > 0");
        self.peap_fragment_size = Some(value);
        Ok(self)
    }

    pub fn peap_max_message_count(mut self, value: usize) -> Self {
        self.peap_max_message_count = Some(value);
        self
    }

    pub fn peap_include_length(mut self, value: bool) -> Self {
        self.peap_include_length = Some(value);
        self
    }

    pub fn peap_tls13_strongswan_compat(mut self, value: bool) -> Self {
        self.peap_tls13_strongswan_compat = Some(value);
        self
    }

    pub fn rightid(mut self, value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let value = value.trim();
        ensure!(!value.is_empty(), "rightid must not be empty");
        if let Some(dn) = value.strip_prefix('=') {
            ensure!(!dn.is_empty(), "rightid DN value must not be empty");
        }
        if let Some(dn) = value.strip_prefix("dn:") {
            ensure!(!dn.is_empty(), "rightid DN value must not be empty");
        }
        if let Some(key_id) = value.strip_prefix("#") {
            ensure!(!key_id.is_empty(), "rightid KEY_ID value must not be empty");
        }
        if let Some(key_id) = value.strip_prefix("@#") {
            ensure!(!key_id.is_empty(), "rightid KEY_ID value must not be empty");
        }
        if let Some(key_id) = value.strip_prefix("keyid:") {
            ensure!(!key_id.is_empty(), "rightid KEY_ID value must not be empty");
        }
        if let Some(fqdn) = value.strip_prefix('@') {
            ensure!(!fqdn.is_empty(), "rightid fqdn value must not be empty");
        }
        self.rightid = if matches!(value, "%any" | "*") { None } else { Some(value.to_string()) };
        Ok(self)
    }

    pub fn build(self) -> Result<Ikev2Config> {
        let ike_suite = self.ike_suite.ok_or_else(|| anyhow!("ike_suite is required"))?;
        ensure!(!ike_suite.is_empty(), "ike_suite must not be empty");
        let esp_suite = self.esp_suite.ok_or_else(|| anyhow!("esp_suite is required"))?;
        ensure!(!esp_suite.is_empty(), "esp_suite must not be empty");
        let eap_identity = self.eap_identity.ok_or_else(|| anyhow!("eap_identity is required"))?;
        Ok(Ikev2Config {
            ike_suite,
            esp_suite,
            peer: self.peer.ok_or_else(|| anyhow!("peer is required"))?,
            idi: self.idi.unwrap_or_else(|| eap_identity.clone()),
            eap_identity,
            eap_password: self.eap_password.ok_or_else(|| anyhow!("eap_password is required"))?,
            eap_method: self.eap_method.unwrap_or_else(|| Self::DEFAULT_EAP_METHOD.to_string()),
            aaa_identity: self.aaa_identity.ok_or_else(|| anyhow!("aaa_identity is required"))?,
            peap_fragment_size: self.peap_fragment_size.unwrap_or(Self::DEFAULT_PEAP_FRAGMENT_SIZE),
            peap_max_message_count: self
                .peap_max_message_count
                .unwrap_or(Self::DEFAULT_PEAP_MAX_MESSAGE_COUNT),
            peap_include_length: self
                .peap_include_length
                .unwrap_or(Self::DEFAULT_PEAP_INCLUDE_LENGTH),
            peap_tls13_strongswan_compat: self
                .peap_tls13_strongswan_compat
                .unwrap_or(Self::DEFAULT_PEAP_TLS13_STRONGSWAN_COMPAT),
            rightid: self.rightid,
        })
    }
}

// cipher

#[derive(Clone, Debug)]
pub struct CipherSuite {
    pub encryption: SmallVec<[EncryptionAlgID; 2]>,
    pub integrity: SmallVec<[IntegrityAlgID; 2]>,
    pub prf: SmallVec<[PrfAlgID; 2]>,
    pub dh: SmallVec<[DhAlgID; 2]>,
}

#[derive(Clone)]
pub struct CipherSuiteSelection {
    pub encryption: &'static EncryptionAlg,
    pub integrity: &'static IntegrityAlg,
    pub prf: &'static PrfAlg,
    pub dh: &'static DhAlg,
}

impl CipherSuite {
    pub fn parse_strongswan(value: &str) -> Result<Self> {
        let mut encryption = SmallVec::<[EncryptionAlgID; 2]>::new();
        let mut integrity = SmallVec::<[IntegrityAlgID; 2]>::new();
        let mut prf = SmallVec::<[PrfAlgID; 2]>::new();
        let mut dh = SmallVec::<[DhAlgID; 2]>::new();

        fn push_unique<T: Copy + Eq, const N: usize>(values: &mut SmallVec<[T; N]>, value: T) {
            if !values.contains(&value) {
                values.push(value);
            }
        }
        for token in value.split('-').filter(|token| !token.is_empty()) {
            if let Some(v) = ENCRYPTION_TABLE.get(token).copied() {
                push_unique(&mut encryption, v);
                continue;
            }
            if let Some(v) = INTEGRITY_TABLE.get(token).copied() {
                push_unique(&mut integrity, v);
                continue;
            }
            if let Some(v) = PRF_TABLE.get(token).copied() {
                push_unique(&mut prf, v);
                continue;
            }
            if let Some(v) = DH_ALG_TABLE.get(token).copied() {
                push_unique(&mut dh, v);
                continue;
            }
            bail!("unsupported strongSwan proposal token: {token}");
        }

        ensure!(!encryption.is_empty(), "missing encryption algorithm: {value}");
        ensure!(!integrity.is_empty(), "missing integrity algorithm: {value}");
        ensure!(!dh.is_empty(), "missing DH group: {value}");

        if prf.is_empty() {
            for v in &integrity {
                push_unique(&mut prf, prf_alg_from_integrity_alg(*v));
            }
        }

        Ok(Self { encryption, integrity, prf, dh })
    }

    pub fn parse_strongswan_suites(value: &str) -> Result<Vec<Self>> {
        let mut suites = Vec::new();
        for suite in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            suites.push(Self::parse_strongswan(suite)?);
        }
        ensure!(!suites.is_empty(), "missing cipher suite proposal: {value}");
        Ok(suites)
    }

    pub fn select(&self, remote: &CipherSuite) -> Result<CipherSuiteSelection> {
        macro_rules! select_one {
            ($algs:ident, $local:expr, $remote:expr) => {{
                let selected =
                    $local.iter().find(|candidate| $remote.contains(*candidate)).ok_or_else(
                        || anyhow!("no compatible {} algorithm found", stringify!($algs)),
                    )?;
                $algs.get(selected).ok_or_else(|| {
                    anyhow!("({}) local selection {:?} not supported", stringify!($algs), selected)
                })?
            }};
        }
        Ok(CipherSuiteSelection {
            encryption: select_one!(ENCRYPTION_ALGS, &self.encryption, &remote.encryption),
            integrity: select_one!(INTEGRITY_ALGS, &self.integrity, &remote.integrity),
            prf: select_one!(PRF_ALGS, &self.prf, &remote.prf),
            dh: select_one!(DH_ALGS, &self.dh, &remote.dh),
        })
    }
}

static ENCRYPTION_TABLE: phf::Map<&'static str, EncryptionAlgID> = phf_map! {
    "aes" => (ENCR_AES_CBC, 16),
    "aes128" => (ENCR_AES_CBC, 16),
    "aes256" => (ENCR_AES_CBC, 32),
};

static INTEGRITY_TABLE: phf::Map<&'static str, IntegrityAlgID> = phf_map! {
    "sha" => AUTH_HMAC_SHA1_96,
    "sha1" => AUTH_HMAC_SHA1_96,
    "sha2_256" => AUTH_HMAC_SHA2_256_128,
    "sha256" => AUTH_HMAC_SHA2_256_128,
    "sha2_512" => AUTH_HMAC_SHA2_512_256,
    "sha512" => AUTH_HMAC_SHA2_512_256,
};

static PRF_TABLE: phf::Map<&'static str, PrfAlgID> = phf_map! {
    "prfsha1" => PRF_HMAC_SHA1,
    "prfsha256" => PRF_HMAC_SHA2_256,
    "prfsha2_256" => PRF_HMAC_SHA2_256,
    "prfsha512" => PRF_HMAC_SHA2_256,
    "prfsha2_512" => PRF_HMAC_SHA2_512,
};

static DH_ALG_TABLE: phf::Map<&'static str, DhAlgID> = phf_map! {
    "modp1024" => DH_MODP_1024,
    "curve25519" => DH_CURVE_25519,
};

fn prf_alg_from_integrity_alg(value: IntegrityAlgID) -> PrfAlgID {
    // TODO: phf
    match value {
        AUTH_HMAC_SHA1_96 => PRF_HMAC_SHA1,
        AUTH_HMAC_SHA2_256_128 => PRF_HMAC_SHA2_256,
        AUTH_HMAC_SHA2_512_256 => PRF_HMAC_SHA2_512,
        _ => PRF_HMAC_SHA1,
    }
}
