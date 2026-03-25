use anyhow::{Result, anyhow, ensure};
use ring::{agreement, rand::SystemRandom};

pub type DhAlgID = u16;

pub enum DhKeyPair {
    Curve25519(agreement::EphemeralPrivateKey),
}

pub type SharedSecretFn = fn(keypair: DhKeyPair, peer_public: &[u8]) -> Result<Box<[u8]>>;

pub struct DhAlg {
    pub transform_id: u16,
    pub name: &'static str,
    pub generate_keypair: fn() -> Result<DhKeyPair>,
    pub public_key: fn(keypair: &DhKeyPair) -> Result<Box<[u8]>>,
    pub shared_secret: SharedSecretFn,
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

fn curve25519_generate_keypair() -> Result<DhKeyPair> {
    Ok(DhKeyPair::Curve25519(
        agreement::EphemeralPrivateKey::generate(&agreement::X25519, &SystemRandom::new())
            .map_err(|_| anyhow!("generate X25519 keypair"))?,
    ))
}

fn curve25519_public_key(keypair: &DhKeyPair) -> Result<Box<[u8]>> {
    let DhKeyPair::Curve25519(keypair) = keypair;
    Ok(keypair
        .compute_public_key()
        .map_err(|_| anyhow!("encode X25519 public key"))?
        .as_ref()
        .to_vec()
        .into_boxed_slice())
}

fn curve25519_shared_secret(keypair: DhKeyPair, peer_public: &[u8]) -> Result<Box<[u8]>> {
    let DhKeyPair::Curve25519(keypair) = keypair;
    ensure!(peer_public.len() == 32, "invalid X25519 peer public key");
    let peer_public = agreement::UnparsedPublicKey::new(&agreement::X25519, peer_public);
    agreement::agree_ephemeral(keypair, &peer_public, |shared_secret| {
        shared_secret.to_vec().into_boxed_slice()
    })
    .map_err(|_| anyhow!("derive X25519 shared secret"))
}

fn dummy_generate_keypair() -> Result<DhKeyPair> {
    super::dummy()
}

fn dummy_public_key(_: &DhKeyPair) -> Result<Box<[u8]>> {
    super::dummy()
}

fn dummy_shared_secret(_: DhKeyPair, _: &[u8]) -> Result<Box<[u8]>> {
    super::dummy()
}
