/// For ikev2 algorithms, check https://docs.strongswan.org/docs/latest/config/proposals.html
use anyhow::{Result, bail};
use ring::rand::{SecureRandom, SystemRandom};

pub use hash::*;
pub use hmac::*;
pub use integrity::*;
pub use ke::*;
pub use pkey::*;
pub use prf::*;
pub use symm::*;
pub use tls::*;

mod hash;
mod hmac;
mod integrity;
mod ke;
mod pkey;
mod prf;
mod symm;
mod tls;

pub struct IkeKeyMaterial {
    pub sk_d: Box<[u8]>,
    pub sk_ai: Box<[u8]>,
    pub sk_ar: Box<[u8]>,
    pub sk_ei: Box<[u8]>,
    pub sk_er: Box<[u8]>,
    pub sk_pi: Box<[u8]>,
    pub sk_pr: Box<[u8]>,
}

#[cold]
fn dummy<T>() -> Result<T> {
    bail!("call dummy implement unexpectedly")
}

pub fn rand_bytes(buf: &mut [u8]) {
    SystemRandom::new().fill(buf).expect("ring SystemRandom fill failed");
}
