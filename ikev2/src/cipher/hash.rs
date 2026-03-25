use ring::digest;

pub struct DigestBytes(Box<[u8]>);

impl DigestBytes {
    fn new(value: digest::Digest) -> Self {
        Self(value.as_ref().to_vec().into_boxed_slice())
    }
}

impl AsRef<[u8]> for DigestBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::ops::Deref for DigestBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

pub struct Hasher {
    kind: HashKind,
    algorithm: &'static digest::Algorithm,
}

impl Hasher {
    pub const fn new(kind: HashKind, algorithm: &'static digest::Algorithm) -> Self {
        Self { kind, algorithm }
    }

    pub const fn kind(&self) -> HashKind {
        self.kind
    }

    pub fn output_len(&self) -> usize {
        self.algorithm.output_len()
    }

    pub fn digest(&self, data: &[u8]) -> DigestBytes {
        DigestBytes::new(digest::digest(self.algorithm, data))
    }

    pub fn context(&self) -> HashContext {
        HashContext { context: digest::Context::new(self.algorithm) }
    }
}

pub struct HashContext {
    context: digest::Context,
}

impl HashContext {
    pub fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    pub fn chain_update(mut self, data: impl AsRef<[u8]>) -> Self {
        self.update(data.as_ref());
        self
    }

    pub fn finalize(self) -> DigestBytes {
        DigestBytes::new(self.context.finish())
    }
}

pub struct Sha1;
pub struct Sha256;
pub struct Sha384;
pub struct Sha512;

pub const SHA1_HASHER: Hasher = Hasher::new(HashKind::Sha1, &digest::SHA1_FOR_LEGACY_USE_ONLY);
pub const SHA256_HASHER: Hasher = Hasher::new(HashKind::Sha256, &digest::SHA256);
pub const SHA384_HASHER: Hasher = Hasher::new(HashKind::Sha384, &digest::SHA384);
pub const SHA512_HASHER: Hasher = Hasher::new(HashKind::Sha512, &digest::SHA512);

impl Sha1 {
    pub fn begin() -> HashContext {
        SHA1_HASHER.context()
    }

    pub fn digest(data: &[u8]) -> DigestBytes {
        SHA1_HASHER.digest(data)
    }
}

impl Sha256 {
    pub fn begin() -> HashContext {
        SHA256_HASHER.context()
    }

    pub fn digest(data: &[u8]) -> DigestBytes {
        SHA256_HASHER.digest(data)
    }
}

impl Sha384 {
    pub fn begin() -> HashContext {
        SHA384_HASHER.context()
    }
}

impl Sha512 {
    pub fn begin() -> HashContext {
        SHA512_HASHER.context()
    }
}

pub fn sha1() -> Box<Hasher> {
    Box::new(Hasher::new(HashKind::Sha1, &digest::SHA1_FOR_LEGACY_USE_ONLY))
}

pub fn sha256() -> Box<Hasher> {
    Box::new(Hasher::new(HashKind::Sha256, &digest::SHA256))
}

pub fn sha384() -> Box<Hasher> {
    Box::new(Hasher::new(HashKind::Sha384, &digest::SHA384))
}

pub fn sha512() -> Box<Hasher> {
    Box::new(Hasher::new(HashKind::Sha512, &digest::SHA512))
}
