use crate::{Hash, HashFunction, Hasher, NamedHashFunction};

/// This represents the SHA_256 hash function itself (from the SHA2 family of hash functions).
/// Note that this is distinct from a SHA_256 hasher or a SHA_256_Hash value.
pub struct SHA256;

#[cfg(feature = "sha-256")]
lazy_static::lazy_static! {
    static ref SHA_256_PLACEHOLDER: SHA256Hash = SHA256Hash::from(SHA256HashInner::default());
}

impl HashFunction for SHA256 {
    fn named_hash_function(&self) -> NamedHashFunction {
        NamedHashFunction::SHA_256
    }
    fn keri_prefix(&self) -> &'static str {
        "I"
    }
    fn placeholder_hash(&self) -> &'static dyn Hash {
        #[cfg(feature = "sha-256")]
        {
            &*SHA_256_PLACEHOLDER
        }
        #[cfg(not(feature = "sha-256"))]
        {
            panic!("programmer error: sha-256 feature not enabled");
        }
    }
    fn new_hasher(&self) -> Box<dyn Hasher> {
        #[cfg(feature = "sha-256")]
        {
            Box::new(sha2::Sha256::default())
        }
        #[cfg(not(feature = "sha-256"))]
        {
            panic!("programmer error: sha-256 feature not enabled");
        }
    }
}

#[cfg(feature = "sha-256")]
impl Hasher for sha2::Sha256 {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
    fn hash_function(&self) -> &dyn HashFunction {
        &SHA256
    }
    fn update(&mut self, byte_v: &[u8]) {
        sha2::Digest::update(self, byte_v);
    }
    fn finalize(self: Box<Self>) -> Box<dyn Hash> {
        Box::new(SHA256Hash::from(sha2::Digest::finalize(*self)))
    }
}

#[cfg(feature = "sha-256")]
pub type SHA256HashInner =
    digest::generic_array::GenericArray<u8, <sha2::Sha256 as digest::OutputSizeUser>::OutputSize>;

/// This is a newtype over the result of sha2::Sha256::finalize because it is just a GenericArray,
/// and that doesn't give semantic distinction over other hash values that may have the same size
/// but mean a different thing.
#[cfg(feature = "sha-256")]
#[derive(Clone, Debug, derive_more::Deref, derive_more::From, Eq, derive_more::Into, PartialEq)]
pub struct SHA256Hash(pub(crate) SHA256HashInner);

#[cfg(feature = "sha-256")]
impl SHA256Hash {
    pub fn into_inner(self) -> SHA256HashInner {
        self.0
    }
}

#[cfg(feature = "sha-256")]
impl Hash for SHA256Hash {
    fn hash_function(&self) -> &'static dyn HashFunction {
        &SHA256
    }
    /// This will not allocate.
    fn as_preferred_hash_format<'s: 'h, 'h>(&'s self) -> crate::PreferredHashFormat<'h> {
        crate::HashBytes {
            named_hash_function: self.hash_function().named_hash_function(),
            hash_byte_v: std::borrow::Cow::Borrowed(self.as_slice()),
        }
        .into()
    }
}
