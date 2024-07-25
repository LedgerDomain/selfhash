use crate::{Hash, HashFunction, Hasher, NamedHashFunction};

/// This represents the SHA_512 hash function itself.  Note that this is distinct from a
/// SHA_512 hasher or a SHA_512_Hash value.
pub struct SHA512;

#[cfg(feature = "sha-512")]
lazy_static::lazy_static! {
    static ref SHA_512_PLACEHOLDER: SHA512Hash = SHA512Hash::from(SHA512HashInner::default());
}

impl HashFunction for SHA512 {
    fn named_hash_function(&self) -> NamedHashFunction {
        NamedHashFunction::SHA_512
    }
    fn keri_prefix(&self) -> &'static str {
        "0G"
    }
    fn placeholder_hash(&self) -> &'static dyn Hash {
        #[cfg(feature = "sha-512")]
        {
            &*SHA_512_PLACEHOLDER
        }
        #[cfg(not(feature = "sha-512"))]
        {
            panic!("programmer error: sha-512 feature not enabled");
        }
    }
    fn new_hasher(&self) -> Box<dyn Hasher> {
        #[cfg(feature = "sha-512")]
        {
            Box::new(sha2::Sha512::default())
        }
        #[cfg(not(feature = "sha-512"))]
        {
            panic!("programmer error: sha-512 feature not enabled");
        }
    }
}

#[cfg(feature = "sha-512")]
impl Hasher for sha2::Sha512 {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
    fn hash_function(&self) -> &dyn HashFunction {
        &SHA512
    }
    fn update(&mut self, byte_v: &[u8]) {
        sha2::Digest::update(self, byte_v);
    }
    fn finalize(self: Box<Self>) -> Box<dyn Hash> {
        Box::new(SHA512Hash::from(sha2::Digest::finalize(*self)))
    }
}

#[cfg(feature = "sha-512")]
pub type SHA512HashInner =
    digest::generic_array::GenericArray<u8, <sha2::Sha512 as digest::OutputSizeUser>::OutputSize>;

/// This is a newtype over the result of sha2::Sha512::finalize because it is just a GenericArray,
/// and that doesn't give semantic distinction over other hash values that may have the same size
/// but mean a different thing.
#[cfg(feature = "sha-512")]
#[derive(Clone, Debug, derive_more::Deref, derive_more::From, Eq, derive_more::Into, PartialEq)]
pub struct SHA512Hash(SHA512HashInner);

#[cfg(feature = "sha-512")]
impl SHA512Hash {
    pub fn into_inner(self) -> SHA512HashInner {
        self.0
    }
}

#[cfg(feature = "sha-512")]
impl Hash for SHA512Hash {
    fn hash_function(&self) -> &dyn HashFunction {
        &SHA512
    }
    fn equals(&self, other: &dyn Hash) -> bool {
        // Check the hash function directly before resorting to converting.
        if !self.hash_function().equals(other.hash_function()) {
            return false;
        }
        // Convert to common type for comparison.
        self.to_hash_bytes() == other.to_hash_bytes()
    }
    /// This won't allocate, since the hash bytes are already in memory.
    fn to_hash_bytes(&self) -> crate::HashBytes {
        crate::HashBytes {
            named_hash_function: self.hash_function().named_hash_function(),
            hash_byte_v: std::borrow::Cow::Borrowed(self.as_slice()),
        }
    }
    /// This will allocate, since the hash bytes have to be converted into a KERIHash.
    fn to_keri_hash(&self) -> crate::KERIHash {
        self.to_hash_bytes()
            .to_keri_hash()
            .expect("programmer error")
    }
}
