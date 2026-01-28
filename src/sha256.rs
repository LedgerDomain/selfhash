#[cfg(feature = "sha-256")]
use crate::HashDynT;
use crate::HasherDynT;

#[cfg(feature = "sha-256")]
lazy_static::lazy_static! {
    static ref SHA256_PLACEHOLDER: SHA256Hash = SHA256Hash::from(SHA256HashInner::default());
}

//
// SHA256
//

/// This represents the SHA-256 hash function itself (from the SHA2 family of hash functions).
/// Note that this is distinct from a sha2::Sha256 hasher or a SHA256Hash value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SHA256;

impl SHA256 {
    pub fn new_hasher_dyn() -> Box<dyn HasherDynT> {
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
impl crate::HashFunctionT<SHA256Hash> for SHA256 {
    type Hasher = sha2::Sha256;
    fn placeholder_hash(&self) -> std::borrow::Cow<'static, SHA256Hash> {
        #[cfg(feature = "sha-256")]
        {
            std::borrow::Cow::Borrowed(&*SHA256_PLACEHOLDER)
        }
        #[cfg(not(feature = "sha-256"))]
        {
            panic!("programmer error: sha-256 feature not enabled");
        }
    }
    fn new_hasher(&self) -> Self::Hasher {
        #[cfg(feature = "sha-256")]
        {
            sha2::Sha256::default()
        }
        #[cfg(not(feature = "sha-256"))]
        {
            panic!("programmer error: sha-256 feature not enabled");
        }
    }
}

//
// sha2::Sha256
//

#[cfg(feature = "sha-256")]
impl crate::HasherT for sha2::Sha256 {
    type HashRef = SHA256Hash;
    fn hash_function(&self) -> <Self::HashRef as crate::HashRefT>::HashFunction {
        SHA256
    }
    fn update(&mut self, byte_v: &[u8]) {
        sha2::Digest::update(self, byte_v);
    }
    fn finalize(self) -> <Self::HashRef as ToOwned>::Owned {
        SHA256Hash::from(sha2::Digest::finalize(self))
    }
}

#[cfg(feature = "sha-256")]
impl HasherDynT for sha2::Sha256 {
    fn update(&mut self, byte_v: &[u8]) {
        sha2::Digest::update(self, byte_v);
    }
    fn finalize(self: Box<Self>) -> Box<dyn HashDynT> {
        Box::new(SHA256Hash::from(sha2::Digest::finalize(*self)))
    }
}

//
// SHA256HashInner
//

#[cfg(feature = "sha-256")]
#[allow(non_camel_case_types)]
pub type SHA256HashInner =
    digest::generic_array::GenericArray<u8, <sha2::Sha256 as digest::OutputSizeUser>::OutputSize>;

//
// SHA256Hash
//

/// This is a newtype over the result of sha2::Sha256::finalize because it is just a GenericArray,
/// and that doesn't give semantic distinction over other hash values that may have the same size
/// but mean a different thing.
#[cfg(feature = "sha-256")]
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, derive_more::Deref, derive_more::From, Eq, derive_more::Into, PartialEq)]
pub struct SHA256Hash(pub(crate) SHA256HashInner);

#[cfg(feature = "sha-256")]
impl SHA256Hash {
    pub fn into_inner(self) -> SHA256HashInner {
        self.0
    }
}

#[cfg(feature = "sha-256")]
impl crate::HashRefT for SHA256Hash {
    type HashFunction = SHA256;
    fn hash_function(&self) -> Self::HashFunction {
        SHA256
    }
    fn is_placeholder(&self) -> bool {
        self.as_slice().iter().all(|b| *b == 0u8)
    }
}

#[cfg(feature = "sha-256")]
impl HashDynT for SHA256Hash {
    fn hash_bytes<'s: 'h, 'h>(&'s self) -> std::borrow::Cow<'h, [u8]> {
        std::borrow::Cow::Borrowed(self.as_slice())
    }
}
