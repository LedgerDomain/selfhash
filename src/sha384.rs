#[cfg(feature = "sha-384")]
use crate::HashDynT;
use crate::HasherDynT;

#[cfg(feature = "sha-384")]
lazy_static::lazy_static! {
    static ref SHA384_PLACEHOLDER: SHA384Hash = SHA384Hash::from(SHA384HashInner::default());
}

//
// SHA384
//

/// This represents the SHA-384 hash function itself (from the SHA2 family of hash functions).
/// Note that this is distinct from a sha2::Sha384 hasher or a SHA384Hash value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SHA384;

impl SHA384 {
    pub fn new_hasher_dyn() -> Box<dyn HasherDynT> {
        #[cfg(feature = "sha-384")]
        {
            Box::new(sha2::Sha384::default())
        }
        #[cfg(not(feature = "sha-384"))]
        {
            panic!("programmer error: sha-384 feature not enabled");
        }
    }
}

#[cfg(feature = "sha-384")]
impl crate::HashFunctionT<SHA384Hash> for SHA384 {
    type Hasher = sha2::Sha384;
    fn placeholder_hash(&self) -> std::borrow::Cow<'static, SHA384Hash> {
        #[cfg(feature = "sha-384")]
        {
            std::borrow::Cow::Borrowed(&*SHA384_PLACEHOLDER)
        }
        #[cfg(not(feature = "sha-384"))]
        {
            panic!("programmer error: sha-384 feature not enabled");
        }
    }
    fn new_hasher(&self) -> Self::Hasher {
        #[cfg(feature = "sha-384")]
        {
            sha2::Sha384::default()
        }
        #[cfg(not(feature = "sha-384"))]
        {
            panic!("programmer error: sha-384 feature not enabled");
        }
    }
}

//
// sha2::Sha384
//

#[cfg(feature = "sha-384")]
impl crate::HasherT for sha2::Sha384 {
    type HashRef = SHA384Hash;
    fn hash_function(&self) -> <Self::HashRef as crate::HashRefT>::HashFunction {
        SHA384
    }
    fn update(&mut self, byte_v: &[u8]) {
        sha2::Digest::update(self, byte_v);
    }
    fn finalize(self) -> <Self::HashRef as ToOwned>::Owned {
        SHA384Hash::from(sha2::Digest::finalize(self))
    }
}

#[cfg(feature = "sha-384")]
impl HasherDynT for sha2::Sha384 {
    fn update(&mut self, byte_v: &[u8]) {
        sha2::Digest::update(self, byte_v);
    }
    fn finalize(self: Box<Self>) -> Box<dyn HashDynT> {
        Box::new(SHA384Hash::from(sha2::Digest::finalize(*self)))
    }
}

//
// SHA384HashInner
//

#[cfg(feature = "sha-384")]
#[allow(non_camel_case_types)]
pub type SHA384HashInner =
    digest::generic_array::GenericArray<u8, <sha2::Sha384 as digest::OutputSizeUser>::OutputSize>;

//
// SHA384Hash
//

/// This is a newtype over the result of sha2::Sha384::finalize because it is just a GenericArray,
/// and that doesn't give semantic distinction over other hash values that may have the same size
/// but mean a different thing.
#[cfg(feature = "sha-384")]
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, derive_more::Deref, derive_more::From, Eq, derive_more::Into, PartialEq)]
pub struct SHA384Hash(pub(crate) SHA384HashInner);

#[cfg(feature = "sha-384")]
impl SHA384Hash {
    pub fn into_inner(self) -> SHA384HashInner {
        self.0
    }
}

#[cfg(feature = "sha-384")]
impl crate::HashRefT for SHA384Hash {
    type HashFunction = SHA384;
    fn hash_function(&self) -> Self::HashFunction {
        SHA384
    }
    fn is_placeholder(&self) -> bool {
        self.as_slice().iter().all(|b| *b == 0u8)
    }
}

#[cfg(feature = "sha-384")]
impl HashDynT for SHA384Hash {
    fn hash_bytes<'s: 'h, 'h>(&'s self) -> std::borrow::Cow<'h, [u8]> {
        std::borrow::Cow::Borrowed(self.as_slice())
    }
}
