#[cfg(feature = "sha3-384")]
use crate::HashDynT;
use crate::HasherDynT;

#[cfg(feature = "sha3-384")]
lazy_static::lazy_static! {
    static ref SHA3_384_PLACEHOLDER: SHA3_384_Hash = SHA3_384_Hash::from(SHA3_384_HashInner::default());
}

//
// SHA3_384
//

/// This represents the SHA3_384 hash function itself (from the SHA3 family of hash functions).
/// Note that this is distinct from a SHA3_384 hasher or a SHA3_384_Hash value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SHA3_384;

impl SHA3_384 {
    pub fn new_hasher_dyn() -> Box<dyn HasherDynT> {
        #[cfg(feature = "sha3-384")]
        {
            Box::new(sha3::Sha3_384::default())
        }
        #[cfg(not(feature = "sha3-384"))]
        {
            panic!("programmer error: sha3-384 feature not enabled");
        }
    }
}

#[cfg(feature = "sha3-384")]
impl crate::HashFunctionT<SHA3_384_Hash> for SHA3_384 {
    type Hasher = sha3::Sha3_384;
    fn placeholder_hash(&self) -> std::borrow::Cow<'static, SHA3_384_Hash> {
        #[cfg(feature = "sha3-384")]
        {
            std::borrow::Cow::Borrowed(&*SHA3_384_PLACEHOLDER)
        }
        #[cfg(not(feature = "sha3-384"))]
        {
            panic!("programmer error: sha3-384 feature not enabled");
        }
    }
    fn new_hasher(&self) -> Self::Hasher {
        #[cfg(feature = "sha3-384")]
        {
            sha3::Sha3_384::default()
        }
        #[cfg(not(feature = "sha3-384"))]
        {
            panic!("programmer error: sha3-384 feature not enabled");
        }
    }
}

//
// sha3::Sha3_384
//

#[cfg(feature = "sha3-384")]
impl crate::HasherT for sha3::Sha3_384 {
    type HashRef = SHA3_384_Hash;
    fn hash_function(&self) -> <Self::HashRef as crate::HashRefT>::HashFunction {
        SHA3_384
    }
    fn update(&mut self, byte_v: &[u8]) {
        sha3::Digest::update(self, byte_v);
    }
    fn finalize(self) -> <Self::HashRef as ToOwned>::Owned {
        SHA3_384_Hash::from(sha3::Digest::finalize(self))
    }
}

#[cfg(feature = "sha3-384")]
impl HasherDynT for sha3::Sha3_384 {
    fn update(&mut self, byte_v: &[u8]) {
        sha3::Digest::update(self, byte_v);
    }
    fn finalize(self: Box<Self>) -> Box<dyn HashDynT> {
        Box::new(SHA3_384_Hash::from(sha3::Digest::finalize(*self)))
    }
}

//
// SHA3_384_HashInner
//

#[cfg(feature = "sha3-384")]
#[allow(non_camel_case_types)]
pub type SHA3_384_HashInner =
    digest::generic_array::GenericArray<u8, <sha3::Sha3_384 as digest::OutputSizeUser>::OutputSize>;

//
// SHA3_384_Hash
//

/// This is a newtype over the result of sha3::Sha3_384::finalize because it is just a GenericArray,
/// and that doesn't give semantic distinction over other hash values that may have the same size
/// but mean a different thing.
#[cfg(feature = "sha3-384")]
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, derive_more::Deref, derive_more::From, Eq, derive_more::Into, PartialEq)]
pub struct SHA3_384_Hash(pub(crate) SHA3_384_HashInner);

#[cfg(feature = "sha3-384")]
impl SHA3_384_Hash {
    pub fn into_inner(self) -> SHA3_384_HashInner {
        self.0
    }
}

#[cfg(feature = "sha3-384")]
impl crate::HashRefT for SHA3_384_Hash {
    type HashFunction = SHA3_384;
    fn hash_function(&self) -> Self::HashFunction {
        SHA3_384
    }
    fn is_placeholder(&self) -> bool {
        self.as_slice().iter().all(|b| *b == 0u8)
    }
}

#[cfg(feature = "sha3-384")]
impl HashDynT for SHA3_384_Hash {
    fn hash_bytes<'s: 'h, 'h>(&'s self) -> std::borrow::Cow<'h, [u8]> {
        std::borrow::Cow::Borrowed(self.as_slice())
    }
}
