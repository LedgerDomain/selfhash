#[cfg(feature = "sha-224")]
use crate::HashDynT;
use crate::HasherDynT;

#[cfg(feature = "sha-224")]
lazy_static::lazy_static! {
    static ref SHA224_PLACEHOLDER: SHA224Hash = SHA224Hash::from(SHA224HashInner::default());
}

//
// SHA224
//

/// This represents the SHA-224 hash function itself (from the SHA2 family of hash functions).
/// Note that this is distinct from a sha2::Sha224 hasher or a SHA224Hash value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SHA224;

impl SHA224 {
    pub fn new_hasher_dyn() -> Box<dyn HasherDynT> {
        #[cfg(feature = "sha-224")]
        {
            Box::new(sha2::Sha224::default())
        }
        #[cfg(not(feature = "sha-224"))]
        {
            panic!("programmer error: sha-224 feature not enabled");
        }
    }
}

#[cfg(feature = "sha-224")]
impl crate::HashFunctionT<SHA224Hash> for SHA224 {
    type Hasher = sha2::Sha224;
    fn placeholder_hash(&self) -> std::borrow::Cow<'static, SHA224Hash> {
        #[cfg(feature = "sha-224")]
        {
            std::borrow::Cow::Borrowed(&*SHA224_PLACEHOLDER)
        }
        #[cfg(not(feature = "sha-224"))]
        {
            panic!("programmer error: sha-224 feature not enabled");
        }
    }
    fn new_hasher(&self) -> Self::Hasher {
        #[cfg(feature = "sha-224")]
        {
            sha2::Sha224::default()
        }
        #[cfg(not(feature = "sha-224"))]
        {
            panic!("programmer error: sha-224 feature not enabled");
        }
    }
}

//
// sha2::Sha224
//

#[cfg(feature = "sha-224")]
impl crate::HasherT for sha2::Sha224 {
    type HashRef = SHA224Hash;
    fn hash_function(&self) -> <Self::HashRef as crate::HashRefT>::HashFunction {
        SHA224
    }
    fn update(&mut self, byte_v: &[u8]) {
        sha2::Digest::update(self, byte_v);
    }
    fn finalize(self) -> <Self::HashRef as ToOwned>::Owned {
        SHA224Hash::from(sha2::Digest::finalize(self))
    }
}

#[cfg(feature = "sha-224")]
impl HasherDynT for sha2::Sha224 {
    fn update(&mut self, byte_v: &[u8]) {
        sha2::Digest::update(self, byte_v);
    }
    fn finalize(self: Box<Self>) -> Box<dyn HashDynT> {
        Box::new(SHA224Hash::from(sha2::Digest::finalize(*self)))
    }
}

//
// SHA224HashInner
//

#[cfg(feature = "sha-224")]
#[allow(non_camel_case_types)]
pub type SHA224HashInner =
    digest::generic_array::GenericArray<u8, <sha2::Sha224 as digest::OutputSizeUser>::OutputSize>;

//
// SHA224Hash
//

/// This is a newtype over the result of sha2::Sha224::finalize because it is just a GenericArray,
/// and that doesn't give semantic distinction over other hash values that may have the same size
/// but mean a different thing.
#[cfg(feature = "sha-224")]
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, derive_more::Deref, derive_more::From, Eq, derive_more::Into, PartialEq)]
pub struct SHA224Hash(pub(crate) SHA224HashInner);

#[cfg(feature = "sha-224")]
impl SHA224Hash {
    pub fn into_inner(self) -> SHA224HashInner {
        self.0
    }
}

#[cfg(feature = "sha-224")]
impl crate::HashRefT for SHA224Hash {
    type HashFunction = SHA224;
    fn hash_function(&self) -> Self::HashFunction {
        SHA224
    }
    fn is_placeholder(&self) -> bool {
        self.as_slice().iter().all(|b| *b == 0u8)
    }
}

#[cfg(feature = "sha-224")]
impl HashDynT for SHA224Hash {
    fn hash_bytes<'s: 'h, 'h>(&'s self) -> std::borrow::Cow<'h, [u8]> {
        std::borrow::Cow::Borrowed(self.as_slice())
    }
}
