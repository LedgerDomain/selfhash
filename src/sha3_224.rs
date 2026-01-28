#[cfg(feature = "sha3-224")]
use crate::HashDynT;
use crate::HasherDynT;

#[cfg(feature = "sha3-224")]
lazy_static::lazy_static! {
    static ref SHA3_224_PLACEHOLDER: SHA3_224_Hash = SHA3_224_Hash::from(SHA3_224_HashInner::default());
}

//
// SHA3_224
//

/// This represents the SHA3_224 hash function itself (from the SHA3 family of hash functions).
/// Note that this is distinct from a SHA3_224 hasher or a SHA3_224_Hash value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SHA3_224;

impl SHA3_224 {
    pub fn new_hasher_dyn() -> Box<dyn HasherDynT> {
        #[cfg(feature = "sha3-224")]
        {
            Box::new(sha3::Sha3_224::default())
        }
        #[cfg(not(feature = "sha3-224"))]
        {
            panic!("programmer error: sha3-224 feature not enabled");
        }
    }
}

#[cfg(feature = "sha3-224")]
impl crate::HashFunctionT<SHA3_224_Hash> for SHA3_224 {
    type Hasher = sha3::Sha3_224;
    fn placeholder_hash(&self) -> std::borrow::Cow<'static, SHA3_224_Hash> {
        #[cfg(feature = "sha3-224")]
        {
            std::borrow::Cow::Borrowed(&*SHA3_224_PLACEHOLDER)
        }
        #[cfg(not(feature = "sha3-224"))]
        {
            panic!("programmer error: sha3-224 feature not enabled");
        }
    }
    fn new_hasher(&self) -> Self::Hasher {
        #[cfg(feature = "sha3-224")]
        {
            sha3::Sha3_224::default()
        }
        #[cfg(not(feature = "sha3-224"))]
        {
            panic!("programmer error: sha3-224 feature not enabled");
        }
    }
}

//
// sha3::Sha3_224
//

#[cfg(feature = "sha3-224")]
impl crate::HasherT for sha3::Sha3_224 {
    type HashRef = SHA3_224_Hash;
    fn hash_function(&self) -> <Self::HashRef as crate::HashRefT>::HashFunction {
        SHA3_224
    }
    fn update(&mut self, byte_v: &[u8]) {
        sha3::Digest::update(self, byte_v);
    }
    fn finalize(self) -> <Self::HashRef as ToOwned>::Owned {
        SHA3_224_Hash::from(sha3::Digest::finalize(self))
    }
}

#[cfg(feature = "sha3-224")]
impl HasherDynT for sha3::Sha3_224 {
    fn update(&mut self, byte_v: &[u8]) {
        sha3::Digest::update(self, byte_v);
    }
    fn finalize(self: Box<Self>) -> Box<dyn HashDynT> {
        Box::new(SHA3_224_Hash::from(sha3::Digest::finalize(*self)))
    }
}

//
// SHA3_224_HashInner
//

#[cfg(feature = "sha3-224")]
#[allow(non_camel_case_types)]
pub type SHA3_224_HashInner =
    digest::generic_array::GenericArray<u8, <sha3::Sha3_224 as digest::OutputSizeUser>::OutputSize>;

//
// SHA3_224_Hash
//

/// This is a newtype over the result of sha3::Sha3_224::finalize because it is just a GenericArray,
/// and that doesn't give semantic distinction over other hash values that may have the same size
/// but mean a different thing.
#[cfg(feature = "sha3-224")]
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, derive_more::Deref, derive_more::From, Eq, derive_more::Into, PartialEq)]
pub struct SHA3_224_Hash(pub(crate) SHA3_224_HashInner);

#[cfg(feature = "sha3-224")]
impl SHA3_224_Hash {
    pub fn into_inner(self) -> SHA3_224_HashInner {
        self.0
    }
}

#[cfg(feature = "sha3-224")]
impl crate::HashRefT for SHA3_224_Hash {
    type HashFunction = SHA3_224;
    fn hash_function(&self) -> Self::HashFunction {
        SHA3_224
    }
    fn is_placeholder(&self) -> bool {
        self.as_slice().iter().all(|b| *b == 0u8)
    }
}

#[cfg(feature = "sha3-224")]
impl HashDynT for SHA3_224_Hash {
    fn hash_bytes<'s: 'h, 'h>(&'s self) -> std::borrow::Cow<'h, [u8]> {
        std::borrow::Cow::Borrowed(self.as_slice())
    }
}
