#[cfg(feature = "sha-512")]
use crate::HashDynT;
use crate::HasherDynT;

#[cfg(feature = "sha-512")]
lazy_static::lazy_static! {
    static ref SHA_512_PLACEHOLDER: SHA512Hash = SHA512Hash::from(SHA512HashInner::default());
}

//
// SHA512
//

/// This represents the SHA_512 hash function itself.  Note that this is distinct from a
/// SHA_512 hasher or a SHA_512_Hash value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SHA512;

impl SHA512 {
    pub fn new_hasher_dyn() -> Box<dyn HasherDynT> {
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
impl crate::HashFunctionT<SHA512Hash> for SHA512 {
    type Hasher = sha2::Sha512;
    fn placeholder_hash(&self) -> std::borrow::Cow<'static, SHA512Hash> {
        #[cfg(feature = "sha-512")]
        {
            std::borrow::Cow::Borrowed(&*SHA_512_PLACEHOLDER)
        }
        #[cfg(not(feature = "sha-512"))]
        {
            panic!("programmer error: sha-512 feature not enabled");
        }
    }
    fn new_hasher(&self) -> Self::Hasher {
        #[cfg(feature = "sha-512")]
        {
            sha2::Sha512::default()
        }
        #[cfg(not(feature = "sha-512"))]
        {
            panic!("programmer error: sha-512 feature not enabled");
        }
    }
}

// impl HashFunction for SHA512 {
//     fn named_hash_function(&self) -> NamedHashFunction {
//         NamedHashFunction::SHA_512
//     }
//     fn keri_prefix(&self) -> &'static str {
//         "0G"
//     }
//     fn placeholder_hash(&self) -> &'static dyn Hash {
//         #[cfg(feature = "sha-512")]
//         {
//             &*SHA_512_PLACEHOLDER
//         }
//         #[cfg(not(feature = "sha-512"))]
//         {
//             panic!("programmer error: sha-512 feature not enabled");
//         }
//     }
//     fn new_hasher(&self) -> Box<dyn Hasher> {
//         #[cfg(feature = "sha-512")]
//         {
//             Box::new(sha2::Sha512::default())
//         }
//         #[cfg(not(feature = "sha-512"))]
//         {
//             panic!("programmer error: sha-512 feature not enabled");
//         }
//     }
// }

//
// sha2::Sha512
//

// #[cfg(feature = "sha-512")]
// impl Hasher for sha2::Sha512 {
//     fn as_any(&self) -> &dyn std::any::Any {
//         self
//     }
//     fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
//         self
//     }
//     fn hash_function(&self) -> &dyn HashFunction {
//         &SHA512
//     }
//     fn update(&mut self, byte_v: &[u8]) {
//         sha2::Digest::update(self, byte_v);
//     }
//     fn finalize(self: Box<Self>) -> Box<dyn Hash> {
//         Box::new(SHA512Hash::from(sha2::Digest::finalize(*self)))
//     }
// }

#[cfg(feature = "sha-512")]
impl crate::HasherT for sha2::Sha512 {
    type HashRef = SHA512Hash;
    fn hash_function(&self) -> <Self::HashRef as crate::HashRefT>::HashFunction {
        SHA512
    }
    fn update(&mut self, byte_v: &[u8]) {
        sha2::Digest::update(self, byte_v);
    }
    fn finalize(self) -> <Self::HashRef as ToOwned>::Owned {
        SHA512Hash::from(sha2::Digest::finalize(self))
    }
}

#[cfg(feature = "sha-512")]
impl HasherDynT for sha2::Sha512 {
    fn update(&mut self, byte_v: &[u8]) {
        sha2::Digest::update(self, byte_v);
    }
    fn finalize(self: Box<Self>) -> Box<dyn HashDynT> {
        Box::new(SHA512Hash::from(sha2::Digest::finalize(*self)))
    }
}

//
// SHA512HashInner
//

#[cfg(feature = "sha-512")]
pub type SHA512HashInner =
    digest::generic_array::GenericArray<u8, <sha2::Sha512 as digest::OutputSizeUser>::OutputSize>;

//
// SHA512Hash
//

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
impl crate::HashRefT for SHA512Hash {
    type HashFunction = SHA512;
    fn hash_function(&self) -> Self::HashFunction {
        SHA512
    }
    fn is_placeholder(&self) -> bool {
        self.as_slice().iter().all(|b| *b == 0u8)
    }
}

#[cfg(feature = "sha-512")]
impl HashDynT for SHA512Hash {
    fn hash_bytes<'s: 'h, 'h>(&'s self) -> std::borrow::Cow<'h, [u8]> {
        std::borrow::Cow::Borrowed(self.as_slice())
    }
}
