use crate::HasherDynT;
#[cfg(feature = "blake3")]
use crate::{HashDynT, HashFunctionT, HashRefT, HasherT};

#[cfg(feature = "blake3")]
const BLAKE3_PLACEHOLDER: blake3::Hash = blake3::Hash::from_bytes([0u8; 32]);

/// This represents the BLAKE3 hash function itself, which in particular has 256 bit output.  Note that
/// this is distinct from blake3::Hasher (which is the thing that produces the digest) or a blake3::Hash
/// (which contains the hash value).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Blake3;

impl Blake3 {
    pub fn new_hasher_dyn() -> Box<dyn HasherDynT> {
        #[cfg(feature = "blake3")]
        {
            Box::new(blake3::Hasher::new())
        }
        #[cfg(not(feature = "blake3"))]
        {
            panic!("programmer error: blake3 feature not enabled");
        }
    }
}

#[cfg(feature = "blake3")]
impl HashFunctionT<blake3::Hash> for Blake3 {
    type Hasher = blake3::Hasher;
    fn placeholder_hash(&self) -> std::borrow::Cow<'static, blake3::Hash> {
        std::borrow::Cow::Borrowed(&BLAKE3_PLACEHOLDER)
    }
    fn new_hasher(&self) -> Self::Hasher {
        blake3::Hasher::new()
    }
}

#[cfg(feature = "blake3")]
impl HashRefT for blake3::Hash {
    type HashFunction = Blake3;
    fn hash_function(&self) -> Self::HashFunction {
        Blake3
    }
    fn is_placeholder(&self) -> bool {
        self.as_bytes().iter().all(|b| *b == 0u8)
    }
}

#[cfg(feature = "blake3")]
impl HasherT for blake3::Hasher {
    type HashRef = blake3::Hash;
    fn hash_function(&self) -> <Self::HashRef as HashRefT>::HashFunction {
        Blake3
    }
    fn update(&mut self, byte_v: &[u8]) {
        self.update(byte_v);
    }
    fn finalize(self) -> <Self::HashRef as ToOwned>::Owned {
        blake3::Hasher::finalize(&self)
    }
}

#[cfg(feature = "blake3")]
impl HasherDynT for blake3::Hasher {
    fn update(&mut self, byte_v: &[u8]) {
        blake3::Hasher::update(self, byte_v);
    }
    fn finalize(self: Box<Self>) -> Box<dyn HashDynT> {
        Box::new(blake3::Hasher::finalize(self.as_ref()))
    }
}

#[cfg(feature = "blake3")]
impl HashDynT for blake3::Hash {
    fn hash_bytes<'s: 'h, 'h>(&'s self) -> std::borrow::Cow<'h, [u8]> {
        std::borrow::Cow::Borrowed(self.as_bytes().as_slice())
    }
}
