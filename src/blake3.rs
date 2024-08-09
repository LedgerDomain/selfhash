use crate::{Hash, HashFunction, Hasher, NamedHashFunction};
use std::borrow::Cow;

/// This represents the BLAKE3 hash function itself, which in particular has 256 bit output.  Note that
/// this is distinct from blake3::Hasher (which is the thing that produces the digest) or a blake3::Hash
/// (which contains the hash value).
pub struct Blake3;

#[cfg(feature = "blake3")]
const BLAKE3_PLACEHOLDER: blake3::Hash = blake3::Hash::from_bytes([0u8; 32]);

impl HashFunction for Blake3 {
    fn named_hash_function(&self) -> NamedHashFunction {
        NamedHashFunction::BLAKE3
    }
    fn keri_prefix(&self) -> &'static str {
        "E"
    }
    fn placeholder_hash(&self) -> &'static dyn Hash {
        #[cfg(feature = "blake3")]
        {
            &BLAKE3_PLACEHOLDER
        }
        #[cfg(not(feature = "blake3"))]
        {
            panic!("programmer error: blake3 feature not enabled");
        }
    }
    fn new_hasher(&self) -> Box<dyn Hasher> {
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
impl Hasher for blake3::Hasher {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
    fn hash_function(&self) -> &dyn HashFunction {
        &Blake3
    }
    fn update(&mut self, byte_v: &[u8]) {
        blake3::Hasher::update(self, byte_v);
    }
    fn finalize(self: Box<Self>) -> Box<dyn Hash> {
        Box::new(blake3::Hasher::finalize(self.as_ref()))
    }
}

#[cfg(feature = "blake3")]
impl Hash for blake3::Hash {
    fn hash_function(&self) -> &'static dyn HashFunction {
        &Blake3
    }
    fn as_preferred_hash_format<'s: 'h, 'h>(&'s self) -> crate::PreferredHashFormat<'h> {
        crate::HashBytes {
            named_hash_function: self.hash_function().named_hash_function(),
            hash_byte_v: Cow::Borrowed(self.as_bytes().as_slice()),
        }
        .into()
    }
}
