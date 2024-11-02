use crate::{Hash, HashFunction, Hasher, NamedHashFunction};

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
    fn hash_function(&self) -> crate::Result<&'static dyn HashFunction> {
        Ok(&Blake3)
    }
    fn as_preferred_hash_format<'s: 'h, 'h>(
        &'s self,
    ) -> crate::Result<crate::PreferredHashFormat<'h>> {
        Ok(crate::HashBytes {
            named_hash_function: self.hash_function()?.named_hash_function(),
            hash_byte_v: std::borrow::Cow::Borrowed(self.as_bytes().as_slice()),
        }
        .into())
    }
}

#[cfg(feature = "blake3")]
impl TryFrom<&dyn Hash> for blake3::Hash {
    type Error = crate::Error;
    fn try_from(hash: &dyn Hash) -> crate::Result<Self> {
        let named_hash_function = hash.hash_function()?.named_hash_function();
        if named_hash_function != NamedHashFunction::BLAKE3 {
            crate::bail!(
                "expected hash function to be {}, but was {}",
                NamedHashFunction::BLAKE3,
                named_hash_function
            );
        }
        let hash_byte_v = hash.to_hash_bytes()?.hash_byte_v;
        crate::require!(
            hash_byte_v.len() == 32,
            "expected hash byte vector to be {} bytes, but was {} bytes",
            32,
            hash_byte_v.len()
        );
        use std::ops::Deref;
        Ok(Self::from_bytes(hash_byte_v.deref().try_into().unwrap()))
    }
}
