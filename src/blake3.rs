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
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn hash_function(&self) -> &dyn HashFunction {
        &Blake3
    }
    fn equals(&self, other: &dyn Hash) -> bool {
        if let Some(other_blake3_hash) = other.as_any().downcast_ref::<blake3::Hash>() {
            // If the other is also a blake3::Hash, then we can compare directly.
            self.as_bytes() == other_blake3_hash.as_bytes()
        } else {
            // Otherwise need to convert into a common type.
            self.to_hash_bytes() == other.to_hash_bytes()
        }
    }
    fn to_hash_bytes(&self) -> crate::HashBytes<'_> {
        crate::HashBytes {
            named_hash_function: self.hash_function().named_hash_function(),
            // This allocation is potentially not necessary.
            hash_byte_v: self.as_bytes().as_slice().into(),
        }
    }
    /// This might allocate, and potentially can be implemented without allocations.
    fn to_keri_hash(&self) -> crate::KERIHash<'_> {
        self.to_hash_bytes()
            .to_keri_hash()
            .expect("programmer error")
    }
}
