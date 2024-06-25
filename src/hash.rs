use crate::{HashBytes, HashFunction, KERIHash};

/// Represents the typed output of a Hasher.
pub trait Hash: std::any::Any {
    fn as_any(&self) -> &dyn std::any::Any;
    fn hash_function(&self) -> &dyn HashFunction;
    fn equals(&self, other: &dyn Hash) -> bool;
    fn to_hash_bytes(&self) -> HashBytes<'_>;
    fn to_keri_hash(&self) -> KERIHash;
}
