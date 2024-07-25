use crate::{HashBytes, HashFunction, KERIHash};

/// Represents the typed output of a Hasher.
// pub trait Hash: std::any::Any {
pub trait Hash {
    fn hash_function(&self) -> &dyn HashFunction;
    fn equals(&self, other: &dyn Hash) -> bool;
    fn to_hash_bytes(&self) -> HashBytes;
    // TODO: This could be `fn to_keri_hash<'s>(&'s self) -> Cow<'s, KERIHashStr>;`
    fn to_keri_hash(&self) -> KERIHash;
}
