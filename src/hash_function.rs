use crate::{Hash, Hasher, NamedHashFunction};

/// This trait represents a hash function itself.  This is distinct from Hasher (which is what actually
/// does the hashing) and Hash (which is the typed output of a Hasher).
pub trait HashFunction {
    /// Returns the NamedHashFunction form of this hash function.
    fn named_hash_function(&self) -> NamedHashFunction;
    /// Returns the KERI prefix for this hash function.
    fn keri_prefix(&self) -> &'static str;
    /// Returns the appropriate hash value to use as the placeholder when self-hashing.
    fn placeholder_hash(&self) -> &'static dyn Hash;
    /// Simply compares the keri_prefix value of self with that of other.
    fn equals(&self, other: &dyn HashFunction) -> bool {
        self.keri_prefix() == other.keri_prefix()
    }
    fn new_hasher(&self) -> Box<dyn Hasher>;
}
