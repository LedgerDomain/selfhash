use crate::{HashRefT, HasherT};

/// This trait represents a hash function itself.  This is distinct from HasherT (impls of which are
/// what actually do the hashing) and HashRefT (which is the typed output of a HasherT).
pub trait HashFunctionT<HashRef: HashRefT + ?Sized + ToOwned>: PartialEq {
    type Hasher: HasherT<HashRef = HashRef>;
    /// Returns the appropriate hash value to use as the placeholder when self-hashing.
    fn placeholder_hash(&self) -> std::borrow::Cow<'static, HashRef>;
    /// Returns a new hasher object for this hash function.
    fn new_hasher(&self) -> Self::Hasher;
}
