use crate::HashFunctionT;

/// Represents the typed output of an impl of HasherT, and has an associated impl of HashFunctionT.  In
/// particular, impls of this trait should be analogous to a slice/str (in that they are used by reference).
/// This way, it's possible to pass around references to hashes, rather than having to clone them.
pub trait HashRefT: std::fmt::Debug + PartialEq + ToOwned + 'static {
    type HashFunction: HashFunctionT<Self>;
    /// Returns the HashFunction corresponding to this hash value.
    fn hash_function(&self) -> Self::HashFunction;
    /// Returns true iff this hash value is equal to the placeholder hash value for its hash function.
    fn is_placeholder(&self) -> bool;
}
