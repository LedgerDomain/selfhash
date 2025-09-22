use crate::HashRefT;

/// Represents a hash value that can be converted to a hash reference.
pub trait HashT<HashRef: HashRefT + ?Sized + ToOwned> {
    fn as_hash_ref(&self) -> &HashRef;
}
