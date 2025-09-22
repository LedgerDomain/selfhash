use crate::HashRefT;

/// Represents a hasher object, which is what digests a message and produces a hash value.
pub trait HasherT: std::io::Write {
    type HashRef: HashRefT + ?Sized;
    /// Returns the HashFunction corresponding to this hasher.
    fn hash_function(&self) -> <Self::HashRef as HashRefT>::HashFunction;
    /// Updates the hasher with the given byte vector.
    fn update(&mut self, byte_v: &[u8]);
    /// Finalizes the hasher and returns a hash value.
    fn finalize(self) -> <Self::HashRef as ToOwned>::Owned;
}
