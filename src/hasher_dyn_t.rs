use crate::HashDynT;

/// Represents a hasher object, which is what digests a message and produces a hash value.
/// This trait is dyn-compatible, and is used when the hash function is only known at runtime.
pub trait HasherDynT: std::io::Write {
    /// Updates the hasher with the given byte vector.
    fn update(&mut self, byte_v: &[u8]);
    /// Finalizes the hasher and returns a hash value.
    fn finalize(self: Box<Self>) -> Box<dyn HashDynT>;
}
