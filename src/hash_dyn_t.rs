/// Represents the typed output of a HasherDynT.
pub trait HashDynT {
    /// Returns the byte representation of this hash.
    fn hash_bytes<'s: 'h, 'h>(&'s self) -> std::borrow::Cow<'h, [u8]>;
}
