use crate::{HashBytes, HashFunction, KERIHashStr};

/// Represents the typed output of a Hasher.  It has an associated HashFunction.  It has a "native"
/// representation type, which will either be bytes (in which case self.to_hash_bytes() doesn't need
/// to allocate), or KERIHash (in which case, self.to_keri_hash() doesn't need to allocate).
pub trait Hash {
    /// Returns the HashFunction corresponding to this hash value.
    fn hash_function(&self) -> &dyn HashFunction;
    /// Returns true iff self represents the same hash value as other.  Default impl checks if
    /// self.hash_function() equals other.hash_function().  If so, then checks if self.to_hash_bytes()
    /// equals other.to_hash_bytes() (as a common type for comparison).
    fn equals(&self, other: &dyn Hash) -> bool {
        // Check the hash function directly before resorting to converting.
        if !self.hash_function().equals(other.hash_function()) {
            return false;
        }
        // Convert to common type for comparison.
        self.to_hash_bytes() == other.to_hash_bytes()
    }
    /// Returns the HashBytes representation of this hash.  If the native representation of this hash is
    /// bytes, then the HashBytes can (and should) use Cow::Borrowed (see HashBytes), in which case no
    /// allocation is done.
    fn to_hash_bytes<'s: 'h, 'h>(&'s self) -> HashBytes<'h>;
    /// Returns the KERIHash representation of this hash.  Default impl is
    /// std::borrow::Cow::Owned(self.to_hash_bytes().to_keri_hash()).
    fn to_keri_hash<'s: 'h, 'h>(&'s self) -> std::borrow::Cow<'h, KERIHashStr> {
        std::borrow::Cow::Owned(
            self.to_hash_bytes()
                .to_keri_hash()
                .expect("programmer error"),
        )
    }
}
