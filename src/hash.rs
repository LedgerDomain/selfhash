use crate::{HashBytes, HashFunction, KERIHashStr, PreferredHashFormat, Result};
use std::borrow::Cow;

/// Represents the typed output of a Hasher.  It has an associated HashFunction.  It has a "native"
/// representation type, which will either be bytes (in which case self.to_hash_bytes() doesn't need
/// to allocate), or KERIHash (in which case, self.to_keri_hash() doesn't need to allocate).
pub trait Hash {
    /// Returns the HashFunction corresponding to this hash value.
    fn hash_function(&self) -> Result<&'static dyn HashFunction>;
    /// Returns true iff self represents the same Hash value as other.  Default impl checks if
    /// self.hash_function() equals other.hash_function().  If so, then compares the preferred
    /// hash format values of each, avoiding allocation if possible.
    fn equals(&self, other: &dyn Hash) -> Result<bool> {
        // Check the hash function directly before resorting to converting.
        if !self.hash_function()?.equals(other.hash_function()?) {
            return Ok(false);
        }
        match (
            self.as_preferred_hash_format()?,
            other.as_preferred_hash_format()?,
        ) {
            (
                PreferredHashFormat::HashBytes(self_hash_bytes),
                PreferredHashFormat::HashBytes(other_hash_bytes),
            ) => Ok(self_hash_bytes == other_hash_bytes),
            (
                PreferredHashFormat::HashBytes(self_hash_bytes),
                PreferredHashFormat::KERIHash(other_keri_hash),
            ) => {
                // Convert to HashBytes for comparison
                Ok(self_hash_bytes == other_keri_hash.to_hash_bytes())
            }
            (
                PreferredHashFormat::KERIHash(self_keri_hash),
                PreferredHashFormat::HashBytes(other_hash_bytes),
            ) => {
                // Convert to HashBytes for comparison
                Ok(self_keri_hash.to_hash_bytes() == other_hash_bytes)
            }
            (
                PreferredHashFormat::KERIHash(self_keri_hash),
                PreferredHashFormat::KERIHash(other_keri_hash),
            ) => Ok(self_keri_hash == other_keri_hash),
        }
    }
    /// Returns the preferred concrete representation of this hash, either HashBytes<'h> or Cow<'h, KERIHashStr>,
    /// chosen to minimize allocations.
    fn as_preferred_hash_format<'s: 'h, 'h>(&'s self) -> Result<PreferredHashFormat<'h>>;
    /// Returns the HashBytes representation of this hash.  If the preferred representation of this hash is
    /// HashBytes, then the HashBytes will use Cow::Borrowed when possible, in which case no allocation is done.
    fn to_hash_bytes<'s: 'h, 'h>(&'s self) -> Result<HashBytes<'h>> {
        match self.as_preferred_hash_format()? {
            PreferredHashFormat::HashBytes(hash_bytes) => Ok(hash_bytes),
            PreferredHashFormat::KERIHash(keri_hash) => Ok(keri_hash.to_hash_bytes()),
        }
    }
    /// Returns the KERIHash representation of this hash.  If the preferred representation of this hash
    /// is KERIHash, then it will use std::borrow::Cow::Borrowed(_), in which case no allocation is done.
    fn to_keri_hash<'s: 'h, 'h>(&'s self) -> Result<Cow<'h, KERIHashStr>> {
        match self.as_preferred_hash_format()? {
            PreferredHashFormat::HashBytes(hash_bytes) => Ok(Cow::Owned(
                hash_bytes.to_keri_hash().expect("programmer error"),
            )),
            PreferredHashFormat::KERIHash(keri_hash) => Ok(keri_hash),
        }
    }
}
