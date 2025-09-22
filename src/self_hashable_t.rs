use crate::{bail, ensure, error, Error, HashFunctionT, HashRefT, HasherT, Result};

/// This is the canonical implementation of the SelfHashable::write_digest_data
/// method for when the SelfHashable type implements Clone and the desired desired serialization
/// format is JSON Canonicalization Scheme (JCS).  Simply call this method from your implementation of
/// SelfHashable::write_digest_data.
#[cfg(feature = "jcs")]
pub fn write_digest_data_using_jcs<
    HashRef: HashRefT + ?Sized + ToOwned,
    S: Clone + SelfHashableT<HashRef> + serde::Serialize,
>(
    self_hashable: &S,
    mut hasher: &mut <<HashRef as HashRefT>::HashFunction as crate::HashFunctionT<HashRef>>::Hasher,
) -> Result<()> {
    let mut c = self_hashable.clone();
    use crate::HashFunctionT;
    c.set_self_hash_slots_to(hasher.hash_function().placeholder_hash().as_ref())?;
    // Use JCS to produce canonical output.  The `&mut hasher` ridiculousness is because
    // serde_json_canonicalizer::to_writer uses a generic impl of std::io::Write and therefore
    // implicitly requires the `Sized` trait.  Therefore passing in a reference to the reference
    // achieves the desired effect.
    serde_json_canonicalizer::to_writer(&c, &mut hasher)
        .map_err(|e| error!("Failed to write digest data using JCS; error was {}", e))?;
    Ok(())
}

/// This trait allows a self-hashing procedure to be defined for a data type.  The data type must implement
/// the following required methods:
/// - self_hash_oi: defines the self-hash slots.
/// - set_self_hash_slots_to: sets all the self-hash slots to the given hash.
/// - write_digest_data: writes the data to be hashed into the hasher, using the appropriate placeholder
///   for the self-hash slots).
///
/// An easy default for the implementation of write_digest_data is provided by the write_digest_data_using_jcs
/// function, which can be called from your implementation of write_digest_data if your type implements
/// Clone and serde::Serialize and the desired serialization format is JSON Canonicalization Scheme (JCS).
// TODO: Consider breaking out the `&mut self` methods into a separate trait called SelfHashableMut.
pub trait SelfHashableT<HashRef: HashRefT + ?Sized + ToOwned> {
    /// This should feed the content of this object into the hasher in the order that it should be hashed,
    /// writing placeholders for the self-hash slots.
    ///
    /// If the implementing type implements Clone and serde::Serialize, and the desired serialization
    /// format is JSON Canonicalization Scheme (JCS), then you can simply call write_digest_data_using_jcs
    /// from your implementation of this method.
    fn write_digest_data(
        &self,
        hasher: &mut <<HashRef as HashRefT>::HashFunction as HashFunctionT<HashRef>>::Hasher,
    ) -> Result<()>;
    /// Returns an iterator over the self-hash slots in this object.
    fn self_hash_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Result<Box<dyn std::iter::Iterator<Item = Option<&'b HashRef>> + 'a>>;
    /// Sets all self-hash slots in this object (including any nested objects) to the given hash.
    fn set_self_hash_slots_to(&mut self, hash: &HashRef) -> Result<()>;
    /// Checks that all the self-hash slots are equal, returning error if they aren't.  Otherwise returns
    /// Some(self_hash) if they are set, and None if they are not set.
    fn get_unverified_self_hash(&self) -> Result<Option<&HashRef>> {
        let total_self_hash_count = self.self_hash_oi()?.count();
        // First, ensure that the self-hash slots are either all Some(_) or all None.
        match self
            .self_hash_oi()?
            .map(|self_hash_o| {
                if self_hash_o.is_some() {
                    1usize
                } else {
                    0usize
                }
            })
            .reduce(|a, b| a + b)
        {
            Some(0) => {
                // All self-hash slots are None, which is valid.  We can return early here.
                return Ok(None);
            }
            Some(populated_self_hash_count)
                if populated_self_hash_count == total_self_hash_count =>
            {
                // All self-hash slots are populated, so we have to check them.
            }
            Some(_) => {
                bail!("This object is a malformed as SelfHashing because some but not all self-hash slots are populated -- it must be all or nothing.");
            }
            None => {
                bail!("This object has no self-hash slots, and therefore can't be self-hashed or self-verified.");
            }
        }

        let first_self_hash = self.self_hash_oi()?.nth(0).unwrap().unwrap();
        // Now ensure all self-hash slots are equal.
        for self_hash in self.self_hash_oi()?.map(|self_hash_o| self_hash_o.unwrap()) {
            ensure!(
                // self_hash.equals(first_self_hash),
                self_hash == first_self_hash,
                "Object's self-hash slots do not all match."
            );
        }
        // If it got this far, it's valid.
        Ok(Some(first_self_hash))
    }
    /// Computes the self-hash for this object.  Note that this ignores any existing values in
    /// the self-hash slots, using the appropriate placeholder for those values instead.
    fn compute_self_hash(
        &self,
        mut hasher: <<HashRef as HashRefT>::HashFunction as HashFunctionT<HashRef>>::Hasher,
    ) -> Result<<HashRef as ToOwned>::Owned> {
        self.write_digest_data(&mut hasher)?;
        Ok(hasher.finalize())
    }
    /// Computes the self-hash and writes it into all the self-hash slots.
    fn self_hash(
        &mut self,
        hasher: <<HashRef as HashRefT>::HashFunction as HashFunctionT<HashRef>>::Hasher,
    ) -> Result<&HashRef> {
        let self_hash = self.compute_self_hash(hasher)?;
        use std::borrow::Borrow;
        self.set_self_hash_slots_to(self_hash.borrow())?;
        for self_hash_o in self.self_hash_oi()? {
            if let Some(self_hash) = self_hash_o {
                use crate::HashFunctionT;
                use std::borrow::Borrow;
                // ensure!(!self_hash.equals(self_hash.hash_function().placeholder_hash().borrow()), "programmer error: implementation of set_self_hash_slots_to did not set all self-hash slots.");
                ensure!(self_hash != self_hash.hash_function().placeholder_hash().borrow(), "programmer error: implementation of set_self_hash_slots_to did not set all self-hash slots.");
            } else {
                bail!("programmer error: implementation of set_self_hash_slots_to did not set all self-hash slots (some were left unset).");
            }
        }
        let first_self_hash = self
            .self_hash_oi()?
            .nth(0)
            .ok_or_else(|| {
                error!("This object has no self-hash slots, and therefore can't be self-hashed.")
            })?
            .unwrap();
        Ok(first_self_hash)
    }
    /// Verifies the self-hashes in this object and returns a reference to the verified self-hash.
    fn verify_self_hashes<'a, 'b: 'a>(&'b self) -> Result<&'a HashRef> {
        let unverified_self_hash = self.get_unverified_self_hash()?.ok_or_else(|| {
            "This object has no self-hash slots, and therefore can't be self-verified."
        })?;
        // Now compute the digest which will be used either as the direct hash value, or as the input
        // to the signature algorithm.
        let hash_function = unverified_self_hash.hash_function();
        use crate::HashFunctionT;
        use std::borrow::Borrow;
        let hasher = hash_function.new_hasher();
        let computed_self_hash = self.compute_self_hash(hasher)?;
        // if !computed_self_hash.borrow().equals(unverified_self_hash) {
        if computed_self_hash.borrow() != unverified_self_hash {
            return Err(
                Error::from(format!("This object's computed self-hash ({:?}) doesn't match the object's claimed self-hash ({:?}).",
                computed_self_hash.borrow(), unverified_self_hash))
            );
        }
        // If it got this far, it's valid.
        Ok(unverified_self_hash)
    }
}
