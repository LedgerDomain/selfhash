use crate::{Hash, Hasher};

pub trait SelfHashable {
    /// This should feed the content of this object into the hasher in the order that it should be hashed,
    /// writing placeholders for any self-hash slots that have not yet been computed.
    fn write_digest_data(&self, hasher: &mut dyn Hasher);
    /// Returns an iterator over the self-hash slots in this object.
    fn self_hash_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn Hash>> + 'a>;
    /// Sets all self-hash slots in this object (including any nested objects) to the given hash.
    fn set_self_hash_slots_to(&mut self, hash: &dyn Hash);
    /// Checks that all the self-hash slots are equal, returning error if they aren't.  Otherwise returns
    /// Some(self_hash) if they are set, and None if they are not set.
    fn get_unverified_self_hash(&self) -> Result<Option<&dyn Hash>, &'static str> {
        let total_self_hash_count = self.self_hash_oi().count();
        // First, ensure that the self-hash slots are either all Some(_) or all None.
        match self
            .self_hash_oi()
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
                return Err("This object is a malformed as SelfHashing because some but not all self-hash slots are populated -- it must be all or nothing.");
            }
            None => {
                return Err("This object has no self-hash slots, and therefore can't be self-hashed or self-verified.");
            }
        }

        let first_self_hash = self.self_hash_oi().nth(0).unwrap().unwrap();
        // Now ensure all self-hash slots are equal.
        for self_hash in self.self_hash_oi().map(|self_hash_o| self_hash_o.unwrap()) {
            if !self_hash.equals(first_self_hash) {
                return Err("Object's self-hash slots do not all match.");
            }
        }
        // If it got this far, it's valid.
        Ok(Some(first_self_hash))
    }
    /// Computes the self-hash for this object.  Note that this ignores any existing values in
    /// the self-hash slots, using the appropriate placeholder for those values instead.
    fn compute_self_hash(
        &self,
        mut hasher_b: Box<dyn Hasher>,
    ) -> Result<Box<dyn Hash>, &'static str> {
        self.write_digest_data(hasher_b.as_mut());
        Ok(hasher_b.finalize())
    }
    /// Computes the self-hash and writes it into all the self-hash slots.
    fn self_hash(&mut self, hasher_b: Box<dyn Hasher>) -> Result<&dyn Hash, &'static str> {
        let self_hash = self.compute_self_hash(hasher_b)?;
        self.set_self_hash_slots_to(self_hash.as_ref());
        let first_self_hash = self.self_hash_oi().nth(0).unwrap().unwrap();
        Ok(first_self_hash)
    }
    /// Verifies the self-hashes in this object and returns a reference to the verified self-hash.
    fn verify_self_hashes<'a, 'b: 'a>(&'b self) -> Result<&'a dyn Hash, &'static str> {
        let unverified_self_hash = self.get_unverified_self_hash()?.ok_or_else(|| {
            "This object has no self-hash slots, and therefore can't be self-hashed or self-verified."
        })?;
        // Now compute the digest which will be used either as the direct hash value, or as the input
        // to the signature algorithm.
        let hash_function = unverified_self_hash.hash_function();
        let hasher_b = hash_function.new_hasher();
        let computed_self_hash = self.compute_self_hash(hasher_b)?;
        if !computed_self_hash.equals(unverified_self_hash) {
            return Err(
                "This object's computed self-hash does not match the object's claimed self-hash.",
            );
        }
        // If it got this far, it's valid.
        Ok(unverified_self_hash)
    }
}
