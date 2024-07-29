use crate::{Hash, HashBytes, KERIHashStr};
use std::ops::Deref;

/// This is a concise, ASCII-only representation of a hash value, which comes from the KERI spec.
#[derive(Clone, Debug, Eq, Hash, PartialEq, pneutype::PneuString)]
#[pneu_string(as_pneu_str = "as_keri_hash_str", borrow = "KERIHashStr")]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", pneu_string(deserialize))]
pub struct KERIHash(String);

impl Hash for KERIHash {
    fn hash_function(&self) -> &dyn crate::HashFunction {
        self.deref().hash_function()
    }
    fn equals(&self, other: &dyn Hash) -> bool {
        self.deref().equals(other)
    }
    fn to_hash_bytes<'s: 'h, 'h>(&'s self) -> HashBytes<'h> {
        self.deref().to_hash_bytes()
    }
    fn to_keri_hash<'s: 'h, 'h>(&'s self) -> std::borrow::Cow<'h, KERIHashStr> {
        std::borrow::Cow::Borrowed(self.as_keri_hash_str())
    }
}
