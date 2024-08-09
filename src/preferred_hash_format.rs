use crate::{HashBytes, KERIHashStr};
use std::borrow::Cow;

/// A type which allows a Hash impl to represent its hash in its "preferred" format, chosen to minimize allocations.
pub enum PreferredHashFormat<'h> {
    HashBytes(HashBytes<'h>),
    KERIHash(Cow<'h, KERIHashStr>),
}

impl<'h> From<HashBytes<'h>> for PreferredHashFormat<'h> {
    fn from(hash_bytes: HashBytes<'h>) -> Self {
        Self::HashBytes(hash_bytes)
    }
}

impl<'h> From<Cow<'h, KERIHashStr>> for PreferredHashFormat<'h> {
    fn from(keri_hash: Cow<'h, KERIHashStr>) -> Self {
        Self::KERIHash(keri_hash)
    }
}
