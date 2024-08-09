use crate::{Hash, KERIHashStr, PreferredHashFormat};

/// This is a concise, ASCII-only representation of a hash value, which comes from the KERI spec.
#[derive(Clone, Debug, Eq, Hash, PartialEq, pneutype::PneuString)]
#[pneu_string(as_pneu_str = "as_keri_hash_str", borrow = "KERIHashStr")]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", pneu_string(deserialize))]
pub struct KERIHash(String);

impl Hash for KERIHash {
    fn hash_function(&self) -> &'static dyn crate::HashFunction {
        // TODO: De-duplicate this
        match self.keri_prefix() {
            "E" => &crate::Blake3,
            "I" => &crate::SHA256,
            "0G" => &crate::SHA512,
            _ => {
                panic!("this should not be possible because of check in from_str");
            }
        }
    }
    fn as_preferred_hash_format<'s: 'h, 'h>(&'s self) -> PreferredHashFormat<'h> {
        std::borrow::Cow::Borrowed(self.as_keri_hash_str()).into()
    }
}
