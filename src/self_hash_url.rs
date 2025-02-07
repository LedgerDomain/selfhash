use crate::{Hash, KERIHashStr, PreferredHashFormat, Result, SelfHashURLStr};
use pneutype::Validate;

/// EXPERIMENTAL: Represents a URL that has the form "vjson:///<keri-hash>"
// TODO: Maybe make this a general URL in which there's a "selfHash=<X>" query parameter.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, pneutype::PneuString)]
#[pneu_string(as_pneu_str = "as_self_hash_url_str", borrow = "SelfHashURLStr")]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", pneu_string(deserialize))]
pub struct SelfHashURL(String);

impl SelfHashURL {
    pub fn new(keri_hash: &KERIHashStr) -> Self {
        let mut s = String::with_capacity(12 + keri_hash.len());
        s.push_str("vjson:///");
        s.push_str(keri_hash.as_str());
        Self::try_from(s).unwrap()
    }
    pub fn set_self_hash_slots_to_keri_hash(&mut self, keri_hash: &KERIHashStr) {
        self.0 = format!("vjson:///{}", keri_hash);
        assert!(SelfHashURLStr::validate(&self.0).is_ok());
    }
}

impl Hash for SelfHashURL {
    fn hash_function(&self) -> Result<&'static dyn crate::HashFunction> {
        self.keri_hash_o().unwrap().hash_function()
    }
    fn as_preferred_hash_format<'s: 'h, 'h>(&'s self) -> Result<PreferredHashFormat<'h>> {
        Ok(std::borrow::Cow::Borrowed(self.keri_hash_o().unwrap()).into())
    }
}
