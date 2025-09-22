use crate::{HashT, SelfHashURLStr};
use pneutype::Validate;

/// EXPERIMENTAL: Represents a URL that has the form "vjson:///<keri-hash>"
// TODO: Maybe make this a general URL in which there's a "selfHash=<X>" query parameter.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, pneutype::PneuString)]
#[pneu_string(as_pneu_str = "as_self_hash_url_str", borrow = "SelfHashURLStr")]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", pneu_string(deserialize))]
pub struct SelfHashURL(String);

impl SelfHashURL {
    pub fn new(mb_hash: &mbx::MBHashStr) -> Self {
        let mut s = String::with_capacity("vjson:///".len() + mb_hash.len());
        s.push_str("vjson:///");
        s.push_str(mb_hash.as_str());
        Self::try_from(s).unwrap()
    }
    pub fn set_self_hash_slots_to_mb_hash(&mut self, mb_hash: &mbx::MBHashStr) {
        self.0 = format!("vjson:///{}", mb_hash);
        assert!(SelfHashURLStr::validate(&self.0).is_ok());
    }
}

impl HashT<mbx::MBHashStr> for SelfHashURL {
    fn as_hash_ref(&self) -> &mbx::MBHashStr {
        self.mb_hash_o().unwrap()
    }
}
