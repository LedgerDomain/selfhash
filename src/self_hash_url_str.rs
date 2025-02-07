use crate::{require, Error, Hash, HashFunction, KERIHashStr, PreferredHashFormat, Result};

/// This is the str-based analog to SelfHashURL.
#[derive(Debug, Eq, Hash, Ord, PartialEq, PartialOrd, pneutype::PneuStr)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", pneu_str(deserialize))]
#[repr(transparent)]
pub struct SelfHashURLStr(str);

impl SelfHashURLStr {
    // TODO: This really has to return Option<&KERIHashStr>
    pub fn keri_hash_o(&self) -> Option<&KERIHashStr> {
        let stripped = self.0.strip_prefix("vjson:///").unwrap();
        if let Ok(keri_hash) = KERIHashStr::new_ref(stripped) {
            Some(keri_hash)
        } else {
            // If what follows "vjson:///" doesn't parse as a valid KERIHash, then consider it "None".
            None
        }
    }
}

impl<'a> Hash for &'a SelfHashURLStr {
    fn hash_function(&self) -> Result<&'static dyn HashFunction> {
        self.keri_hash_o().unwrap().hash_function()
    }
    fn as_preferred_hash_format<'s: 'h, 'h>(&'s self) -> Result<PreferredHashFormat<'h>> {
        Ok(std::borrow::Cow::Borrowed(self.keri_hash_o().unwrap()).into())
    }
}

impl pneutype::Validate for SelfHashURLStr {
    type Data = str;
    type Error = Error;
    fn validate(s: &Self::Data) -> std::result::Result<(), Self::Error> {
        require!(
            s.starts_with("vjson:///"),
            "self-hash URL must start with \"vjson:///\""
        );
        // require!(
        //     KERIHashStr::validate(s.strip_prefix("vjson:///").unwrap()).is_ok(),
        //     "self-hash URL must have the form \"vjson:///X\" where X is a valid KERIHash string"
        // );
        Ok(())
    }
}
