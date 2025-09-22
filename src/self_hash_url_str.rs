use crate::{ensure, Error, HashT};

/// This is the str-based analog to SelfHashURL.
#[derive(Debug, Eq, Hash, Ord, PartialEq, PartialOrd, pneutype::PneuStr)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", pneu_str(deserialize))]
#[repr(transparent)]
pub struct SelfHashURLStr(str);

impl SelfHashURLStr {
    pub fn mb_hash_o(&self) -> Option<&mbx::MBHashStr> {
        let stripped = self.0.strip_prefix("vjson:///").unwrap();
        if let Ok(mb_hash) = mbx::MBHashStr::new_ref(stripped) {
            Some(mb_hash)
        } else {
            // If what follows "vjson:///" doesn't parse as a valid mbx::MBHashStr, then consider it "None".
            None
        }
    }
}

impl HashT<mbx::MBHashStr> for SelfHashURLStr {
    fn as_hash_ref(&self) -> &mbx::MBHashStr {
        if let Some(mb_hash) = self.mb_hash_o() {
            mb_hash
        } else {
            panic!("programmer error: need to handle this case");
        }
    }
}

impl pneutype::Validate for SelfHashURLStr {
    type Data = str;
    type Error = Error;
    fn validate(s: &Self::Data) -> std::result::Result<(), Self::Error> {
        ensure!(
            s.starts_with("vjson:///"),
            "self-hash URL must start with \"vjson:///\""
        );
        Ok(())
    }
}
