use crate::{
    require, Hash, HashFunction, KERIHash, NamedHashFunction, PreferredHashFormat, Result,
};
use std::borrow::Cow;

/// This is meant to be used in end-use data structures that are self-hashing.
// TODO: Make elements private and then ensure constructors always render valid data, so that
// some methods (e.g. to_keri_hash) can't fail?
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct HashBytes<'a> {
    pub named_hash_function: NamedHashFunction,
    #[cfg_attr(feature = "serde", serde(borrow))]
    pub hash_byte_v: Cow<'a, [u8]>,
}

impl<'a> HashBytes<'a> {
    pub fn into_owned(self) -> HashBytes<'static> {
        HashBytes {
            named_hash_function: self.named_hash_function,
            hash_byte_v: Cow::Owned(self.hash_byte_v.into_owned()),
        }
    }
    pub fn to_owned(&self) -> HashBytes<'static> {
        HashBytes {
            named_hash_function: self.named_hash_function.clone(),
            hash_byte_v: Cow::Owned(self.hash_byte_v.to_vec()),
        }
    }
    pub fn to_keri_hash(&self) -> Result<KERIHash> {
        require!(self.hash_byte_v.len() == self.named_hash_function.placeholder_bytes().len(), "hash_byte_v length ({}) does not match expected placeholder bytes length ({}) of the NamedHashFunction", self.hash_byte_v.len(), self.named_hash_function.placeholder_bytes().len());
        let keri_hash_string = match self.named_hash_function.placeholder_bytes().len() {
            32 => {
                let mut buffer = [0u8; 43];
                let verifying_key = crate::base64_encode_256_bits(
                    self.hash_byte_v.as_ref().try_into().expect("temp hack"),
                    &mut buffer,
                );
                format!(
                    "{}{}",
                    self.named_hash_function.keri_prefix(),
                    verifying_key
                )
            }
            64 => {
                let mut buffer = [0u8; 86];
                let verifying_key = crate::base64_encode_512_bits(
                    self.hash_byte_v.as_ref().try_into().expect("temp hack"),
                    &mut buffer,
                );
                format!(
                    "{}{}",
                    self.named_hash_function.keri_prefix(),
                    verifying_key
                )
            }
            _ => {
                panic!("this should not be possible");
            }
        };
        Ok(KERIHash::try_from(keri_hash_string)
            .expect("programmer error: should be a valid KERIHash by construction"))
    }
}

impl AsRef<[u8]> for HashBytes<'_> {
    fn as_ref(&self) -> &[u8] {
        self.hash_byte_v.as_ref()
    }
}

impl std::ops::Deref for HashBytes<'_> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.hash_byte_v.as_ref()
    }
}

impl Hash for HashBytes<'_> {
    fn hash_function(&self) -> &'static dyn HashFunction {
        self.named_hash_function.as_hash_function()
    }
    /// This will not allocate.
    fn as_preferred_hash_format<'s: 'h, 'h>(&'s self) -> PreferredHashFormat<'h> {
        HashBytes::<'h> {
            named_hash_function: self.named_hash_function.clone(),
            hash_byte_v: Cow::Borrowed(&self.hash_byte_v),
        }
        .into()
    }
    /// This will not allocate.
    fn to_hash_bytes<'s: 'h, 'h>(&'s self) -> HashBytes<'h> {
        HashBytes::<'h> {
            named_hash_function: self.named_hash_function.clone(),
            hash_byte_v: Cow::Borrowed(&self.hash_byte_v),
        }
    }
}
