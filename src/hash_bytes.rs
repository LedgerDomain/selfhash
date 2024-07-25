use std::borrow::Cow;

use crate::{Hash, HashFunction, KERIHash, NamedHashFunction};

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
    pub fn to_keri_hash(&self) -> Result<KERIHash, &'static str> {
        if self.hash_byte_v.len() != self.named_hash_function.placeholder_bytes().len() {
            return Err(
                "hash_byte_v length does not match expected placeholder bytes length of the NamedHashFunction",
            );
        }
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

// TODO: Try to impl for arbitrary lifetime now that std::any::Any trait is no longer required.
impl Hash for HashBytes<'static> {
    fn hash_function(&self) -> &dyn HashFunction {
        &self.named_hash_function
    }
    fn equals(&self, other: &dyn Hash) -> bool {
        // Check the hash function directly before resorting to converting to HashBytes.
        if !self.named_hash_function.equals(other.hash_function()) {
            return false;
        }
        let other_hash_bytes = other.to_hash_bytes();
        self.hash_byte_v == other_hash_bytes.hash_byte_v
    }
    fn to_hash_bytes(&self) -> HashBytes {
        self.clone()
    }
    fn to_keri_hash(&self) -> KERIHash {
        self.to_keri_hash().expect("this should not fail")
    }
}
