use std::borrow::Cow;

use crate::{base64_decode_256_bits, base64_decode_512_bits, Hash, HashBytes, NamedHashFunction};

/// This is a concise, ASCII-only representation of a hash value, which comes from the KERI spec.
#[derive(Clone, Debug, derive_more::Display, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct KERIHash(pub(crate) String);

impl KERIHash {
    /// This returns the prefix portion of the KERIHash string, which defines which hash function
    /// was used to generate the hash.
    pub fn keri_prefix(&self) -> &str {
        match self.len() {
            44 => {
                // NOTE: This assumes that 44 chars imply a 1-char prefix and a 43-char base64 string.
                &self.0[..1]
            }
            88 => {
                // NOTE: This assumes that 88 chars imply a 2-char prefix and an 86-char base64 string.
                &self.0[..2]
            }
            _ => {
                panic!("this should not be possible because of check in from_str");
            }
        }
    }
    /// This returns the data portion of the KERIHash string, which is the base64url-no-pad-encoded hash bytes.
    pub fn data(&self) -> &str {
        match self.len() {
            44 => {
                // NOTE: This assumes that 44 chars imply a 1-char prefix and a 43-char base64 string.
                &self.0[1..]
            }
            88 => {
                // NOTE: This assumes that 88 chars imply a 2-char prefix and an 86-char base64 string.
                &self.0[2..]
            }
            _ => {
                panic!("this should not be possible because of check in from_str");
            }
        }
    }
    pub fn to_hash_bytes(&self) -> HashBytes {
        match self.len() {
            44 => {
                // NOTE: This assumes that 44 chars imply a 1-char prefix and a 43-char base64 string.
                let keri_prefix = &self.0[..1];
                let data = &self.0[1..];
                let named_hash_function = NamedHashFunction::try_from_keri_prefix(keri_prefix)
                    .expect("this should not fail because of check in from_str");
                let mut buffer = [0u8; 33];
                let hash_byte_v = crate::base64_decode_256_bits(data, &mut buffer)
                    .expect("this should not fail because of check in from_str");
                HashBytes {
                    named_hash_function,
                    hash_byte_v: Cow::Owned(hash_byte_v.to_vec()),
                }
            }
            88 => {
                // NOTE: This assumes that 88 chars imply a 2-char prefix and an 86-char base64 string.
                let keri_prefix = &self.0[..2];
                let data = &self.0[2..];
                let named_hash_function = NamedHashFunction::try_from_keri_prefix(keri_prefix)
                    .expect("this should not fail because of check in from_str");
                let mut buffer = [0u8; 66];
                let hash_byte_v = crate::base64_decode_512_bits(data, &mut buffer)
                    .expect("this should not fail because of check in from_str");
                HashBytes {
                    named_hash_function,
                    hash_byte_v: Cow::Owned(hash_byte_v.to_vec()),
                }
            }
            _ => {
                panic!("this should not be possible because of check in from_str");
            }
        }
    }
}

impl std::ops::Deref for KERIHash {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl std::str::FromStr for KERIHash {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        validate_keri_hash_string(s)?;
        Ok(Self(s.to_string()))
    }
}
impl TryFrom<&str> for KERIHash {
    type Error = &'static str;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        validate_keri_hash_string(value)?;
        Ok(Self(value.to_string()))
    }
}

impl TryFrom<String> for KERIHash {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_keri_hash_string(value.as_str())?;
        Ok(Self(value))
    }
}

fn validate_keri_hash_string(s: &str) -> Result<(), &'static str> {
    if s.len() < 1 {
        return Err("string too short to be a KERIHash");
    }
    if !s.is_ascii() {
        return Err("KERIHash strings must contain only ASCII chars");
    }
    match s.len() {
        44 => {
            // NOTE: This assumes that 44 chars imply a 1-char prefix and a 43-char base64 string.
            let keri_prefix = &s[..1];
            let data = &s[1..];
            // This just verifies that the prefix is valid.
            NamedHashFunction::try_from_keri_prefix(keri_prefix)?;
            // This just verifies that the data is valid.
            let mut buffer = [0u8; 33];
            base64_decode_256_bits(data, &mut buffer)?;
        }
        88 => {
            // NOTE: This assumes that 88 chars imply a 2-char prefix and an 86-char base64 string.
            let keri_prefix = &s[..2];
            let data = &s[2..];
            // This just verifies that the prefix is valid.
            NamedHashFunction::try_from_keri_prefix(keri_prefix)?;
            // This just verifies that the data is valid.
            let mut buffer = [0u8; 66];
            base64_decode_512_bits(data, &mut buffer)?;
        }
        _ => {
            return Err("string was not a valid length for a KERIHash");
        }
    }
    Ok(())
}

impl Hash for KERIHash {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn hash_function(&self) -> &dyn crate::HashFunction {
        match self.keri_prefix() {
            "E" => &crate::Blake3,
            "I" => &crate::SHA256,
            "0G" => &crate::SHA512,
            _ => {
                panic!("this should not be possible because of check in from_str");
            }
        }
    }
    fn equals(&self, other: &dyn Hash) -> bool {
        // Check the hash function directly before resorting to converting to KERIHash.
        if !self.hash_function().equals(other.hash_function()) {
            return false;
        }
        let other_keri_hash = other.to_keri_hash();
        *self == other_keri_hash
    }
    fn to_hash_bytes(&self) -> HashBytes<'_> {
        self.to_hash_bytes()
    }
    fn to_keri_hash(&self) -> KERIHash {
        self.clone()
    }
}
