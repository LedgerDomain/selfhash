use crate::{
    bail, base64_decode_256_bits, base64_decode_512_bits, require, Error, Hash, HashBytes,
    HashFunction, NamedHashFunction, PreferredHashFormat,
};
use std::borrow::Cow;

/// This is the str-based analog to KERIHash.
#[derive(Debug, Eq, Hash, PartialEq, pneutype::PneuStr)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", pneu_str(deserialize))]
#[repr(transparent)]
pub struct KERIHashStr(str);

impl KERIHashStr {
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
    pub fn to_hash_bytes<'h>(&self) -> HashBytes<'h> {
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

impl<'a> Hash for &'a KERIHashStr {
    fn hash_function(&self) -> &'static dyn HashFunction {
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
        std::borrow::Cow::Borrowed(*self).into()
    }
}

impl pneutype::Validate for KERIHashStr {
    type Data = str;
    type Error = Error;
    fn validate(s: &Self::Data) -> Result<(), Self::Error> {
        require!(s.len() >= 1, "string too short to be a KERIHash");
        require!(
            s.is_ascii(),
            "KERIHash strings must contain only ASCII chars"
        );
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
                bail!(
                    "string was not a valid length for a KERIHash (length was {})",
                    s.len()
                );
            }
        }
        Ok(())
    }
}
