use crate::NamedHashFunction;
use std::borrow::Cow;

/// This structure represents an arbitrary hash value with an associated hash function.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct HashBytes<'a> {
    named_hash_function: NamedHashFunction,
    #[cfg_attr(feature = "serde", serde(borrow))]
    byte_v: Cow<'a, [u8]>,
}

impl<'a> HashBytes<'a> {
    pub fn new(named_hash_function: NamedHashFunction, byte_v: Cow<'a, [u8]>) -> Self {
        Self {
            named_hash_function,
            byte_v,
        }
    }
    pub fn named_hash_function(&self) -> NamedHashFunction {
        self.named_hash_function
    }
    pub fn bytes(&self) -> &[u8] {
        self.byte_v.as_ref()
    }
    pub fn into_owned(self) -> HashBytes<'static> {
        HashBytes {
            named_hash_function: self.named_hash_function,
            byte_v: Cow::Owned(self.byte_v.into_owned()),
        }
    }
    pub fn to_owned(&self) -> HashBytes<'static> {
        HashBytes {
            named_hash_function: self.named_hash_function.clone(),
            byte_v: Cow::Owned(self.byte_v.to_vec()),
        }
    }
}

// // TODO: Figure out how to implement HashRefT for HashBytes<'a> for arbitrary 'a.
// impl HashRefT for HashBytes<'static> {
//     type HashFunction = NamedHashFunction;
//     fn hash_function(&self) -> Self::HashFunction {
//         self.named_hash_function
//     }
//     fn is_placeholder(&self) -> bool {
//         self.byte_v.iter().all(|b| *b == 0u8)
//     }
// }

// // TODO: Implement HashT for HashBytes<'a>.
