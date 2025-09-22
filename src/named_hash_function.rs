use crate::{bail, Error, HashFunctionT};

/// A hash function represented by its official name.
#[derive(
    Clone,
    Copy,
    Debug,
    derive_more::Display,
    derive_more::Deref,
    Eq,
    derive_more::Into,
    Ord,
    PartialEq,
    PartialOrd,
)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::DeserializeFromStr, serde_with::SerializeDisplay)
)]
pub struct NamedHashFunction(&'static str);

const BLAKE3_STR: &'static str = "BLAKE3";
const SHA_256_STR: &'static str = "SHA-256";
const SHA_512_STR: &'static str = "SHA-512";

impl NamedHashFunction {
    /// See https://github.com/BLAKE3-team/BLAKE3
    pub const BLAKE3: NamedHashFunction = NamedHashFunction(BLAKE3_STR);
    /// See https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
    pub const SHA_256: NamedHashFunction = NamedHashFunction(SHA_256_STR);
    /// See https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
    pub const SHA_512: NamedHashFunction = NamedHashFunction(SHA_512_STR);

    #[cfg(feature = "mbx")]
    pub fn as_mb_hash_function(&self, base: mbx::Base) -> crate::MBHashFunction {
        match self.0 {
            BLAKE3_STR => crate::MBHashFunction::blake3(base),
            SHA_256_STR => crate::MBHashFunction::sha2_256(base),
            SHA_512_STR => crate::MBHashFunction::sha2_512(base),
            _ => {
                panic!("programmer error: unrecognized hash function name");
            }
        }
    }
    pub fn placeholder_bytes(&self) -> &'static [u8] {
        match self.0 {
            BLAKE3_STR => &[0u8; 32],
            SHA_256_STR => &[0u8; 32],
            SHA_512_STR => &[0u8; 64],
            _ => {
                panic!("programmer error: unrecognized hash function name");
            }
        }
    }
}

impl std::str::FromStr for NamedHashFunction {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            BLAKE3_STR => Ok(NamedHashFunction::BLAKE3),
            SHA_256_STR => Ok(NamedHashFunction::SHA_256),
            SHA_512_STR => Ok(NamedHashFunction::SHA_512),
            _ => bail!("unrecognized hash function name {:?}", s),
        }
    }
}

#[cfg(feature = "mbx")]
impl HashFunctionT<mbx::MBHashStr> for NamedHashFunction {
    type Hasher = crate::MBHasher;
    fn placeholder_hash(&self) -> std::borrow::Cow<'static, mbx::MBHashStr> {
        self.as_mb_hash_function(mbx::Base::Base64Url)
            .placeholder_hash()
    }
    fn new_hasher(&self) -> Self::Hasher {
        self.as_mb_hash_function(mbx::Base::Base64Url).new_hasher()
    }
}

// impl HashFunctionT<HashBytes<'static>> for NamedHashFunction {
//     type Hasher = HashBytesHasher;
//     fn placeholder_hash(&self) -> std::borrow::Cow<'static, HashBytes<'static>> {
//         std::borrow::Cow::Owned(HashBytes::new(
//             self.clone(),
//             std::borrow::Cow::Borrowed(self.placeholder_bytes()),
//         ))
//     }
//     fn new_hasher(&self) -> Self::Hasher {
//         let hasher_b: Box<dyn HasherDynT> = match *self {
//             NamedHashFunction::BLAKE3 => Box::new(crate::Blake3.new_hasher()),
//             NamedHashFunction::SHA_256 => Box::new(crate::SHA256.new_hasher()),
//             NamedHashFunction::SHA_512 => Box::new(crate::SHA512.new_hasher()),
//             _ => {
//                 panic!("programmer error: unrecognized hash function name");
//             }
//         };
//         HashBytesHasher {
//             named_hash_function: self.clone(),
//             hasher_b,
//         }
//     }
// }

// // TEMP HACK
// pub struct HashBytesHasher {
//     named_hash_function: NamedHashFunction,
//     hasher_b: Box<dyn HasherDynT>,
// }

// impl HasherT for HashBytesHasher {
//     type HashRef = HashBytes<'static>;
//     fn hash_function(&self) -> <Self::HashRef as HashRefT>::HashFunction {
//         self.named_hash_function
//     }
//     fn update(&mut self, byte_v: &[u8]) {
//         self.hasher_b.update(byte_v);
//     }
//     fn finalize(self) -> <Self::HashRef as ToOwned>::Owned {
//         HashBytes::new(
//             self.named_hash_function,
//             self.hasher_b.finalize().hash_bytes().into_owned().into(),
//         )
//     }
// }

// impl std::io::Write for HashBytesHasher {
//     fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
//         self.hasher_b.write(buf)
//     }
//     fn flush(&mut self) -> std::io::Result<()> {
//         self.hasher_b.flush()
//     }
// }
