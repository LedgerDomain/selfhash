use crate::{bail, Blake3, Error, Hash, HashFunction, Hasher, Result, SHA256, SHA512};

/// A hash function represented by its official name.
#[derive(
    Clone,
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

    pub fn try_from_keri_prefix(keri_prefix: &str) -> Result<Self> {
        match keri_prefix {
            "E" => Ok(Self::BLAKE3),
            "I" => Ok(Self::SHA_256),
            "0G" => Ok(Self::SHA_512),
            _ => bail!("unrecognized keri_prefix {:?}", keri_prefix),
        }
    }
    pub fn as_hash_function(&self) -> &'static dyn HashFunction {
        match self.0 {
            BLAKE3_STR => &Blake3,
            SHA_256_STR => &SHA256,
            SHA_512_STR => &SHA512,
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

impl HashFunction for NamedHashFunction {
    fn named_hash_function(&self) -> NamedHashFunction {
        self.clone()
    }
    fn keri_prefix(&self) -> &'static str {
        self.as_hash_function().keri_prefix()
    }
    fn placeholder_hash(&self) -> &'static dyn Hash {
        self.as_hash_function().placeholder_hash()
    }
    fn equals(&self, other: &dyn HashFunction) -> bool {
        self.as_hash_function().equals(other)
    }
    fn new_hasher(&self) -> Box<dyn Hasher> {
        self.as_hash_function().new_hasher()
    }
}
