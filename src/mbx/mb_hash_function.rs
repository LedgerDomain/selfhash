use crate::{ensure, HashFunctionT, MBHasher, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MBHashFunction {
    base: mbx::Base,
    codec: u64,
}

impl MBHashFunction {
    /// Generic constructor for the MBHashFunction type using the given base and hash function specified by codec.
    pub fn new(base: mbx::Base, codec: u64) -> Result<Self> {
        ensure!(
            mbx::CodecCategory::from_codec(codec) == mbx::CodecCategory::Multihash,
            "codec 0x{:02x} is not a multihash",
            codec,
        );
        Ok(Self { base, codec })
    }
    /// Convenience constructor for the BLAKE3 hash function using the given base.
    pub fn blake3(base: mbx::Base) -> Self {
        Self::new(base, ssi_multicodec::BLAKE3).expect("programmer error")
    }
    /// Convenience constructor for the SHA-224 hash function (part of the SHA2 family) using the given base.
    pub fn sha224(base: mbx::Base) -> Self {
        Self::new(base, ssi_multicodec::SHA2_224).expect("programmer error")
    }
    /// Convenience constructor for the SHA-256 hash function (part of the SHA2 family) using the given base.
    pub fn sha256(base: mbx::Base) -> Self {
        Self::new(base, ssi_multicodec::SHA2_256).expect("programmer error")
    }
    /// Convenience constructor for the SHA-384 hash function (part of the SHA2 family) using the given base.
    pub fn sha384(base: mbx::Base) -> Self {
        Self::new(base, ssi_multicodec::SHA2_384).expect("programmer error")
    }
    /// Convenience constructor for the SHA-512 hash function (part of the SHA2 family) using the given base.
    pub fn sha512(base: mbx::Base) -> Self {
        Self::new(base, ssi_multicodec::SHA2_512).expect("programmer error")
    }
    /// Convenience constructor for the SHA3-224 hash function (part of the SHA3 family) using the given base.
    pub fn sha3_224(base: mbx::Base) -> Self {
        Self::new(base, ssi_multicodec::SHA3_224).expect("programmer error")
    }
    /// Convenience constructor for the SHA3-256 hash function (part of the SHA3 family) using the given base.
    pub fn sha3_256(base: mbx::Base) -> Self {
        Self::new(base, ssi_multicodec::SHA3_256).expect("programmer error")
    }
    /// Convenience constructor for the SHA3-384 hash function (part of the SHA3 family) using the given base.
    pub fn sha3_384(base: mbx::Base) -> Self {
        Self::new(base, ssi_multicodec::SHA3_384).expect("programmer error")
    }
    /// Convenience constructor for the SHA3-512 hash function (part of the SHA3 family) using the given base.
    pub fn sha3_512(base: mbx::Base) -> Self {
        Self::new(base, ssi_multicodec::SHA3_512).expect("programmer error")
    }
    pub fn base(&self) -> mbx::Base {
        self.base
    }
    pub fn codec(&self) -> u64 {
        self.codec
    }
    /// Convenience method for hashing a byte vector with this hash function, producing an MBHash value.
    pub fn hash(&self, byte_v: &[u8]) -> mbx::MBHash {
        use crate::HashFunctionT;
        let mut hasher = self.new_hasher();
        use crate::HasherT;
        hasher.update(byte_v);
        hasher.finalize()
    }
}

impl std::hash::Hash for MBHashFunction {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.base.code().hash(state);
        self.codec.hash(state);
    }
}

impl HashFunctionT<mbx::MBHashStr> for MBHashFunction {
    type Hasher = MBHasher;
    fn placeholder_hash(&self) -> std::borrow::Cow<'static, mbx::MBHashStr> {
        // TODO: Return a Cow::Borrowed to a memoized value here.
        match self.codec {
            // codecs corresponding to 28-byte digests
            ssi_multicodec::SHA2_224 | ssi_multicodec::SHA3_224 => std::borrow::Cow::Owned(
                mbx::MBHash::encoded::<28>(self.base, self.codec, [0u8; 28].as_slice())
                    .expect("programmer error"),
            ),
            // codecs corresponding to 32-byte digests
            ssi_multicodec::BLAKE3 | ssi_multicodec::SHA2_256 | ssi_multicodec::SHA3_256 => {
                std::borrow::Cow::Owned(
                    mbx::MBHash::encoded::<32>(self.base, self.codec, [0u8; 32].as_slice())
                        .expect("programmer error"),
                )
            }
            // codecs corresponding to 48-byte digests
            ssi_multicodec::SHA2_384 | ssi_multicodec::SHA3_384 => std::borrow::Cow::Owned(
                mbx::MBHash::encoded::<48>(self.base, self.codec, [0u8; 48].as_slice())
                    .expect("programmer error"),
            ),
            // codecs corresponding to 64-byte digests
            ssi_multicodec::SHA2_512 | ssi_multicodec::SHA3_512 => std::borrow::Cow::Owned(
                mbx::MBHash::encoded::<64>(self.base, self.codec, [0u8; 64].as_slice())
                    .expect("programmer error"),
            ),
            _ => {
                panic!("programmer error: unrecognized codec");
            }
        }
    }
    fn new_hasher(&self) -> Self::Hasher {
        // This allow is necessary if all these features are disabled.
        #[allow(unused_variables)]
        let hasher_b = match self.codec {
            ssi_multicodec::BLAKE3 => {
                #[cfg(feature = "blake3")]
                {
                    crate::Blake3::new_hasher_dyn()
                }
                #[cfg(not(feature = "blake3"))]
                {
                    panic!("programmer error: blake3 feature not enabled");
                }
            }
            ssi_multicodec::SHA2_224 => {
                #[cfg(feature = "sha-224")]
                {
                    crate::SHA224::new_hasher_dyn()
                }
                #[cfg(not(feature = "sha-224"))]
                {
                    panic!("programmer error: sha-224 feature not enabled");
                }
            }
            ssi_multicodec::SHA2_256 => {
                #[cfg(feature = "sha-256")]
                {
                    crate::SHA256::new_hasher_dyn()
                }
                #[cfg(not(feature = "sha-256"))]
                {
                    panic!("programmer error: sha-256 feature not enabled");
                }
            }
            ssi_multicodec::SHA2_384 => {
                #[cfg(feature = "sha-384")]
                {
                    crate::SHA384::new_hasher_dyn()
                }
                #[cfg(not(feature = "sha-384"))]
                {
                    panic!("programmer error: sha-384 feature not enabled");
                }
            }
            ssi_multicodec::SHA2_512 => {
                #[cfg(feature = "sha-512")]
                {
                    crate::SHA512::new_hasher_dyn()
                }
                #[cfg(not(feature = "sha-512"))]
                {
                    panic!("programmer error: sha-512 feature not enabled");
                }
            }
            ssi_multicodec::SHA3_224 => {
                #[cfg(feature = "sha3-224")]
                {
                    crate::SHA3_224::new_hasher_dyn()
                }
                #[cfg(not(feature = "sha3-224"))]
                {
                    panic!("programmer error: sha3-224 feature not enabled");
                }
            }
            ssi_multicodec::SHA3_256 => {
                #[cfg(feature = "sha3-256")]
                {
                    crate::SHA3_256::new_hasher_dyn()
                }
                #[cfg(not(feature = "sha3-256"))]
                {
                    panic!("programmer error: sha3-256 feature not enabled");
                }
            }
            ssi_multicodec::SHA3_384 => {
                #[cfg(feature = "sha3-384")]
                {
                    crate::SHA3_384::new_hasher_dyn()
                }
                #[cfg(not(feature = "sha3-384"))]
                {
                    panic!("programmer error: sha3-384 feature not enabled");
                }
            }
            ssi_multicodec::SHA3_512 => {
                #[cfg(feature = "sha3-512")]
                {
                    crate::SHA3_512::new_hasher_dyn()
                }
                #[cfg(not(feature = "sha3-512"))]
                {
                    panic!("programmer error: sha3-512 feature not enabled");
                }
            }
            _ => panic!("programmer error: unrecognized codec: {:?}", self.codec),
        };
        // This allow is necessary if all these features are disabled.
        #[allow(unreachable_code)]
        MBHasher::new(self.base, self.codec, hasher_b).expect("programmer error")
    }
}
