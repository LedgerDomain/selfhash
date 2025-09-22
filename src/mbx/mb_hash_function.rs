use crate::{ensure, HashFunctionT, MBHasher, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MBHashFunction {
    base: mbx::Base,
    codec: u64,
}

impl MBHashFunction {
    pub fn new(base: mbx::Base, codec: u64) -> Result<Self> {
        ensure!(
            mbx::CodecCategory::from_codec(codec) == mbx::CodecCategory::Multihash,
            "codec 0x{:02x} is not a multihash",
            codec,
        );
        Ok(Self { base, codec })
    }
    pub fn blake3(base: mbx::Base) -> Self {
        Self::new(base, ssi_multicodec::BLAKE3).expect("programmer error")
    }
    pub fn sha2_256(base: mbx::Base) -> Self {
        Self::new(base, ssi_multicodec::SHA2_256).expect("programmer error")
    }
    pub fn sha2_512(base: mbx::Base) -> Self {
        Self::new(base, ssi_multicodec::SHA2_512).expect("programmer error")
    }
    pub fn base(&self) -> mbx::Base {
        self.base
    }
    pub fn codec(&self) -> u64 {
        self.codec
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
            // codecs corresponding to 32-byte digests
            ssi_multicodec::BLAKE3 | ssi_multicodec::SHA2_256 => std::borrow::Cow::Owned(
                mbx::MBHash::encoded::<32>(self.base, self.codec, [0u8; 32].as_slice())
                    .expect("programmer error"),
            ),
            // codecs corresponding to 48-byte digests
            ssi_multicodec::SHA2_384 => std::borrow::Cow::Owned(
                mbx::MBHash::encoded::<48>(self.base, self.codec, [0u8; 48].as_slice())
                    .expect("programmer error"),
            ),
            // codecs corresponding to 64-byte digests
            ssi_multicodec::SHA2_512 => std::borrow::Cow::Owned(
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
            _ => panic!("programmer error: unrecognized codec: {:?}", self.codec),
        };
        // This allow is necessary if all these features are disabled.
        #[allow(unreachable_code)]
        MBHasher::new(self.base, self.codec, hasher_b).expect("programmer error")
    }
}
