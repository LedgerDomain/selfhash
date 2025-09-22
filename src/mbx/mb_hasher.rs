use crate::{ensure, HashRefT, HasherDynT, HasherT, MBHashFunction, Result};

/// A hasher for the MBHash type.  Note that because the hash function is determined by a runtime
/// value (codec), the hasher_b Box contains dyn HasherDynT.
pub struct MBHasher {
    base: mbx::Base,
    codec: u64,
    hasher_b: Box<dyn HasherDynT>,
}

impl MBHasher {
    pub fn new(base: mbx::Base, codec: u64, hasher_b: Box<dyn HasherDynT>) -> Result<Self> {
        // TODO: Check that codec matches the hasher_b.
        ensure!(
            mbx::CodecCategory::from_codec(codec) == mbx::CodecCategory::Multihash,
            "codec 0x{:02x} is not a multihash",
            codec
        );
        Ok(Self {
            base,
            codec,
            hasher_b,
        })
    }
    pub fn base(&self) -> mbx::Base {
        self.base
    }
    pub fn codec(&self) -> u64 {
        self.codec
    }
}

impl HasherT for MBHasher {
    type HashRef = mbx::MBHashStr;
    fn hash_function(&self) -> <Self::HashRef as HashRefT>::HashFunction {
        MBHashFunction::new(self.base, self.codec).expect("programmer error")
    }
    fn update(&mut self, byte_v: &[u8]) {
        self.hasher_b.update(byte_v);
    }
    fn finalize(self) -> <Self::HashRef as ToOwned>::Owned {
        let hash_b = self.hasher_b.finalize();
        // NOTE: Use 64 bytes as max supported digest size.
        mbx::MBHash::encoded::<64>(self.base, self.codec, hash_b.hash_bytes().as_ref())
            .expect("programmer error")
    }
}

impl std::io::Write for MBHasher {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.hasher_b.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.hasher_b.flush()
    }
}
