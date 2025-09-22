use crate::{HashRefT, MBHashFunction};

impl HashRefT for mbx::MBHashStr {
    type HashFunction = MBHashFunction;
    fn hash_function(&self) -> Self::HashFunction {
        // NOTE: Use 64 bytes as max supported digest size.
        let multihash = self.decoded::<64>().expect("programmer error");
        MBHashFunction::new(self.base(), multihash.code()).expect("programmer error")
    }
    fn is_placeholder(&self) -> bool {
        // NOTE: Use 64 bytes as max supported digest size.
        self.decoded::<64>()
            .expect("programmer error")
            .digest()
            .iter()
            .all(|b| *b == 0u8)
    }
}
