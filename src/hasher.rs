use crate::{Hash, HashFunction};

pub trait Hasher: std::any::Any + std::io::Write {
    fn as_any(&self) -> &dyn std::any::Any;
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any>;
    fn hash_function(&self) -> &dyn HashFunction;
    fn update(&mut self, byte_v: &[u8]);
    fn finalize(self: Box<Self>) -> Box<dyn Hash>;
}
