mod base64;
mod blake3;
mod error;
mod hash;
mod hash_bytes;
mod hash_function;
mod hasher;
mod keri_hash;
mod keri_hash_str;
mod named_hash_function;
mod preferred_hash_format;
#[cfg(feature = "self-hashable-json")]
mod self_hash_url;
#[cfg(feature = "self-hashable-json")]
mod self_hash_url_str;
mod self_hashable;
#[cfg(feature = "self-hashable-json")]
mod self_hashable_json;
mod sha256;
mod sha512;

pub use crate::base64::{base64_decode_256_bits, base64_encode_256_bits};
pub use crate::base64::{base64_decode_512_bits, base64_encode_512_bits};
#[cfg(feature = "self-hashable-json")]
pub use crate::self_hash_url::SelfHashURL;
#[cfg(feature = "self-hashable-json")]
pub use crate::self_hash_url_str::SelfHashURLStr;
#[cfg(feature = "jcs")]
pub use crate::self_hashable::write_digest_data_using_jcs;
#[cfg(feature = "self-hashable-json")]
pub use crate::self_hashable_json::SelfHashableJSON;
#[cfg(feature = "sha-256")]
pub use crate::sha256::{SHA256Hash, SHA256HashInner};
#[cfg(feature = "sha-512")]
pub use crate::sha512::{SHA512Hash, SHA512HashInner};
pub use crate::{
    blake3::Blake3, error::Error, hash::Hash, hash_bytes::HashBytes, hash_function::HashFunction,
    hasher::Hasher, keri_hash::KERIHash, keri_hash_str::KERIHashStr,
    named_hash_function::NamedHashFunction, preferred_hash_format::PreferredHashFormat,
    self_hashable::SelfHashable, sha256::SHA256, sha512::SHA512,
};

pub type Result<T> = std::result::Result<T, Error>;
