mod blake3;
mod error;
mod hash_bytes;
mod hash_dyn_t;
mod hash_function_t;
mod hash_ref_t;
mod hash_t;
mod hasher_dyn_t;
mod hasher_t;
#[cfg(feature = "mbx")]
mod mbx;
mod named_hash_function;
#[cfg(feature = "self-hashable-json")]
mod self_hash_url;
#[cfg(feature = "self-hashable-json")]
mod self_hash_url_str;
#[cfg(feature = "self-hashable-json")]
mod self_hashable_json;
mod self_hashable_t;
mod sha256;
mod sha512;

#[cfg(feature = "mbx")]
pub use crate::mbx::{MBHashFunction, MBHasher};
#[cfg(feature = "self-hashable-json")]
pub use crate::self_hash_url::SelfHashURL;
#[cfg(feature = "self-hashable-json")]
pub use crate::self_hash_url_str::SelfHashURLStr;
#[cfg(feature = "self-hashable-json")]
pub use crate::self_hashable_json::SelfHashableJSON;
#[cfg(feature = "jcs")]
pub use crate::self_hashable_t::write_digest_data_using_jcs;
#[cfg(feature = "sha-256")]
pub use crate::sha256::{SHA256Hash, SHA256HashInner};
#[cfg(feature = "sha-512")]
pub use crate::sha512::{SHA512Hash, SHA512HashInner};
pub use crate::{
    blake3::Blake3, error::Error, hash_bytes::HashBytes, hash_dyn_t::HashDynT,
    hash_function_t::HashFunctionT, hash_ref_t::HashRefT, hash_t::HashT, hasher_dyn_t::HasherDynT,
    hasher_t::HasherT, named_hash_function::NamedHashFunction, self_hashable_t::SelfHashableT,
    sha256::SHA256, sha512::SHA512,
};

pub type Result<T> = std::result::Result<T, Error>;
