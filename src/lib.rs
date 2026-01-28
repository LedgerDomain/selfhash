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
mod sha224;
mod sha256;
mod sha384;
mod sha3_224;
mod sha3_256;
mod sha3_384;
mod sha3_512;
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
#[cfg(feature = "sha-224")]
pub use crate::sha224::{SHA224Hash, SHA224HashInner};
#[cfg(feature = "sha-256")]
pub use crate::sha256::{SHA256Hash, SHA256HashInner};
#[cfg(feature = "sha-384")]
pub use crate::sha384::{SHA384Hash, SHA384HashInner};
#[cfg(feature = "sha3-224")]
pub use crate::sha3_224::{SHA3_224_Hash, SHA3_224_HashInner};
#[cfg(feature = "sha3-256")]
pub use crate::sha3_256::{SHA3_256_Hash, SHA3_256_HashInner};
#[cfg(feature = "sha3-384")]
pub use crate::sha3_384::{SHA3_384_Hash, SHA3_384_HashInner};
#[cfg(feature = "sha3-512")]
pub use crate::sha3_512::{SHA3_512_Hash, SHA3_512_HashInner};
#[cfg(feature = "sha-512")]
pub use crate::sha512::{SHA512Hash, SHA512HashInner};
pub use crate::{
    blake3::Blake3, error::Error, hash_bytes::HashBytes, hash_dyn_t::HashDynT,
    hash_function_t::HashFunctionT, hash_ref_t::HashRefT, hash_t::HashT, hasher_dyn_t::HasherDynT,
    hasher_t::HasherT, named_hash_function::NamedHashFunction, self_hashable_t::SelfHashableT,
    sha224::SHA224, sha256::SHA256, sha384::SHA384, sha3_224::SHA3_224, sha3_256::SHA3_256,
    sha3_384::SHA3_384, sha3_512::SHA3_512, sha512::SHA512,
};

pub type Result<T> = std::result::Result<T, Error>;
