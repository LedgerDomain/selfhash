use selfhash::{ensure, Error};

pub fn hash_from_hash_bytes(hash_bytes: selfhash::HashBytes<'_>) -> Box<dyn selfhash::HashDynT> {
    match hash_bytes.named_hash_function() {
        selfhash::NamedHashFunction::BLAKE3 => {
            #[cfg(feature = "blake3")]
            {
                let hash_byte_v: [u8; 32] = hash_bytes
                    .bytes()
                    // .into_owned()
                    .try_into()
                    .expect("programmer error");
                let hash = blake3::Hash::from(hash_byte_v);
                Box::new(hash)
            }
            #[cfg(not(feature = "blake3"))]
            {
                panic!("programmer error: blake3 feature not enabled");
            }
        }
        selfhash::NamedHashFunction::SHA_256 => {
            #[cfg(feature = "sha-256")]
            {
                let hash = selfhash::SHA256Hash::from(selfhash::SHA256HashInner::clone_from_slice(
                    hash_bytes.bytes(),
                ));
                Box::new(hash)
            }
            #[cfg(not(feature = "sha-256"))]
            {
                panic!("programmer error: sha-256 feature not enabled");
            }
        }
        selfhash::NamedHashFunction::SHA_512 => {
            #[cfg(feature = "sha-512")]
            {
                let hash = selfhash::SHA512Hash::from(selfhash::SHA512HashInner::clone_from_slice(
                    hash_bytes.bytes(),
                ));
                Box::new(hash)
            }
            #[cfg(not(feature = "sha-512"))]
            {
                panic!("programmer error: sha-512 feature not enabled");
            }
        }
        _ => {
            panic!("programmer error: unrecognized hash function name");
        }
    }
}

//
// HashBytes
//

// /// A simple example of a self-hashing data structure, where the self-hash is kept in HashBytes
// /// format (i.e. binary) for fewer allocations and conversions.  Note that there is only one
// /// self-hash slot in the structure.  An example with multiple self-hash slots is given elsewhere.
// #[derive(Clone, Debug, serde::Serialize)]
// pub struct SimpleDataHash<
//     HashRef: selfhash::HashRefT + ?Sized + ToOwned<Owned = Hash>,
//     Hash: Clone + selfhash::HashT<HashRef> + serde::Serialize,
// > {
//     pub marker: std::marker::PhantomData<HashRef>,
//     /// Self-hash of the previous SimpleData.
//     // #[serde(skip_serializing_if = "Option::is_none")]
//     #[serde(rename = "previous")]
//     pub previous_o: Option<Hash>,
//     pub name: String,
//     pub stuff_count: u32,
//     pub data_byte_v: Vec<u8>,
//     // #[serde(skip_serializing_if = "Option::is_none")]
//     #[serde(rename = "self_hash")]
//     pub self_hash_o: Option<Hash>,
// }

// impl<
//         HashRef: Clone + selfhash::HashRefT + ?Sized + ToOwned<Owned = Hash>,
//         Hash: Clone + selfhash::HashT<HashRef> + serde::Serialize,
//     > selfhash::SelfHashableT<HashRef> for SimpleDataHash<HashRef, Hash>
// {
//     fn write_digest_data(
//         &self,
//         hasher: &mut <<HashRef as selfhash::HashRefT>::HashFunction as selfhash::HashFunctionT<
//             HashRef,
//         >>::Hasher,
//     ) -> selfhash::Result<()> {
//         selfhash::write_digest_data_using_jcs(self, hasher)
//     }
//     fn self_hash_oi<'a, 'b: 'a>(
//         &'b self,
//     ) -> selfhash::Result<Box<dyn std::iter::Iterator<Item = Option<&'b HashRef>> + 'a>> {
//         Ok(Box::new(std::iter::once(
//             self.self_hash_o.as_ref().map(|s| s.as_hash_ref()),
//         )))
//     }
//     // fn set_self_hash_slots_to(&mut self, hash: &HashRef) -> selfhash::Result<()> {
//     //     self.self_hash_o = Some(hash.to_owned());
//     //     Ok(())
//     // }
//     fn set_self_hash_slots_to(&mut self, hash: &HashRef) -> selfhash::Result<()> {
//         self.self_hash_o = Some(hash.to_owned());
//         Ok(())
//     }
// }

// fn test_self_hashable_simple_data_hash_case<
//     // HashFunction: std::fmt::Debug + selfhash::HashFunctionT<HashRef>,
//     HashRef: Clone + selfhash::HashRefT + ?Sized + ToOwned<Owned = Hash>,
//     Hash: Clone + selfhash::HashT<HashRef> + serde::Serialize,
// >(
//     hash_function: <HashRef as selfhash::HashRefT>::HashFunction,
// ) where
//     <HashRef as selfhash::HashRefT>::HashFunction: std::fmt::Debug,
// {
//     println!("---------------------------------------------------");
//     println!(
//         "test_self_hashable_simple_data_hash_case; hash_function: {:?}",
//         hash_function
//     );

//     let mut simple_data_0 = SimpleDataHash::<HashRef, Hash> {
//         marker: std::marker::PhantomData,
//         previous_o: None,
//         name: "hippodonkey".to_string(),
//         stuff_count: 42,
//         data_byte_v: vec![0x01, 0x02, 0x03],
//         self_hash_o: None,
//     };
//     // println!("simple_data_0 before self-hash: {:#?}", simple_data_0);
//     println!(
//         "simple_data_0 before self-hash as JCS: {}",
//         std::str::from_utf8(
//             serde_json_canonicalizer::to_vec(&simple_data_0)
//                 .expect("pass")
//                 .as_slice()
//         )
//         .expect("pass")
//     );
//     use selfhash::{HashFunctionT, SelfHashableT};
//     simple_data_0
//         .self_hash(hash_function.new_hasher())
//         .expect("pass");
//     // println!("simple_data_0 after self-hash: {:#?}", simple_data_0);
//     println!(
//         "simple_data_0 after self-hash as JCS: {}",
//         std::str::from_utf8(
//             serde_json_canonicalizer::to_vec(&simple_data_0)
//                 .expect("pass")
//                 .as_slice()
//         )
//         .expect("pass")
//     );
//     simple_data_0.verify_self_hashes().expect("pass");
//     println!("simple_data_0 self self-hash verified!");
//     // Let's make sure that altering the data causes the verification to fail.
//     let mut altered_simple_data_0 = simple_data_0.clone();
//     altered_simple_data_0.name = "maaaaaaaaaa".to_string();
//     assert!(altered_simple_data_0.verify_self_hashes().is_err());

//     let mut simple_data_1 = SimpleDataHash {
//         marker: std::marker::PhantomData,
//         previous_o: simple_data_0.self_hash_o.clone(),
//         name: "grippoponkey".to_string(),
//         stuff_count: 43,
//         data_byte_v: vec![0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80],
//         self_hash_o: None,
//     };
//     // println!("simple_data_1 before self-hash: {:#?}", simple_data_1);
//     println!(
//         "simple_data_1 before self-hash as JCS: {}",
//         std::str::from_utf8(
//             serde_json_canonicalizer::to_vec(&simple_data_1)
//                 .expect("pass")
//                 .as_slice()
//         )
//         .expect("pass")
//     );
//     simple_data_1
//         .self_hash(hash_function.new_hasher())
//         .expect("pass");
//     // println!("simple_data_1 after self-hash: {:#?}", simple_data_1);
//     println!(
//         "simple_data_1 after self-hash as JCS: {}",
//         std::str::from_utf8(
//             serde_json_canonicalizer::to_vec(&simple_data_1)
//                 .expect("pass")
//                 .as_slice()
//         )
//         .expect("pass")
//     );
//     simple_data_1.verify_self_hashes().expect("pass");
//     println!("simple_data_1 self self-hash verified!");
// }

// #[test]
// #[serial_test::serial]
// fn test_self_hashable_simple_data_hash_blake3() {
//     test_self_hashable_simple_data_hash_case::<blake3::Hash, selfhash::Blake3>(selfhash::Blake3);
// }

// #[test]
// #[serial_test::serial]
// fn test_self_hashable_simple_data_hash_sha256() {
//     test_self_hashable_simple_data_hash_case(selfhash::SHA256);
// }

// #[test]
// #[serial_test::serial]
// fn test_self_hashable_simple_data_hash_sha512() {
//     test_self_hashable_simple_data_hash_case(selfhash::SHA512);
// }

//
// MBX
//

/// MBHash-using version of SimpleData.
#[cfg(feature = "mbx")]
#[derive(Clone, Debug, serde::Serialize)]
pub struct SimpleDataMBHash {
    /// Self-hash of the previous SimpleDataKERIHash.
    #[serde(rename = "previous")]
    pub previous_o: Option<mbx::MBHash>,
    pub name: String,
    pub stuff_count: u32,
    pub data_byte_v: Vec<u8>,
    /// Self-hash of this data.
    #[serde(rename = "self_hash")]
    pub self_hash_o: Option<mbx::MBHash>,
    // pub compound: String,
}

#[cfg(feature = "mbx")]
impl selfhash::SelfHashableT<mbx::MBHashStr> for SimpleDataMBHash {
    fn write_digest_data(
        &self,
        hasher: &mut <<mbx::MBHashStr as selfhash::HashRefT>::HashFunction as selfhash::HashFunctionT<mbx::MBHashStr>>::Hasher,
    ) -> selfhash::Result<()> {
        selfhash::write_digest_data_using_jcs(self, hasher)
    }
    fn self_hash_oi<'a, 'b: 'a>(
        &'b self,
    ) -> selfhash::Result<Box<dyn std::iter::Iterator<Item = Option<&'b mbx::MBHashStr>> + 'a>>
    {
        Ok(Box::new(std::iter::once(
            self.self_hash_o
                .as_ref()
                .map(|s| -> &'b mbx::MBHashStr { s }),
        )))
    }
    fn set_self_hash_slots_to(&mut self, hash: &mbx::MBHashStr) -> selfhash::Result<()> {
        self.self_hash_o = Some(hash.to_owned());
        Ok(())
    }
}

#[cfg(feature = "mbx")]
#[test]
#[serial_test::serial]
fn test_self_hashable_mb_hash() {
    for base in [
        mbx::Base::Base16Lower,
        mbx::Base::Base16Upper,
        mbx::Base::Base32Lower,
        mbx::Base::Base32Upper,
        mbx::Base::Base58Btc,
        mbx::Base::Base64Url,
    ] {
        for codec in [
            ssi_multicodec::BLAKE3,
            ssi_multicodec::SHA2_256,
            ssi_multicodec::SHA2_512,
        ] {
            println!("---------------------------------------------------");
            let hash_function =
                selfhash::MBHashFunction::new(base, codec).expect("programmer error");
            println!(
                "test_self_hashable_mb_hash; {:?}; base: {:?}, codec: {:?} ({:?})",
                hash_function,
                base,
                codec,
                mbx::codec_str(codec)
            );

            let mut simple_data_0 = SimpleDataMBHash {
                previous_o: None,
                name: "hippodonkey".to_string(),
                stuff_count: 42,
                data_byte_v: vec![0x01, 0x02, 0x03],
                self_hash_o: None,
            };
            // println!("simple_data_0 before self-hash: {:#?}", simple_data_0);
            println!(
                "simple_data_0 before self-hash as JCS: {}",
                std::str::from_utf8(
                    serde_json_canonicalizer::to_vec(&simple_data_0)
                        .expect("pass")
                        .as_slice()
                )
                .expect("pass")
            );
            use selfhash::{HashFunctionT, SelfHashableT};
            simple_data_0
                .self_hash(hash_function.new_hasher())
                .expect("pass");
            println!(
                "simple_data_0 after self-hash as JCS: {}",
                std::str::from_utf8(
                    serde_json_canonicalizer::to_vec(&simple_data_0)
                        .expect("pass")
                        .as_slice()
                )
                .expect("pass")
            );
            assert!(simple_data_0.self_hash_o.is_some());
            simple_data_0.verify_self_hashes().expect("pass");
            println!("simple_data_0 self self-hash verified!");
            // Let's make sure that altering the data causes the verification to fail.
            let mut altered_simple_data_0 = simple_data_0.clone();
            altered_simple_data_0.name = "maaaaaaaaaa".to_string();
            assert!(altered_simple_data_0.verify_self_hashes().is_err());

            let mut simple_data_1 = SimpleDataMBHash {
                previous_o: simple_data_0.self_hash_o.clone(),
                name: "grippoponkey".to_string(),
                stuff_count: 43,
                data_byte_v: vec![0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80],
                self_hash_o: None,
            };
            assert!(simple_data_1.previous_o.is_some());
            println!(
                "simple_data_1 before self-hash as JCS: {}",
                std::str::from_utf8(
                    serde_json_canonicalizer::to_vec(&simple_data_1)
                        .expect("pass")
                        .as_slice()
                )
                .expect("pass")
            );
            assert!(simple_data_1.previous_o.is_some());
            simple_data_1
                .self_hash(hash_function.new_hasher())
                .expect("pass");
            assert!(simple_data_1.previous_o.is_some());
            // println!("simple_data_1 after self-hash: {:#?}", simple_data_1);
            println!(
                "simple_data_1 after self-hash as JCS: {}",
                std::str::from_utf8(
                    serde_json_canonicalizer::to_vec(&simple_data_1)
                        .expect("pass")
                        .as_slice()
                )
                .expect("pass")
            );
            assert!(simple_data_1.self_hash_o.is_some());
            simple_data_1.verify_self_hashes().expect("pass");
            println!("simple_data_1 self self-hash verified!");
        }
    }
}

//
// End MBX
//

// NOTE: This is not fully compliant with the URI spec, but it's good enough for a demonstration.
// NOTE: This doesn't deal with percent-encoding at all.
// The mbx::MBHash is the last component of the path.
#[derive(
    Clone, Debug, serde_with::DeserializeFromStr, Eq, serde_with::SerializeDisplay, PartialEq,
)]
pub struct URIWithHash {
    pub scheme: String,
    pub authority_o: Option<String>,
    // This is the path before the signature, which includes the leading and trailing slash,
    // and therefore might just be equal to "/".
    pub pre_hash_path: String,
    // Self-hash in mbx::MBHash form, which is renderable as a URL-safe string.
    pub hash: mbx::MBHash,
    pub query_o: Option<String>,
    pub fragment_o: Option<String>,
}

impl std::fmt::Display for URIWithHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:", self.scheme)?;
        if let Some(authority) = self.authority_o.as_deref() {
            write!(f, "//{}", authority)?;
        }
        write!(f, "{}{}", self.pre_hash_path, self.hash)?;
        if let Some(query) = self.query_o.as_deref() {
            write!(f, "?{}", query)?;
        }
        if let Some(fragment) = self.fragment_o.as_deref() {
            write!(f, "#{}", fragment)?;
        }
        Ok(())
    }
}

impl std::str::FromStr for URIWithHash {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO: Need to check for proper percent-encoding, etc.
        ensure!(s.is_ascii(), "URIWithSignature must be ASCII");
        // Parse the scheme.
        let (scheme, after_scheme) = s
            .split_once(":")
            .ok_or("URIWithSignature must have a scheme")?;
        // Parse the authority.
        let (authority_o, after_authority) = if after_scheme.starts_with("//") {
            let path_start = after_scheme[2..]
                .find('/')
                .ok_or("URIWithSignature is missing path component")?;
            let (authority, after_authority) = after_scheme.split_at(path_start + 2);
            (Some(authority), after_authority)
        } else {
            (None, after_scheme)
        };
        // Parse the pre-signature path.
        let path_end = after_authority
            .rfind('/')
            .ok_or("URIWithSignature is missing path component")?
            + 1;
        let (pre_hash_path, hash_and_beyond) = after_authority.split_at(path_end);
        assert!(pre_hash_path.starts_with('/'));
        assert!(pre_hash_path.ends_with('/'));
        // Parse signature component of path (the last component).
        let hash_end = hash_and_beyond
            .find(|c| c == '?' || c == '#')
            .unwrap_or_else(|| hash_and_beyond.len());
        let (hash_str, after_hash) = hash_and_beyond.split_at(hash_end);
        let hash = mbx::MBHash::try_from(hash_str.to_string())?;
        // Parse query, if present.
        let (query_o, after_query) = if after_hash.starts_with('?') {
            let query_end = after_hash.find('#').unwrap_or_else(|| after_hash.len());
            let (query, after_query) = after_hash[1..].split_at(query_end);
            (Some(query), after_query)
        } else {
            (None, after_hash)
        };
        // Parse fragment, if present
        let fragment_o = if after_query.starts_with('#') {
            Some(&after_query[1..])
        } else {
            None
        };

        Ok(URIWithHash {
            scheme: scheme.to_string(),
            authority_o: authority_o.map(|s| s.to_string()),
            pre_hash_path: pre_hash_path.to_string(),
            hash,
            query_o: query_o.map(|s| s.to_string()),
            fragment_o: fragment_o.map(|s| s.to_string()),
        })
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct FancyData {
    pub uri: URIWithHash,
    pub stuff: String,
    pub things: Vec<u32>,
    #[serde(rename = "self_hash")]
    pub self_hash_o: Option<mbx::MBHash>,
}

impl selfhash::SelfHashableT<mbx::MBHashStr> for FancyData {
    fn write_digest_data(
        &self,
        hasher: &mut <<mbx::MBHashStr as selfhash::HashRefT>::HashFunction as selfhash::HashFunctionT<mbx::MBHashStr>>::Hasher,
    ) -> selfhash::Result<()> {
        selfhash::write_digest_data_using_jcs(self, hasher)
    }
    fn self_hash_oi<'a, 'b: 'a>(
        &'b self,
    ) -> selfhash::Result<Box<dyn std::iter::Iterator<Item = Option<&'b mbx::MBHashStr>> + 'a>>
    {
        Ok(Box::new(
            std::iter::once(Some(self.uri.hash.as_mb_hash_str())).chain(std::iter::once(
                self.self_hash_o
                    .as_ref()
                    .map(|self_hash| self_hash.as_mb_hash_str()),
            )),
        ))
    }
    fn set_self_hash_slots_to(&mut self, hash: &mbx::MBHashStr) -> selfhash::Result<()> {
        let hash = hash.to_owned();
        self.uri.hash = hash.clone();
        self.self_hash_o = Some(hash);
        Ok(())
    }
}

#[cfg(feature = "self-hashable-json")]
#[test]
fn test_self_hashable_json_0() {
    use selfhash::{HashFunctionT, SelfHashableT};
    {
        let mut json = serde_json::from_str::<serde_json::Value>(r#"{"thing":3}"#).expect("pass");
        println!("json before self-hashing: {}", json.to_string());
        // json.self_hash(selfhash::Blake3.new_hasher()).expect("pass");
        let mb_hash_function =
            selfhash::MBHashFunction::new(mbx::Base::Base64Url, ssi_multicodec::BLAKE3)
                .expect("programmer error");
        json.self_hash(mb_hash_function.new_hasher()).expect("pass");
        println!("json after self-hashing: {}", json.to_string());
        json.verify_self_hashes().expect("pass");
    }
}

#[cfg(feature = "self-hashable-json")]
#[test]
fn test_self_hashable_json_1a() {
    use selfhash::{HashFunctionT, SelfHashableJSON, SelfHashableT};
    use std::{borrow::Cow, collections::HashSet};
    {
        println!("with self-hash field name override:");
        // Here, the "selfie" field is provided as null.
        let value = serde_json::from_str::<serde_json::Value>(r#"{"thing":3, "selfie": null}"#)
            .expect("pass");
        println!("json before self-hashing: {}", value.to_string());
        let self_hash_path_s = maplit::hashset! { Cow::Borrowed("$.selfie") };
        let self_hash_url_path_s = HashSet::new();
        let mut self_hashable_json = SelfHashableJSON::new(
            value,
            Cow::Owned(self_hash_path_s),
            Cow::Owned(self_hash_url_path_s),
        )
        .expect("pass");
        let mb_hash_function =
            selfhash::MBHashFunction::new(mbx::Base::Base64Url, ssi_multicodec::BLAKE3)
                .expect("programmer error");
        self_hashable_json
            .self_hash(mb_hash_function.new_hasher())
            .expect("pass");
        self_hashable_json.verify_self_hashes().expect("pass");
        println!(
            "json after self-hashing: {}",
            self_hashable_json.value().to_string()
        );
    }
}

#[cfg(feature = "self-hashable-json")]
#[test]
fn test_self_hashable_json_1b() {
    use selfhash::{HashFunctionT, SelfHashableJSON, SelfHashableT};
    use std::{borrow::Cow, collections::HashSet};
    {
        println!("with self-hash field name override:");
        // Here, the "selfie" field is missing (which is fine, it behaves as null in this case).
        let value = serde_json::from_str::<serde_json::Value>(r#"{"thing":3}"#).expect("pass");
        println!("json before self-hashing: {}", value.to_string());
        let self_hash_path_s = maplit::hashset! { Cow::Borrowed("$.selfie") };
        let self_hash_url_path_s = HashSet::new();
        let mut self_hashable_json = SelfHashableJSON::new(
            value,
            Cow::Owned(self_hash_path_s),
            Cow::Owned(self_hash_url_path_s),
        )
        .expect("pass");
        let mb_hash_function =
            selfhash::MBHashFunction::new(mbx::Base::Base64Url, ssi_multicodec::BLAKE3)
                .expect("programmer error");
        self_hashable_json
            .self_hash(mb_hash_function.new_hasher())
            .expect("pass");
        self_hashable_json.verify_self_hashes().expect("pass");
        println!(
            "json after self-hashing: {}",
            self_hashable_json.value().to_string()
        );
    }
}

#[cfg(feature = "self-hashable-json")]
#[test]
fn test_self_hashable_json_1c() {
    use selfhash::{HashFunctionT, SelfHashableJSON, SelfHashableT};
    use std::{borrow::Cow, collections::HashSet};
    {
        println!("with self-hash field name override:");
        let value =
            serde_json::from_str::<serde_json::Value>(r#"{"thing":3, "blah": {"stuff": true}}"#)
                .expect("pass");
        println!("json before self-hashing: {}", value.to_string());
        let self_hash_path_s = maplit::hashset! { Cow::Borrowed("$.blah.selfie") };
        let self_hash_url_path_s = HashSet::new();
        let mut self_hashable_json = SelfHashableJSON::new(
            value,
            Cow::Owned(self_hash_path_s),
            Cow::Owned(self_hash_url_path_s),
        )
        .expect("pass");
        let mb_hash_function =
            selfhash::MBHashFunction::new(mbx::Base::Base64Url, ssi_multicodec::BLAKE3)
                .expect("programmer error");
        self_hashable_json
            .self_hash(mb_hash_function.new_hasher())
            .expect("pass");
        self_hashable_json.verify_self_hashes().expect("pass");
        println!(
            "json after self-hashing: {}",
            self_hashable_json.value().to_string()
        );
    }
}

#[cfg(feature = "self-hashable-json")]
#[test]
fn test_self_hashable_json_1d() {
    use selfhash::{HashFunctionT, SelfHashableJSON, SelfHashableT};
    use std::{borrow::Cow, collections::HashSet};
    {
        println!("with self-hash field name override:");
        let value = serde_json::from_str::<serde_json::Value>(r#"{"thing":3, "$id":"vjson:///"}"#)
            .expect("pass");
        println!("json before self-hashing: {}", value.to_string());
        let self_hash_path_s = HashSet::new();
        let self_hash_url_path_s = maplit::hashset! { Cow::Borrowed("$.$id") };
        let mut self_hashable_json = SelfHashableJSON::new(
            value,
            Cow::Owned(self_hash_path_s),
            Cow::Owned(self_hash_url_path_s),
        )
        .expect("pass");
        let mb_hash_function =
            selfhash::MBHashFunction::new(mbx::Base::Base64Url, ssi_multicodec::BLAKE3)
                .expect("programmer error");
        self_hashable_json
            .self_hash(mb_hash_function.new_hasher())
            .expect("pass");
        self_hashable_json.verify_self_hashes().expect("pass");
        println!(
            "json after self-hashing: {}",
            self_hashable_json.value().to_string()
        );
    }
}
