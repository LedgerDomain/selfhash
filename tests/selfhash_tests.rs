use selfhash::{require, Error};

#[test]
fn test_serialize_deserialize_keri_hash() {
    let keri_hash =
        selfhash::KERIHash::try_from("EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").expect("pass");
    let keri_hash_json = serde_json_canonicalizer::to_vec(&keri_hash).expect("pass");
    assert_eq!(
        std::str::from_utf8(keri_hash_json.as_slice()).expect("pass"),
        "\"EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\""
    );
    let keri_hash_deserialized: selfhash::KERIHash =
        serde_json::from_slice(keri_hash_json.as_slice()).expect("pass");
    assert_eq!(keri_hash, keri_hash_deserialized);
}

pub fn hash_from_hash_bytes(hash_bytes: selfhash::HashBytes<'_>) -> Box<dyn selfhash::Hash> {
    match hash_bytes.named_hash_function {
        selfhash::NamedHashFunction::BLAKE3 => {
            #[cfg(feature = "blake3")]
            {
                let hash_byte_v: [u8; 32] = hash_bytes
                    .hash_byte_v
                    .into_owned()
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
                    hash_bytes.hash_byte_v.as_ref(),
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
                    hash_bytes.hash_byte_v.as_ref(),
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

/// Parses the known-to-selfhash hashes via their KERIHash.
pub fn hash_from_keri_hash(keri_hash: &selfhash::KERIHashStr) -> Box<dyn selfhash::Hash> {
    hash_from_hash_bytes(keri_hash.to_hash_bytes())
}

// Produces a Vec containing all the known hash functions (subject to what features are enabled).
fn hash_functions() -> Vec<&'static dyn selfhash::HashFunction> {
    #[allow(unused_mut)]
    let mut hash_function_v: Vec<&'static dyn selfhash::HashFunction> = Vec::new();
    #[cfg(feature = "blake3")]
    hash_function_v.push(&selfhash::Blake3);
    #[cfg(feature = "sha-256")]
    hash_function_v.push(&selfhash::SHA256);
    #[cfg(feature = "sha-512")]
    hash_function_v.push(&selfhash::SHA512);
    hash_function_v
}

#[test]
#[serial_test::serial]
fn test_hash_roundtrips() {
    for hash_function in hash_functions().into_iter() {
        println!("---------------------------------------------------");
        println!(
            "test_hash_roundtrips; testing: {:#?}",
            hash_function.named_hash_function()
        );
        let mut hasher = hash_function.new_hasher();
        hasher.update(b"blah blah blah blah hippos");
        let hash_b = hasher.finalize();
        let keri_hash = hash_b.to_keri_hash();
        println!("keri_hash: {}", keri_hash);
        let hash_parsed_b = hash_from_keri_hash(&keri_hash);
        assert!(hash_parsed_b.equals(hash_b.as_ref()));

        // Round trip to HashBytes as well.
        let hash_bytes = hash_b.to_hash_bytes();
        let hash_roundtripped_b = hash_from_hash_bytes(hash_bytes);
        assert!(hash_roundtripped_b.equals(hash_b.as_ref()));
    }
}

/// A simple example of a self-hashing data structure, where the self-hash is kept in HashBytes
/// format (i.e. binary) for fewer allocations and conversions.  Note that there is only one
/// self-hash slot in the structure.  An example with multiple self-hash slots is given elsewhere.
#[derive(Clone, Debug, serde::Serialize)]
pub struct SimpleDataHashBytes {
    /// Self-hash of the previous SimpleData.
    // #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "previous")]
    pub previous_o: Option<selfhash::HashBytes<'static>>,
    pub name: String,
    pub stuff_count: u32,
    pub data_byte_v: Vec<u8>,
    // #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "self_hash")]
    pub self_hash_o: Option<selfhash::HashBytes<'static>>,
}

impl selfhash::SelfHashable for SimpleDataHashBytes {
    fn write_digest_data(&self, hasher: &mut dyn selfhash::Hasher) {
        selfhash::write_digest_data_using_jcs(self, hasher);
    }
    fn self_hash_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfhash::Hash>> + 'a> {
        Box::new(std::iter::once(
            self.self_hash_o
                .as_ref()
                .map(|s| -> &dyn selfhash::Hash { s }),
        ))
    }
    fn set_self_hash_slots_to(&mut self, hash: &dyn selfhash::Hash) {
        self.self_hash_o = Some(hash.to_hash_bytes().into_owned());
    }
}

#[test]
#[serial_test::serial]
fn test_self_hashable_hash_bytes() {
    for hash_function in hash_functions() {
        println!("---------------------------------------------------");
        println!(
            "test_self_hashable_hash_bytes; hash_function KERI prefix: {:?}",
            hash_function.keri_prefix()
        );

        let mut simple_data_0 = SimpleDataHashBytes {
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
        use selfhash::SelfHashable;
        simple_data_0
            .self_hash(hash_function.new_hasher())
            .expect("pass");
        // println!("simple_data_0 after self-hash: {:#?}", simple_data_0);
        println!(
            "simple_data_0 after self-hash as JCS: {}",
            std::str::from_utf8(
                serde_json_canonicalizer::to_vec(&simple_data_0)
                    .expect("pass")
                    .as_slice()
            )
            .expect("pass")
        );
        simple_data_0.verify_self_hashes().expect("pass");
        println!("simple_data_0 self self-hash verified!");
        // Let's make sure that altering the data causes the verification to fail.
        let mut altered_simple_data_0 = simple_data_0.clone();
        altered_simple_data_0.name = "maaaaaaaaaa".to_string();
        assert!(altered_simple_data_0.verify_self_hashes().is_err());

        let mut simple_data_1 = SimpleDataHashBytes {
            previous_o: simple_data_0.self_hash_o.clone(),
            name: "grippoponkey".to_string(),
            stuff_count: 43,
            data_byte_v: vec![0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80],
            self_hash_o: None,
        };
        // println!("simple_data_1 before self-hash: {:#?}", simple_data_1);
        println!(
            "simple_data_1 before self-hash as JCS: {}",
            std::str::from_utf8(
                serde_json_canonicalizer::to_vec(&simple_data_1)
                    .expect("pass")
                    .as_slice()
            )
            .expect("pass")
        );
        simple_data_1
            .self_hash(hash_function.new_hasher())
            .expect("pass");
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
        simple_data_1.verify_self_hashes().expect("pass");
        println!("simple_data_1 self self-hash verified!");
    }
}

/// KERIHash-using version of SimpleData.
#[derive(Clone, Debug, serde::Serialize)]
pub struct SimpleDataKERIHash {
    /// Self-hash of the previous SimpleDataKERIHash.
    #[serde(rename = "previous")]
    pub previous_o: Option<selfhash::KERIHash>,
    pub name: String,
    pub stuff_count: u32,
    pub data_byte_v: Vec<u8>,
    /// Self-hash of this data.
    #[serde(rename = "self_hash")]
    pub self_hash_o: Option<selfhash::KERIHash>,
}

impl selfhash::SelfHashable for SimpleDataKERIHash {
    fn write_digest_data(&self, hasher: &mut dyn selfhash::Hasher) {
        selfhash::write_digest_data_using_jcs(self, hasher);
    }
    fn self_hash_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfhash::Hash>> + 'a> {
        Box::new(std::iter::once(
            self.self_hash_o
                .as_ref()
                .map(|s| -> &dyn selfhash::Hash { s }),
        ))
    }
    fn set_self_hash_slots_to(&mut self, hash: &dyn selfhash::Hash) {
        self.self_hash_o = Some(hash.to_keri_hash().into_owned());
    }
}

#[test]
#[serial_test::serial]
fn test_self_hashable_keri_hash() {
    for hash_function in hash_functions() {
        println!("---------------------------------------------------");
        println!(
            "test_self_hashable_keri_hash; hash_function KERI prefix: {:?}",
            hash_function.keri_prefix()
        );

        let mut simple_data_0 = SimpleDataKERIHash {
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
        use selfhash::SelfHashable;
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

        let mut simple_data_1 = SimpleDataKERIHash {
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

// NOTE: This is not fully compliant with the URI spec, but it's good enough for a demonstration.
// NOTE: This doesn't deal with percent-encoding at all.
// The KERIHash is the last component of the path.
#[derive(
    Clone, Debug, serde_with::DeserializeFromStr, Eq, serde_with::SerializeDisplay, PartialEq,
)]
pub struct URIWithHash {
    pub scheme: String,
    pub authority_o: Option<String>,
    // This is the path before the signature, which includes the leading and trailing slash,
    // and therefore might just be equal to "/".
    pub pre_hash_path: String,
    // Self-hash in KERIHash form, which is renderable as a URL-safe string.
    pub hash: selfhash::KERIHash,
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
        require!(s.is_ascii(), "URIWithSignature must be ASCII");
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
        let hash = selfhash::KERIHash::try_from(hash_str.to_string())?;
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
    pub self_hash_o: Option<selfhash::KERIHash>,
}

impl selfhash::SelfHashable for FancyData {
    fn write_digest_data(&self, hasher: &mut dyn selfhash::Hasher) {
        selfhash::write_digest_data_using_jcs(self, hasher);
    }
    fn self_hash_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfhash::Hash>> + 'a> {
        Box::new(
            std::iter::once(Some(&self.uri.hash as &dyn selfhash::Hash)).chain(std::iter::once(
                self.self_hash_o
                    .as_ref()
                    .map(|self_hash| self_hash as &dyn selfhash::Hash),
            )),
        )
    }
    fn set_self_hash_slots_to(&mut self, hash: &dyn selfhash::Hash) {
        let keri_hash = hash.to_keri_hash().into_owned();
        self.uri.hash = keri_hash.clone();
        self.self_hash_o = Some(keri_hash);
    }
}

#[test]
#[serial_test::serial]
fn test_multiple_self_hash_slots() {
    for hash_function in hash_functions() {
        println!("------------------------------------------------");
        println!(
            "test_multiple_self_hash_slots; testing {:?}",
            hash_function.named_hash_function()
        );
        let mut fancy_data = FancyData {
            uri: URIWithHash {
                scheme: "https".to_string(),
                authority_o: Some("example.com".to_string()),
                pre_hash_path: "/fancy_data/".to_string(),
                hash: hash_function.placeholder_hash().to_keri_hash().into_owned(),
                query_o: None,
                fragment_o: None,
            },
            stuff: "hippopotapotamus".to_string(),
            things: vec![1, 2, 3, 4, 5],
            self_hash_o: None,
        };
        println!(
            "fancy_data before self-hash as JCS: {}",
            std::str::from_utf8(
                serde_json_canonicalizer::to_vec(&fancy_data)
                    .expect("pass")
                    .as_slice()
            )
            .expect("pass")
        );
        use selfhash::SelfHashable;
        fancy_data
            .self_hash(hash_function.new_hasher())
            .expect("pass");
        println!(
            "fancy_data after self-hash as JCS: {}",
            std::str::from_utf8(
                serde_json_canonicalizer::to_vec(&fancy_data)
                    .expect("pass")
                    .as_slice()
            )
            .expect("pass")
        );
        fancy_data.verify_self_hashes().expect("pass");
    }
}

#[cfg(feature = "self-hashable-json")]
#[test]
fn test_self_hashable_json_0() {
    use selfhash::{HashFunction, SelfHashable};
    {
        let mut json = serde_json::from_str::<serde_json::Value>(r#"{"thing":3}"#).expect("pass");
        println!("json before self-hashing: {}", json.to_string());
        json.self_hash(selfhash::Blake3.new_hasher()).expect("pass");
        println!("json after self-hashing: {}", json.to_string());
        json.verify_self_hashes().expect("pass");
    }
}

#[cfg(feature = "self-hashable-json")]
#[test]
fn test_self_hashable_json_1() {
    use selfhash::{HashFunction, SelfHashable, SelfHashableJSON};
    use std::{borrow::Cow, collections::HashSet};
    {
        println!("with self-hash field name override:");
        let value =
            serde_json::from_str::<serde_json::Value>(r#"{"thing":3, "$id":"selfhash:///"}"#)
                .expect("pass");
        println!("json before self-hashing: {}", value.to_string());
        let self_hash_field_name_s = HashSet::new();
        let self_hash_url_field_name_s = maplit::hashset! { Cow::Borrowed("$id") };
        let mut self_hashable_json = SelfHashableJSON::new(
            value,
            Cow::Owned(self_hash_field_name_s),
            Cow::Owned(self_hash_url_field_name_s),
        )
        .expect("pass");
        self_hashable_json
            .self_hash(selfhash::Blake3.new_hasher())
            .expect("pass");
        self_hashable_json.verify_self_hashes().expect("pass");
        println!(
            "json after self-hashing: {}",
            self_hashable_json.value().to_string()
        );
    }
}
