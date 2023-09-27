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
pub fn hash_from_keri_hash(keri_hash: &selfhash::KERIHash<'_>) -> Box<dyn selfhash::Hash> {
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
        // let hash_function = hasher.hash_function();
        let mut c = self.clone();
        c.set_self_hash_slots_to(hasher.hash_function().placeholder_hash());
        // Not sure if serde_json always produces the same output...
        serde_json::to_writer(hasher, &c).expect("pass");
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
            "simple_data_0 before self-hash JSON: {}",
            serde_json::to_string(&simple_data_0).expect("pass")
        );
        use selfhash::SelfHashable;
        simple_data_0
            .self_hash(hash_function.new_hasher())
            .expect("pass");
        // println!("simple_data_0 after self-hash: {:#?}", simple_data_0);
        println!(
            "simple_data_0 after self-hash JSON: {}",
            serde_json::to_string(&simple_data_0).expect("pass")
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
            "simple_data_1 before self-hash JSON: {}",
            serde_json::to_string(&simple_data_1).expect("pass")
        );
        simple_data_1
            .self_hash(hash_function.new_hasher())
            .expect("pass");
        // println!("simple_data_1 after self-hash: {:#?}", simple_data_1);
        println!(
            "simple_data_1 after self-hash JSON: {}",
            serde_json::to_string(&simple_data_1).expect("pass")
        );
        simple_data_1.verify_self_hashes().expect("pass");
        println!("simple_data_1 self self-hash verified!");
    }
}

/// KERIHash-using version of SimpleData.
#[derive(Clone, Debug, serde::Serialize)]
pub struct SimpleDataKERIHash {
    /// Self-hash of the previous SimpleDataKERIHash.
    // #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "previous")]
    pub previous_o: Option<selfhash::KERIHash<'static>>,
    pub name: String,
    pub stuff_count: u32,
    pub data_byte_v: Vec<u8>,
    // #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "self_hash")]
    pub self_hash_o: Option<selfhash::KERIHash<'static>>,
}

impl selfhash::SelfHashable for SimpleDataKERIHash {
    fn write_digest_data(&self, hasher: &mut dyn selfhash::Hasher) {
        // let hash_function = hasher.hash_function();
        let mut c = self.clone();
        c.set_self_hash_slots_to(hasher.hash_function().placeholder_hash());
        // Not sure if serde_json always produces the same output...
        serde_json::to_writer(hasher, &c).expect("pass");
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
            "simple_data_0 before self-hash JSON: {}",
            serde_json::to_string(&simple_data_0).expect("pass")
        );
        use selfhash::SelfHashable;
        simple_data_0
            .self_hash(hash_function.new_hasher())
            .expect("pass");
        // println!("simple_data_0 after self-hash: {:#?}", simple_data_0);
        println!(
            "simple_data_0 after self-hash JSON: {}",
            serde_json::to_string(&simple_data_0).expect("pass")
        );
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
        // println!("simple_data_1 before self-hash: {:#?}", simple_data_1);
        println!(
            "simple_data_1 before self-hash JSON: {}",
            serde_json::to_string(&simple_data_1).expect("pass")
        );
        simple_data_1
            .self_hash(hash_function.new_hasher())
            .expect("pass");
        // println!("simple_data_1 after self-hash: {:#?}", simple_data_1);
        println!(
            "simple_data_1 after self-hash JSON: {}",
            serde_json::to_string(&simple_data_1).expect("pass")
        );
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
    pub hash: selfhash::KERIHash<'static>,
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
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO: Need to check for proper percent-encoding, etc.
        if !s.is_ascii() {
            return Err("URIWithSignature must be ASCII");
        }
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
        let hash = selfhash::KERIHash::from_str(hash_str)?;
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
    pub self_hash_o: Option<selfhash::KERIHash<'static>>,
}

impl selfhash::SelfHashable for FancyData {
    fn write_digest_data(&self, hasher: &mut dyn selfhash::Hasher) {
        // let hash_function = hasher.hash_function();
        let mut c = self.clone();
        c.set_self_hash_slots_to(hasher.hash_function().placeholder_hash());
        // Not sure if serde_json always produces the same output...
        serde_json::to_writer(hasher, &c).expect("pass");
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
        let keri_hash = hash.to_keri_hash().to_owned();
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
                hash: hash_function.placeholder_hash().to_keri_hash(),
                query_o: None,
                fragment_o: None,
            },
            stuff: "hippopotapotamus".to_string(),
            things: vec![1, 2, 3, 4, 5],
            self_hash_o: None,
        };
        println!(
            "fancy_data before self-hash: {}",
            serde_json::to_string(&fancy_data).expect("pass")
        );
        use selfhash::SelfHashable;
        fancy_data
            .self_hash(hash_function.new_hasher())
            .expect("pass");
        println!(
            "fancy_data after self-hash: {}",
            serde_json::to_string(&fancy_data).expect("pass")
        );
        fancy_data.verify_self_hashes().expect("pass");
    }
}

// /// This is meant to be a simplified version of the DID data model.
// pub trait KeyMaterial: selfhash::SelfHashable {
//     /// The URI contains the self-hash from the root KeyMaterial, and does not change
//     /// when the KeyMaterial is updated.
//     fn uri(&self) -> &URIWithSignature;
//     /// The root KeyMaterial is the only KeyMaterial that does not have a previous KeyMaterial.
//     fn is_root_key_material(&self) -> bool {
//         self.previous_key_material_self_hash_o().is_none()
//     }
//     /// The root KeyMaterial returns None here.  A non-root KeyMaterial returns the self-hash
//     /// of the previous KeyMaterial.
//     fn previous_key_material_self_hash_o(&self) -> Option<&selfhash::KERIHash<'static>>;
//     /// This is the version ID of this KeyMaterial.  It must start at 0 for the root KeyMaterial
//     /// and increase by exactly one per KeyMaterial update.
//     fn version_id(&self) -> u32;
//     /// This is the timestamp at which this KeyMaterial becomes current and the previous one becomes
//     /// no longer current.
//     fn valid_from(&self) -> chrono::DateTime<chrono::Utc>;
//     /// List of verifiers for the authentication key purpose.
//     fn authentication_v(&self) -> &[selfhash::KERIVerifier<'static>];
//     /// List of verifiers for the assertion key purpose.
//     fn assertion_v(&self) -> &[selfhash::KERIVerifier<'static>];
//     /// List of verifiers for the key exchange key purpose.
//     fn key_exchange_v(&self) -> &[selfhash::KERIVerifier<'static>];
//     /// List of verifiers for the capability invocation key purpose.
//     fn capability_invocation_v(&self) -> &[selfhash::KERIVerifier<'static>];
//     /// List of verifiers for the capability delegation key purpose.
//     fn capability_delegation_v(&self) -> &[selfhash::KERIVerifier<'static>];
//     /// This verifies this KeyMaterial relative to its previous KeyMaterial, or to itself if it's the root.
//     fn verify_nonrecursive(
//         &self,
//         key_material_m: &HashMap<selfhash::KERIHash<'static>, &dyn KeyMaterial>,
//     ) -> Result<(), &'static str> {
//         // First, verify that this KeyMaterial is properly self-signed.
//         self.verify_self_hashs()?;
//         // Now do checks that depend on if this is the root KeyMaterial or not.
//         if let Some(previous_key_material_self_hash) = self.previous_key_material_self_hash_o() {
//             let previous_key_material = key_material_m
//                 .get(previous_key_material_self_hash)
//                 .ok_or("previous_key_material_self_hash not found in key_material_m")?;
//             // Check that the URI matches.
//             if self.uri() != previous_key_material.uri() {
//                 return Err("URI does not match URI of previous KeyMaterial");
//             }
//             // Check that the version_id is exactly one greater than that of the previous KeyMaterial.
//             if self.version_id() != previous_key_material.version_id() + 1 {
//                 return Err(
//                     "version_id must be exactly one greater than that of previous KeyMaterial",
//                 );
//             }
//             // Check that the valid_from timestamps are monotonically increasing.
//             if self.valid_from() <= previous_key_material.valid_from() {
//                 return Err("valid_from timestamp must be later than that of previous KeyMaterial");
//             }
//             // Check that the self-hash verifier is listed in the capability_invocation_v
//             // of the previous KeyMaterial.
//             if !previous_key_material.capability_invocation_v().contains(
//                 &self
//                     .get_self_hash_verifier()
//                     .unwrap()
//                     .as_ref()
//                     .unwrap()
//                     .to_keri_verifier(),
//             ) {
//                 return Err("Unauthorized KeyMaterial update: self_hash_verifier_o is not in capability_invocation_v of previous KeyMaterial");
//             }
//         } else {
//             // Check that the version_id is 0.
//             if self.version_id() != 0 {
//                 return Err("version_id must be 0 for root KeyMaterial");
//             }
//             // Check that the self-hash verifier is listed in capability_invocation_v.
//             if !self.capability_invocation_v().contains(
//                 &self
//                     .get_self_hash_verifier()
//                     .unwrap()
//                     .as_ref()
//                     .unwrap()
//                     .to_keri_verifier(),
//             ) {
//                 return Err("self_hash_verifier_o is not in capability_invocation_v");
//             }
//         }

//         Ok(())
//     }
//     fn verify_recursive(
//         &self,
//         key_material_m: &HashMap<selfhash::KERIHash<'static>, &dyn KeyMaterial>,
//     ) -> Result<(), &'static str> {
//         self.verify_nonrecursive(key_material_m)?;
//         if let Some(previous_key_material_self_hash) = self.previous_key_material_self_hash_o() {
//             let previous_key_material = key_material_m
//                 .get(previous_key_material_self_hash)
//                 .ok_or("previous_key_material_self_hash not found in key_material_m")?;
//             previous_key_material.verify_recursive(key_material_m)?;
//         }
//         Ok(())
//     }
// }

// #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
// pub struct KeyMaterialRoot {
//     pub uri: URIWithSignature,
//     pub version_id: u32,
//     pub valid_from: chrono::DateTime<chrono::Utc>,
//     pub authentication_v: Vec<selfhash::KERIVerifier<'static>>,
//     pub assertion_v: Vec<selfhash::KERIVerifier<'static>>,
//     pub key_exchange_v: Vec<selfhash::KERIVerifier<'static>>,
//     pub capability_invocation_v: Vec<selfhash::KERIVerifier<'static>>,
//     pub capability_delegation_v: Vec<selfhash::KERIVerifier<'static>>,
//     #[serde(rename = "self_hash_verifier")]
//     pub self_hash_verifier_o: Option<selfhash::KERIVerifier<'static>>,
//     #[serde(rename = "self_hash")]
//     pub self_hash_o: Option<selfhash::KERIHash<'static>>,
// }

// impl KeyMaterial for KeyMaterialRoot {
//     fn uri(&self) -> &URIWithSignature {
//         &self.uri
//     }
//     fn previous_key_material_self_hash_o(&self) -> Option<&selfhash::KERIHash<'static>> {
//         None
//     }
//     fn version_id(&self) -> u32 {
//         self.version_id
//     }
//     fn valid_from(&self) -> chrono::DateTime<chrono::Utc> {
//         self.valid_from
//     }
//     fn authentication_v(&self) -> &[selfhash::KERIVerifier<'static>] {
//         &self.authentication_v
//     }
//     fn assertion_v(&self) -> &[selfhash::KERIVerifier<'static>] {
//         &self.assertion_v
//     }
//     fn key_exchange_v(&self) -> &[selfhash::KERIVerifier<'static>] {
//         &self.key_exchange_v
//     }
//     fn capability_invocation_v(&self) -> &[selfhash::KERIVerifier<'static>] {
//         &self.capability_invocation_v
//     }
//     fn capability_delegation_v(&self) -> &[selfhash::KERIVerifier<'static>] {
//         &self.capability_delegation_v
//     }
// }

// impl selfhash::SelfHashable for KeyMaterialRoot {
//     fn write_digest_data(
//         &self,
//         signature_algorithm: SignatureAlgorithm,
//         verifier: &dyn selfhash::Verifier,
//         hasher: &mut selfhash::Hasher,
//     ) {
//         assert!(verifier.key_type() == signature_algorithm.key_type());
//         assert!(signature_algorithm.message_digest_hash_function() == hasher.hash_function());
//         // NOTE: This is a generic JSON-serialization-based implementation.
//         let mut c = self.clone();
//         c.set_self_hash_slots_to(&signature_algorithm.placeholder_keri_signature());
//         c.set_self_hash_verifier_slots_to(verifier);
//         // Not sure if serde_json always produces the same output...
//         serde_json::to_writer(hasher, &c).expect("pass");
//     }
//     fn self_hash_oi<'a, 'b: 'a>(
//         &'b self,
//     ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfhash::Signature>> + 'a> {
//         Box::new(
//             std::iter::once(Some(&self.uri.signature as &dyn selfhash::Signature)).chain(
//                 std::iter::once(
//                     self.self_hash_o
//                         .as_ref()
//                         .map(|s| -> &dyn selfhash::Signature { s }),
//                 ),
//             ),
//         )
//     }
//     fn set_self_hash_slots_to(&mut self, signature: &dyn selfhash::Signature) {
//         let keri_signature = signature.to_keri_hash().into_owned();
//         self.uri.signature = keri_signature.clone();
//         self.self_hash_o = Some(keri_signature);
//         // self.self_hash_o = Some(signature.to_hash_bytes().into_owned());
//     }
//     fn self_hash_verifier_oi<'a, 'b: 'a>(
//         &'b self,
//     ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfhash::Verifier>> + 'a> {
//         Box::new(std::iter::once(
//             self.self_hash_verifier_o
//                 .as_ref()
//                 .map(|v| -> &dyn selfhash::Verifier { v }),
//         ))
//     }
//     fn set_self_hash_verifier_slots_to(&mut self, verifier: &dyn selfhash::Verifier) {
//         self.self_hash_verifier_o = Some(verifier.to_keri_verifier().into_owned());
//     }
// }

// #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
// pub struct KeyMaterialNonRoot {
//     pub uri: URIWithSignature,
//     pub previous_key_material_self_hash: selfhash::KERIHash<'static>,
//     pub version_id: u32,
//     pub valid_from: chrono::DateTime<chrono::Utc>,
//     pub authentication_v: Vec<selfhash::KERIVerifier<'static>>,
//     pub assertion_v: Vec<selfhash::KERIVerifier<'static>>,
//     pub key_exchange_v: Vec<selfhash::KERIVerifier<'static>>,
//     pub capability_invocation_v: Vec<selfhash::KERIVerifier<'static>>,
//     pub capability_delegation_v: Vec<selfhash::KERIVerifier<'static>>,
//     #[serde(rename = "self_hash_verifier")]
//     pub self_hash_verifier_o: Option<selfhash::KERIVerifier<'static>>,
//     #[serde(rename = "self_hash")]
//     pub self_hash_o: Option<selfhash::KERIHash<'static>>,
// }

// impl KeyMaterial for KeyMaterialNonRoot {
//     fn uri(&self) -> &URIWithSignature {
//         &self.uri
//     }
//     fn previous_key_material_self_hash_o(&self) -> Option<&selfhash::KERIHash<'static>> {
//         Some(&self.previous_key_material_self_hash)
//     }
//     fn version_id(&self) -> u32 {
//         self.version_id
//     }
//     fn valid_from(&self) -> chrono::DateTime<chrono::Utc> {
//         self.valid_from
//     }
//     fn authentication_v(&self) -> &[selfhash::KERIVerifier<'static>] {
//         &self.authentication_v
//     }
//     fn assertion_v(&self) -> &[selfhash::KERIVerifier<'static>] {
//         &self.assertion_v
//     }
//     fn key_exchange_v(&self) -> &[selfhash::KERIVerifier<'static>] {
//         &self.key_exchange_v
//     }
//     fn capability_invocation_v(&self) -> &[selfhash::KERIVerifier<'static>] {
//         &self.capability_invocation_v
//     }
//     fn capability_delegation_v(&self) -> &[selfhash::KERIVerifier<'static>] {
//         &self.capability_delegation_v
//     }
// }

// impl selfhash::SelfHashable for KeyMaterialNonRoot {
//     fn write_digest_data(
//         &self,
//         signature_algorithm: SignatureAlgorithm,
//         verifier: &dyn selfhash::Verifier,
//         hasher: &mut selfhash::Hasher,
//     ) {
//         assert!(verifier.key_type() == signature_algorithm.key_type());
//         assert!(signature_algorithm.message_digest_hash_function() == hasher.hash_function());
//         // NOTE: This is a generic JSON-serialization-based implementation.
//         let mut c = self.clone();
//         c.set_self_hash_slots_to(&signature_algorithm.placeholder_keri_signature());
//         c.set_self_hash_verifier_slots_to(verifier);
//         // Not sure if serde_json always produces the same output...
//         serde_json::to_writer(hasher, &c).expect("pass");
//     }
//     fn self_hash_oi<'a, 'b: 'a>(
//         &'b self,
//     ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfhash::Signature>> + 'a> {
//         Box::new(std::iter::once(
//             self.self_hash_o
//                 .as_ref()
//                 .map(|s| -> &dyn selfhash::Signature { s }),
//         ))
//     }
//     fn set_self_hash_slots_to(&mut self, signature: &dyn selfhash::Signature) {
//         let keri_signature = signature.to_keri_hash().into_owned();
//         self.self_hash_o = Some(keri_signature);
//     }
//     fn self_hash_verifier_oi<'a, 'b: 'a>(
//         &'b self,
//     ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfhash::Verifier>> + 'a> {
//         Box::new(std::iter::once(
//             self.self_hash_verifier_o
//                 .as_ref()
//                 .map(|v| -> &dyn selfhash::Verifier { v }),
//         ))
//     }
//     fn set_self_hash_verifier_slots_to(&mut self, verifier: &dyn selfhash::Verifier) {
//         self.self_hash_verifier_o = Some(verifier.to_keri_verifier().into_owned());
//     }
// }

// #[test]
// #[serial_test::serial]
// fn test_multiple_self_hash_slots() {
//     // This will hold each of the KeyMaterial values in the microledger, keyed by their self-hash.
//     let mut key_material_m: HashMap<selfhash::KERIHash<'static>, &dyn KeyMaterial> = HashMap::new();

//     let mut csprng = rand::rngs::OsRng;
//     let authentication_signing_key_0 = ed25519_dalek::SigningKey::generate(&mut csprng);
//     let assertion_signing_key_0 = ed25519_dalek::SigningKey::generate(&mut csprng);
//     let key_exchange_signing_key_0 = ed25519_dalek::SigningKey::generate(&mut csprng);
//     let capability_invocation_signing_key_0 = ed25519_dalek::SigningKey::generate(&mut csprng);
//     let capability_delegation_signing_key_0 = ed25519_dalek::SigningKey::generate(&mut csprng);

//     let key_material_0 = {
//         let mut key_material_0 = KeyMaterialRoot {
//             uri: URIWithSignature {
//                 scheme: "https".into(),
//                 authority_o: Some("example.com".into()),
//                 pre_signature_path: "/identity/".into(),
//                 signature: capability_invocation_signing_key_0
//                     .signature_algorithm()
//                     .placeholder_keri_signature(),
//                 // TODO: Include version_id and self_sig as query params
//                 query_o: None,
//                 fragment_o: None,
//             },
//             version_id: 0,
//             valid_from: chrono::Utc::now(),
//             authentication_v: vec![authentication_signing_key_0
//                 .verifier()
//                 .to_keri_verifier()
//                 .into_owned()],
//             assertion_v: vec![assertion_signing_key_0
//                 .verifier()
//                 .to_keri_verifier()
//                 .into_owned()],
//             key_exchange_v: vec![key_exchange_signing_key_0
//                 .verifier()
//                 .to_keri_verifier()
//                 .into_owned()],
//             capability_invocation_v: vec![capability_invocation_signing_key_0
//                 .verifier()
//                 .to_keri_verifier()
//                 .into_owned()],
//             capability_delegation_v: vec![capability_delegation_signing_key_0
//                 .verifier()
//                 .to_keri_verifier()
//                 .into_owned()],
//             self_hash_verifier_o: None,
//             self_hash_o: None,
//         };
//         key_material_0
//             .self_sign(&capability_invocation_signing_key_0)
//             .expect("pass");
//         key_material_0.verify_self_hashs().expect("pass");
//         key_material_0
//     };
//     // println!("key_material_0: {:#?}", key_material_0);
//     println!(
//         "key_material_0 as JSON:\n{}\n",
//         serde_json::to_string_pretty(&key_material_0).expect("pass")
//     );

//     key_material_m.insert(
//         key_material_0.self_hash_o.as_ref().unwrap().clone(),
//         &key_material_0,
//     );

//     // This is the full verification of the KeyMaterial microledger.
//     key_material_0
//         .verify_recursive(&key_material_m)
//         .expect("pass");

//     // Now generate new keys and rotate the key material.

//     let authentication_signing_key_1 = ed25519_dalek::SigningKey::generate(&mut csprng);
//     let assertion_signing_key_1 = ed25519_dalek::SigningKey::generate(&mut csprng);
//     let key_exchange_signing_key_1 = ed25519_dalek::SigningKey::generate(&mut csprng);
//     let capability_invocation_signing_key_1 = ed25519_dalek::SigningKey::generate(&mut csprng);
//     let capability_delegation_signing_key_1 = ed25519_dalek::SigningKey::generate(&mut csprng);

//     let key_material_1 = {
//         let mut key_material_1 = KeyMaterialNonRoot {
//             uri: key_material_0.uri.clone(),
//             previous_key_material_self_hash: key_material_0.self_hash_o.as_ref().unwrap().clone(),
//             version_id: key_material_0.version_id + 1,
//             valid_from: chrono::Utc::now(),
//             authentication_v: vec![authentication_signing_key_1
//                 .verifier()
//                 .to_keri_verifier()
//                 .into_owned()],
//             assertion_v: vec![assertion_signing_key_1
//                 .verifier()
//                 .to_keri_verifier()
//                 .into_owned()],
//             key_exchange_v: vec![key_exchange_signing_key_1
//                 .verifier()
//                 .to_keri_verifier()
//                 .into_owned()],
//             capability_invocation_v: vec![capability_invocation_signing_key_1
//                 .verifier()
//                 .to_keri_verifier()
//                 .into_owned()],
//             capability_delegation_v: vec![capability_delegation_signing_key_1
//                 .verifier()
//                 .to_keri_verifier()
//                 .into_owned()],
//             self_hash_verifier_o: None,
//             self_hash_o: None,
//         };
//         key_material_1
//             .self_sign(&capability_invocation_signing_key_0)
//             .expect("pass");
//         key_material_1.verify_self_hashs().expect("pass");
//         key_material_1
//     };
//     // println!("key_material_1: {:#?}", key_material_1);
//     println!(
//         "key_material_1 as JSON:\n{}\n",
//         serde_json::to_string_pretty(&key_material_1).expect("pass")
//     );

//     key_material_m.insert(
//         key_material_1.self_hash_o.as_ref().unwrap().clone(),
//         &key_material_1,
//     );

//     // This is the full verification of the KeyMaterial microledger.
//     key_material_1
//         .verify_recursive(&key_material_m)
//         .expect("pass");

//     // Do one more round of generation and rotation, to test verification of a non-root KeyMaterial
//     // against a non-root previous KeyMaterial.

//     let authentication_signing_key_2 = ed25519_dalek::SigningKey::generate(&mut csprng);
//     let assertion_signing_key_2 = ed25519_dalek::SigningKey::generate(&mut csprng);
//     let key_exchange_signing_key_2 = ed25519_dalek::SigningKey::generate(&mut csprng);

//     let key_material_2 = {
//         let mut key_material_2 = KeyMaterialNonRoot {
//             uri: key_material_1.uri.clone(),
//             previous_key_material_self_hash: key_material_1.self_hash_o.as_ref().unwrap().clone(),
//             version_id: key_material_1.version_id + 1,
//             valid_from: chrono::Utc::now(),
//             authentication_v: vec![
//                 authentication_signing_key_1
//                     .verifier()
//                     .to_keri_verifier()
//                     .into_owned(),
//                 authentication_signing_key_2
//                     .verifier()
//                     .to_keri_verifier()
//                     .into_owned(),
//             ],
//             assertion_v: vec![
//                 assertion_signing_key_1
//                     .verifier()
//                     .to_keri_verifier()
//                     .into_owned(),
//                 assertion_signing_key_2
//                     .verifier()
//                     .to_keri_verifier()
//                     .into_owned(),
//             ],
//             key_exchange_v: vec![
//                 key_exchange_signing_key_1
//                     .verifier()
//                     .to_keri_verifier()
//                     .into_owned(),
//                 key_exchange_signing_key_2
//                     .verifier()
//                     .to_keri_verifier()
//                     .into_owned(),
//             ],
//             capability_invocation_v: vec![capability_invocation_signing_key_1
//                 .verifier()
//                 .to_keri_verifier()
//                 .into_owned()],
//             capability_delegation_v: vec![capability_delegation_signing_key_1
//                 .verifier()
//                 .to_keri_verifier()
//                 .into_owned()],
//             self_hash_verifier_o: None,
//             self_hash_o: None,
//         };
//         key_material_2
//             .self_sign(&capability_invocation_signing_key_1)
//             .expect("pass");
//         key_material_2.verify_self_hashs().expect("pass");
//         key_material_2
//     };
//     // println!("key_material_2: {:#?}", key_material_2);
//     println!(
//         "key_material_2 as JSON:\n{}\n",
//         serde_json::to_string_pretty(&key_material_2).expect("pass")
//     );

//     key_material_m.insert(
//         key_material_2.self_hash_o.as_ref().unwrap().clone(),
//         &key_material_2,
//     );

//     // This is the full verification of the KeyMaterial microledger.
//     key_material_2
//         .verify_recursive(&key_material_m)
//         .expect("pass");
// }

// #[test]
// #[serial_test::serial]
// fn test_stuff() {
//     for _ in 0..20 {
//         let ed25519_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
//         let ed25519_verifier = ed25519_signing_key.verifier();
//         let keri_verifier = ed25519_verifier.to_keri_verifier();
//         println!("{}", keri_verifier);
//     }
// }
