use crate::{
    bail, error, require, write_digest_data_using_jcs, Hash, HashFunction, KERIHashStr,
    PreferredHashFormat, Result, SelfHashURL, SelfHashURLStr, SelfHashable,
};
use std::borrow::Cow;

/// Interprets a serde_json::Value as a KERIHash (either as a KERIHash directly or through the KERIHash
/// component of a SelfHashURL).
impl Hash for serde_json::Value {
    fn hash_function(&self) -> Result<&'static dyn HashFunction> {
        match self {
            serde_json::Value::String(s) => {
                if let Ok(self_hash_url) = SelfHashURLStr::new_ref(s) {
                    self_hash_url.hash_function()
                } else if let Ok(keri_hash) = KERIHashStr::new_ref(s) {
                    keri_hash.hash_function()
                } else {
                    panic!("selfHash field is not a valid KERIHash or SelfHashURL.")
                }
            }
            _ => {
                panic!("selfHash JSON Value is expected to be a string.")
            }
        }
    }
    /// We assume that JSON always uses KERIHash, not HashBytes.
    fn as_preferred_hash_format<'s: 'h, 'h>(&'s self) -> Result<PreferredHashFormat<'h>> {
        match self {
            serde_json::Value::String(s) => {
                if let Ok(self_hash_url) = SelfHashURLStr::new_ref(s) {
                    Ok(PreferredHashFormat::KERIHash(Cow::Borrowed(
                        self_hash_url.keri_hash_o().unwrap(),
                    )))
                } else if let Ok(keri_hash) = KERIHashStr::new_ref(s) {
                    Ok(PreferredHashFormat::KERIHash(Cow::Borrowed(keri_hash)))
                } else {
                    panic!("selfHash field is not a valid KERIHash or SelfHashURL.")
                }
            }
            _ => {
                panic!("selfHash JSON Value is expected to be a string.")
            }
        }
    }
}

/// Allows serde_json::Value to be used as a SelfHashable in which the only self-hash slot is the
/// top-level field "selfHash".  See also SelfHashableJSON for a more configurable option.
impl SelfHashable for serde_json::Value {
    fn write_digest_data(&self, hasher: &mut dyn crate::Hasher) -> Result<()> {
        write_digest_data_using_jcs(self, hasher)
    }
    fn self_hash_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Result<Box<dyn std::iter::Iterator<Item = Option<&dyn crate::Hash>> + 'a>> {
        if !self.is_object() {
            bail!("self-hashable JSON value is expected to be a JSON object");
        }
        // Only a top-level "selfHash" field in this JSON object is considered a self-hash slot.
        let self_hash_o = self.get("selfHash");
        let self_hash_oib = match self_hash_o {
            Some(serde_json::Value::Null) | None => Box::new(std::iter::once(None)),
            Some(serde_json::Value::String(_)) => Box::new(std::iter::once(
                self_hash_o.map(|self_hash| self_hash as &dyn crate::Hash),
            )),
            Some(_) => {
                bail!("selfHash field must be a string or null.");
            }
        };
        Ok(self_hash_oib)
    }
    fn set_self_hash_slots_to(&mut self, hash: &dyn crate::Hash) -> Result<()> {
        let self_as_object_mut = self
            .as_object_mut()
            .ok_or_else(|| error!("self-hashable JSON value is expected to be a JSON object"))?;
        self_as_object_mut.insert(
            "selfHash".to_string(),
            serde_json::Value::String(hash.to_keri_hash()?.to_string()),
        );
        Ok(())
    }
}

/// This data structure provides the context necessary to process a serde_json::Value as
/// self-hashable data in a configurable way, where the specific field name(s) for self-hash
/// slots and self-hash URL slots are specifiable.
#[derive(Clone)]
pub struct SelfHashableJSON<'v, 'w: 'v> {
    /// This is the JSON value that is being self-hashed.
    value: serde_json::Value,
    /// These are all the JSONPath queries whose elements are considered to define self-hash values.
    self_hash_path_s: Cow<'v, std::collections::HashSet<Cow<'w, str>>>,
    /// These are all the JSONPath queries whose elements are considered to define self-hash URL values.
    self_hash_url_path_s: Cow<'v, std::collections::HashSet<Cow<'w, str>>>,
}

/// We restrict admissible paths to ones that end in `.<identifier>`, so that there's a well-defined field
/// name for each self-hash slot.
fn jsonpath_terminating_identifier(path: &str) -> Result<&str> {
    // Not sure if this is really necessary.
    // require!(path.starts_with("$."), "self-hash [URL] path must begin with `$.` (indicating the path starts at the root element)");
    let (_, after_period) = path.rsplit_once('.').ok_or_else(|| error!("self-hash [URL] path must end with `.<identifier>`, where <identifier> may not contain `[`, `]`, `'`, or `\"`; path was {}", path))?;
    require!(
        !after_period.contains('['),
        "self-hash [URL] path terminating identifier may not contain `[`; path was {}",
        path
    );
    require!(
        !after_period.contains(']'),
        "self-hash [URL] path terminating identifier may not contain `]`; path was {}",
        path
    );
    require!(
        !after_period.contains('\''),
        "self-hash [URL] path terminating identifier may not contain `'`; path was {}",
        path
    );
    require!(
        !after_period.contains('"'),
        "self-hash [URL] path terminating identifier may not contain `\"`; path was {}",
        path
    );
    Ok(after_period)
}

impl<'v, 'w: 'v> SelfHashableJSON<'v, 'w> {
    pub fn new(
        value: serde_json::Value,
        self_hash_path_s: Cow<'v, std::collections::HashSet<Cow<'w, str>>>,
        self_hash_url_path_s: Cow<'v, std::collections::HashSet<Cow<'w, str>>>,
    ) -> Result<Self> {
        require!(
            value.is_object(),
            "self-hashable JSON value is expected to be a JSON object"
        );
        require!(
            self_hash_path_s.is_disjoint(&self_hash_url_path_s),
            "self-hash paths and self-hash URL paths must be disjoint."
        );
        // Verify that all the self-hash path query results are present (and are strings or nulls).
        let mut self_hash_count = 0;
        for self_hash_path in self_hash_path_s.iter().map(std::ops::Deref::deref) {
            jsonpath_terminating_identifier(self_hash_path)?;
            let mut selector = jsonpath_lib::selector(&value);
            let mut query_result_count = 0;
            for query_value in selector(self_hash_path)?.into_iter() {
                require!(
                    query_value.is_string() || query_value.is_null(),
                    "self-hash field (query was {:?}) is expected to be a string or null",
                    self_hash_path
                );
                if let Some(query_value_str) = query_value.as_str() {
                    require!(
                        KERIHashStr::new_ref(query_value_str).is_ok(),
                        "self-hash field {:?} (query was {:?}) is expected to be a valid self-hash",
                        query_value,
                        self_hash_path
                    );
                }
                query_result_count += 1;
            }
            match query_result_count {
                0 => {
                    // This is fine, this self-hash field will be added in the self-hashing operation.
                }
                1 => {
                    // This is fine, this self-hash field was present.
                }
                _ => {
                    bail!("self-hash path query returned more than 1 result (it returned {} results), which is not a valid self-hash path query by definition; path was {}", query_result_count, self_hash_path);
                }
            }
            self_hash_count += 1;
        }
        // Verify that all the self-hash URL path query results are present (and are strings).
        let mut self_hash_url_count = 0;
        for self_hash_url_path in self_hash_url_path_s.iter().map(std::ops::Deref::deref) {
            jsonpath_terminating_identifier(self_hash_url_path)?;
            let mut selector = jsonpath_lib::selector(&value);
            let mut query_result_count = 0;
            for query_value in selector(self_hash_url_path)?.into_iter() {
                require!(
                    query_value.is_string(),
                    "self-hash URL field (query was {:?}) is expected to be a string",
                    self_hash_url_path
                );
                require!(
                    SelfHashURLStr::new_ref(query_value.as_str().unwrap()).is_ok(),
                    "self-hash URL field {:?} (query was {:?}) is expected to be a valid self-hash URL",
                    query_value,
                    self_hash_url_path
                );
                query_result_count += 1;
            }
            match query_result_count {
                0 => {
                    // There were no results, so the field is missing, which is an error.
                    bail!("self-hash URL path query returned 0 results, which is not a valid self-hash URL path query by definition; path was {}", self_hash_url_path);
                }
                1 => {
                    // The slot was already counted in the loop above.
                }
                _ => {
                    bail!("self-hash URL path query returned more than 1 result (it returned {} results), which is not a valid self-hash URL path query by definition; path was {}", query_result_count, self_hash_url_path);
                }
            }
            self_hash_url_count += 1;
        }

        require!(self_hash_count + self_hash_url_count > 0, "no self-hash or self-hash URL fields found, meaning that this JSON value is not self-hashable");

        Ok(SelfHashableJSON {
            value,
            self_hash_path_s,
            self_hash_url_path_s,
        })
    }
    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }
    pub fn value_mut(&mut self) -> &mut serde_json::Value {
        &mut self.value
    }
    /// Consume this object and produce the serde_json::Value it contains.
    pub fn into_value(self) -> serde_json::Value {
        self.value
    }
}

impl SelfHashable for SelfHashableJSON<'_, '_> {
    fn write_digest_data(&self, mut hasher: &mut dyn crate::Hasher) -> Result<()> {
        let mut c = SelfHashableJSON {
            value: self.value.clone(),
            self_hash_path_s: self.self_hash_path_s.clone(),
            self_hash_url_path_s: self.self_hash_url_path_s.clone(),
        };
        c.set_self_hash_slots_to(hasher.hash_function().placeholder_hash())?;
        // Use JCS to produce canonical output.  The `&mut hasher` ridiculousness is because
        // serde_json_canonicalizer::to_writer uses a generic impl of std::io::Write and therefore
        // implicitly requires the `Sized` trait.  Therefore passing in a reference to the reference
        // achieves the desired effect.
        serde_json_canonicalizer::to_writer(&c.value, &mut hasher)?;
        Ok(())
    }
    fn self_hash_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Result<Box<dyn std::iter::Iterator<Item = Option<&dyn crate::Hash>> + 'a>> {
        // println!(
        //     "SelfHashableJSON::self_hash_oi; self.value: {:?}",
        //     self.value
        // );
        // This will provide storage for the returned iterator.
        let mut self_hash_v = Vec::new();
        // Iterate through all self-hash path query results.  For self-hash fields, a missing field
        // is fine, it just counts as a None.
        // TODO: Not sure how to detect missing fields, unless there's a known number of expected results.
        for self_hash_path in self.self_hash_path_s.iter().map(std::ops::Deref::deref) {
            // println!("    self_hash_path: {:?}", self_hash_path);
            let mut selector = jsonpath_lib::selector(&self.value);
            let mut query_result_count = 0;
            for query_value in selector(self_hash_path)
                .map_err(|e| error!("invalid self-hash path {}; error was {}", self_hash_path, e))?
                .into_iter()
            {
                // println!("        query_value: {:?}", query_value);
                match query_value {
                    serde_json::Value::Null => {
                        self_hash_v.push(None);
                    }
                    serde_json::Value::String(_) => {
                        self_hash_v.push(Some(query_value as &dyn crate::Hash));
                    }
                    _ => {
                        bail!(
                            "self-hash path query result must be a string or null; path was {}",
                            self_hash_path
                        );
                    }
                }
                query_result_count += 1;
            }
            match query_result_count {
                0 => {
                    // There were no results, so the field is missing, which counts as a None (it will be
                    // added during set_self_hash_slots_to).
                    self_hash_v.push(None);
                }
                1 => {
                    // The slot was already counted in the loop above.
                }
                _ => {
                    bail!("self-hash path query returned more than 1 result (it returned {} results), which is not a valid self-hash path query by definition; path was {}", query_result_count, self_hash_path);
                }
            }
        }
        // Iterate through all self-hash URL path query results.  For self-hash URL fields, a missing
        // field is an error, because the form of the URL is specified by the value itself.
        // TODO: Not sure how to detect missing fields, unless there's a known number of expected results.
        for self_hash_url_path in self.self_hash_url_path_s.iter().map(std::ops::Deref::deref) {
            // println!("    self_hash_url_path: {:?}", self_hash_url_path);
            let mut selector = jsonpath_lib::selector(&self.value);
            let mut query_result_count = 0;
            for query_value in selector(self_hash_url_path)
                .map_err(|e| {
                    error!(
                        "invalid self-hash URL path {}; error was {}",
                        self_hash_url_path, e
                    )
                })?
                .into_iter()
            {
                // println!("        query_value: {:?}", query_value);
                match query_value {
                    serde_json::Value::Null => {
                        bail!("a self-hash URL path query result can not be missing for self-hashing or self-hash verification; path was {}", self_hash_url_path);
                    }
                    serde_json::Value::String(_) => {
                        self_hash_v.push(Some(query_value as &dyn crate::Hash));
                    }
                    _ => {
                        bail!(
                            "self-hash URL path query result must be a string or null; path was {}",
                            self_hash_url_path
                        );
                    }
                }
                query_result_count += 1;
            }
            match query_result_count {
                0 => {
                    // There were no results, so the field is missing, which is an error.
                    bail!("self-hash URL path query returned 0 results, which is not a valid self-hash URL path query by definition; path was {}", self_hash_url_path);
                }
                1 => {
                    // The slot was already counted in the loop above.
                }
                _ => {
                    bail!("self-hash URL path query returned more than 1 result (it returned {} results), which is not a valid self-hash URL path query by definition; path was {}", query_result_count, self_hash_url_path);
                }
            }
        }
        Ok(Box::new(self_hash_v.into_iter()))
    }
    fn set_self_hash_slots_to(&mut self, hash: &dyn crate::Hash) -> Result<()> {
        // println!("SelfHashableJSON::set_self_hash_slots_to");
        let keri_hash = hash.to_keri_hash()?;
        let keri_hash_string = keri_hash.to_string();
        // Because of the signature of jsonpath_lib::replace_with, we have to actually hand the ownership
        // of Value over, and then take it back.  DUMB, but whateva.
        let mut value = self.value.take();
        for self_hash_path in self.self_hash_path_s.iter().map(std::ops::Deref::deref) {
            // Because the self-hash fields aren't required to exist beforehand, we have to do some fanciness
            // to set them.  If they exist already, then we can use jsonpath_lib::replace_with.  But if they
            // don't exist, then we have to query the parent Value and operate on it.

            let mut query_result_count = 0;
            {
                let query_result_count = &mut query_result_count;
                value = jsonpath_lib::replace_with(
                    value,
                    self_hash_path,
                    &mut |_query_value| -> Option<serde_json::Value> {
                        // println!(
                        //     "    self-hash path query result: {:?}; path was {}",
                        //     _query_value, self_hash_path
                        // );
                        *query_result_count += 1;
                        Some(serde_json::Value::String(keri_hash_string.clone()))
                    },
                )
                .map_err(|e| {
                    error!("invalid self-hash path {}; error was {}", self_hash_path, e)
                })?;
            }

            match query_result_count {
                0 => {
                    // We have to query the parent and operate on it manually.
                    let terminating_identifier = jsonpath_terminating_identifier(self_hash_path).expect("programmer error: this should be impossible due to validation in SelfHashableJSON::new");
                    let parent_path = self_hash_path
                        .strip_suffix(terminating_identifier)
                        .unwrap()
                        .strip_suffix('.')
                        .unwrap();
                    // println!("    self-hash path query produced 0 results, so have to query the parent and modify directly.\n        path was: {}\n        parent_path: {}\n        terminating_identifier: {}", self_hash_path, parent_path, terminating_identifier);
                    if parent_path == "$" {
                        // println!("    modifying parent Value: {:?}", value);
                        // It seems that jsonpath_lib::replace_with doesn't work if you specify path "$",
                        // so we have to handle this case directly to work around it.
                        let parent = value.as_object_mut().ok_or_else(|| {
                            error!(
                                "self-hash path query parent (parent path was {}) must be a JSON object; path was {}",
                                parent_path,
                                self_hash_path
                            )
                        })?;
                        debug_assert!(!parent.contains_key(terminating_identifier));
                        parent.insert(
                            terminating_identifier.to_string(),
                            serde_json::Value::String(keri_hash_string.clone()),
                        );
                    } else {
                        // First, validate that the parent_query will produce a JSON object, so we can return
                        // an appropriate error if it's not instead of panicking.
                        {
                            let mut selector = jsonpath_lib::selector(&value);
                            let mut query_result_count = 0;
                            for query_value in selector(parent_path)?.into_iter() {
                                require!(query_value.is_object(), "self-hash path query parent (parent path was {}) must be a JSON object; path was {}", parent_path, self_hash_path);
                                query_result_count += 1;
                            }
                            require!(query_result_count == 1, "self-hash path query parent (parent path was {}) must produce exactly 1 result (it produced {} results); path was {}", parent_path, query_result_count, self_hash_path);
                        }
                        value = jsonpath_lib::replace_with(
                            value,
                            parent_path,
                            &mut |mut query_value| -> Option<serde_json::Value> {
                                // println!("    modifying parent Value: {:?}", query_value);
                                {
                                    let parent = query_value.as_object_mut().unwrap();
                                    debug_assert!(!parent.contains_key(terminating_identifier));
                                    parent.insert(
                                        terminating_identifier.to_string(),
                                        serde_json::Value::String(keri_hash_string.clone()),
                                    );
                                }
                                Some(query_value)
                            },
                        )
                        .map_err(|e| {
                            error!("invalid self-hash path {}; error was {}", self_hash_path, e)
                        })?;
                    }
                }
                1 => {
                    // The query was already handled.  Nothing more to do.
                }
                _ => {
                    panic!("programmer error (or the JSON value was modified in an unexpected way before self-hashing, which is still a programmer error)");
                }
            }
        }
        for self_hash_url_path in self.self_hash_url_path_s.iter().map(std::ops::Deref::deref) {
            value = jsonpath_lib::replace_with(
                value,
                self_hash_url_path,
                &mut |query_value| -> Option<serde_json::Value> {
                    let mut self_hash_url =
                        SelfHashURL::try_from(query_value.as_str().expect("programmer error"))
                            .unwrap();
                    self_hash_url.set_self_hash_slots_to_keri_hash(&keri_hash);
                    Some(serde_json::Value::String(self_hash_url.to_string()))
                },
            )
            .map_err(|e| {
                error!(
                    "invalid self-hash URL path {}; error was {}",
                    self_hash_url_path, e
                )
            })?;
        }
        // Give the Value back.
        self.value = value;
        Ok(())
    }
}
