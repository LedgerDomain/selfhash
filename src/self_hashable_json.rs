use crate::{
    require, write_digest_data_using_jcs, Hash, HashFunction, KERIHashStr, PreferredHashFormat,
    Result, SelfHashURL, SelfHashURLStr, SelfHashable,
};
use std::borrow::Cow;

/// Interprets a serde_json::Value as a KERIHash (either as a KERIHash directly or through the KERIHash
/// component of a SelfHashURL).
impl Hash for serde_json::Value {
    fn hash_function(&self) -> &'static dyn HashFunction {
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
    fn as_preferred_hash_format<'s: 'h, 'h>(&'s self) -> PreferredHashFormat<'h> {
        match self {
            serde_json::Value::String(s) => {
                if let Ok(self_hash_url) = SelfHashURLStr::new_ref(s) {
                    PreferredHashFormat::KERIHash(Cow::Borrowed(
                        self_hash_url.keri_hash_o().unwrap(),
                    ))
                } else if let Ok(keri_hash) = KERIHashStr::new_ref(s) {
                    PreferredHashFormat::KERIHash(Cow::Borrowed(keri_hash))
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
    fn write_digest_data(&self, hasher: &mut dyn crate::Hasher) {
        write_digest_data_using_jcs(self, hasher);
    }
    fn self_hash_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn crate::Hash>> + 'a> {
        if !self.is_object() {
            panic!("self-hashable JSON value is expected to be a JSON object");
        }
        // Only a top-level "selfHash" field in this JSON object is considered a self-hash slot.
        let self_hash_o = self.get("selfHash");
        match self_hash_o {
            Some(serde_json::Value::Null) | None => Box::new(std::iter::once(None)),
            Some(serde_json::Value::String(_)) => Box::new(std::iter::once(
                self_hash_o.map(|self_hash| self_hash as &dyn crate::Hash),
            )),
            Some(_) => {
                panic!("selfHash field must be a string or null.");
            }
        }
    }
    fn set_self_hash_slots_to(&mut self, hash: &dyn crate::Hash) {
        let self_as_object_mut = self
            .as_object_mut()
            .expect("self-hashable JSON value is expected to be a JSON object");
        self_as_object_mut.insert(
            "selfHash".to_string(),
            serde_json::Value::String(hash.to_keri_hash().to_string()),
        );
    }
}

/// This data structure provides the context necessary to process a serde_json::Value as
/// self-hashable data in a configurable way, where the specific field name(s) for self-hash
/// slots and self-hash URL slots are specifiable.
#[derive(Clone)]
pub struct SelfHashableJSON<'v, 'w: 'v> {
    /// This is the JSON value that is being self-hashed.
    value: serde_json::Value,
    /// These are all the top-level fields that are considered to define self-hash values.
    self_hash_field_name_s: Cow<'v, std::collections::HashSet<Cow<'w, str>>>,
    /// These are all the top-level fields that are considered to define self-hash URL values.
    self_hash_url_field_name_s: Cow<'v, std::collections::HashSet<Cow<'w, str>>>,
}

impl<'v, 'w: 'v> SelfHashableJSON<'v, 'w> {
    pub fn new(
        value: serde_json::Value,
        self_hash_field_name_s: Cow<'v, std::collections::HashSet<Cow<'w, str>>>,
        self_hash_url_field_name_s: Cow<'v, std::collections::HashSet<Cow<'w, str>>>,
    ) -> Result<Self> {
        require!(
            value.is_object(),
            "self-hashable JSON value is expected to be a JSON object"
        );
        require!(
            self_hash_field_name_s.is_disjoint(&self_hash_url_field_name_s),
            "self-hash field names and self-hash URL field names must be disjoint."
        );
        // Verify that all the self-hash URL fields are present (and are strings).
        for self_hash_url_field_name in self_hash_url_field_name_s
            .iter()
            .map(std::ops::Deref::deref)
        {
            require!(
                value.get(self_hash_url_field_name).is_some(),
                "self-hash URL field {:?} was not present in JSON",
                self_hash_url_field_name
            );
            let self_hash_url_value = value.get(self_hash_url_field_name).unwrap();
            require!(
                self_hash_url_value.is_string(),
                "self-hash URL field {:?} is expected to be a string",
                self_hash_url_field_name
            );
            require!(
                SelfHashURLStr::new_ref(self_hash_url_value.as_str().unwrap()).is_ok(),
                "self-hash URL field {:?} is expected to be a valid self-hash URL",
                self_hash_url_field_name
            );
        }
        Ok(SelfHashableJSON {
            value,
            self_hash_field_name_s,
            self_hash_url_field_name_s,
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
    fn write_digest_data(&self, mut hasher: &mut dyn crate::Hasher) {
        let mut c = SelfHashableJSON {
            value: self.value.clone(),
            self_hash_field_name_s: self.self_hash_field_name_s.clone(),
            self_hash_url_field_name_s: self.self_hash_url_field_name_s.clone(),
        };
        c.set_self_hash_slots_to(hasher.hash_function().placeholder_hash());
        // Use JCS to produce canonical output.  The `&mut hasher` ridiculousness is because
        // serde_json_canonicalizer::to_writer uses a generic impl of std::io::Write and therefore
        // implicitly requires the `Sized` trait.  Therefore passing in a reference to the reference
        // achieves the desired effect.
        serde_json_canonicalizer::to_writer(&c.value, &mut hasher).unwrap();
    }
    fn self_hash_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn crate::Hash>> + 'a> {
        // This will provide storage for the returned iterator.
        let mut self_hash_v = Vec::new();
        // Iterate through all top-level self-hash field names.  For self-hash fields, a missing field
        // is fine, it just counds as a None.
        for self_hash_field_name in self
            .self_hash_field_name_s
            .iter()
            .map(std::ops::Deref::deref)
        {
            let self_hash_value_o = self.value.get(self_hash_field_name);
            match self_hash_value_o {
                Some(serde_json::Value::Null) | None => {
                    self_hash_v.push(None);
                }
                Some(serde_json::Value::String(_)) => {
                    self_hash_v
                        .push(self_hash_value_o.map(|self_hash| self_hash as &dyn crate::Hash));
                }
                Some(_) => {
                    panic!("named self-hash field must be a string or null.");
                }
            }
        }
        // Iterate through all top-level self-hash URL field names.  For self-hash URL fields, a missing
        // field is an error, because the form of the URL is specified by the value itself.
        for self_hash_url_field_name in self
            .self_hash_url_field_name_s
            .iter()
            .map(std::ops::Deref::deref)
        {
            let self_hash_url_value_o = self.value.get(self_hash_url_field_name);
            match self_hash_url_value_o {
                Some(serde_json::Value::Null) | None => {
                    // self_hash_v.push(None);
                    panic!("a self-hash URL field can not be missing for self-hashing or self-hash verification.");
                }
                Some(serde_json::Value::String(_)) => {
                    self_hash_v.push(
                        self_hash_url_value_o
                            .map(|self_hash_url| self_hash_url as &dyn crate::Hash),
                    );
                }
                Some(_) => {
                    panic!("named self-hash URL field must be a string or null.");
                }
            }
        }

        Box::new(self_hash_v.into_iter())
    }
    fn set_self_hash_slots_to(&mut self, hash: &dyn crate::Hash) {
        let value_as_object_mut = self.value.as_object_mut().unwrap();
        for self_hash_field_name in self
            .self_hash_field_name_s
            .iter()
            .map(std::ops::Deref::deref)
        {
            value_as_object_mut.insert(
                self_hash_field_name.to_owned(),
                serde_json::Value::String(hash.to_keri_hash().to_string()),
            );
        }
        let keri_hash = hash.to_keri_hash();
        for self_hash_url_field_name in self
            .self_hash_url_field_name_s
            .iter()
            .map(std::ops::Deref::deref)
        {
            let self_hash_url_value = value_as_object_mut
                .get_mut(self_hash_url_field_name)
                .unwrap();
            let mut self_hash_url =
                SelfHashURL::try_from(self_hash_url_value.as_str().unwrap()).unwrap();
            self_hash_url.set_self_hash_slots_to_keri_hash(&keri_hash);
            *self_hash_url_value = serde_json::Value::String(self_hash_url.to_string());
        }
    }
}
