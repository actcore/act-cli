//! Credential **field definitions** — what a field name means to this host.
//!
//! There is no registry of well-known field *names*, and that is deliberate.
//! `ACT-CONSTANTS.md` §8 registers field **types** (`std:string`, `std:oauth2`)
//! and the members of an OAuth value, because those are mechanical: the type
//! decides how a value is encoded and how it is acquired, and both ends must
//! agree. A field's *name* is not mechanical. Whoever stores the credential
//! names it, in their own namespace, and the component that reads it is the
//! same party that asked for it — by declaring the field, or by printing the
//! exact `act secret set --field …` command a user copies.
//!
//! An earlier model registered `std:username`, `std:password` and `std:token`
//! as shared vocabulary. Two components spelling the same upstream credential
//! identically is a convention benefit, not a mechanical one, and it cost more
//! than it bought: because a component may not declare a `std:` name (§4.3
//! rule 1), the components using the most standard credential shape were the
//! ones that could not declare their fields at all, and so lost the
//! zero-argument `act login` the declaration exists to provide.
//!
//! What remains here is the operator's own vocabulary: `*.toml` files naming a
//! field's label, type and whether it is material. Everything else resolves to
//! a secret `std:string` labelled by its own name.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// What one field name means.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldDef {
    pub key: String,
    pub label: String,
    /// How this field is encoded and acquired (design §3.2). `std:string` is a
    /// CBOR string obtained by prompting; `std:oauth2` is a CBOR map obtained by
    /// running the flow. Defaults to `std:string`.
    #[serde(rename = "type", default = "string_type")]
    pub field_type: String,
    #[serde(default = "yes")]
    pub secret: bool,
    /// Whether the field must be present. Meaningful for a **declaration** — a
    /// component may mark one optional — and defaults to true everywhere else,
    /// since a definition describes what a name means rather than what any one
    /// credential needs.
    #[serde(default = "yes")]
    pub required: bool,
}

fn yes() -> bool {
    true
}

fn string_type() -> String {
    "std:string".to_string()
}

/// What this host knows about field names: whatever the operator defined, and
/// nothing else. `Default` is an empty one, which is the common case.
#[derive(Debug, Clone, Default)]
pub struct FieldRegistry {
    fields: BTreeMap<String, FieldDef>,
}

impl FieldRegistry {
    /// Every `*.toml` in `dir`, each defining one field. An operator may name
    /// anything in their own namespace but never a `std:` one: that namespace
    /// is the spec's, and a local file must not mint into it.
    pub fn load(dir: &Path) -> std::io::Result<Self> {
        let mut reg = Self::default();
        if !dir.is_dir() {
            return Ok(reg);
        }
        let mut entries: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect();
        entries.sort();
        for path in entries {
            let text = std::fs::read_to_string(&path)?;
            let def: FieldDef = toml::from_str(&text).map_err(std::io::Error::other)?;
            if def.key.starts_with("std:") {
                // Refused, and said out loud: an operator whose file is
                // silently ignored goes on believing the label and secrecy
                // flag they wrote are the ones in force.
                eprintln!(
                    "act: warning: {} defines '{}', and the std: namespace is the \
                     spec's — ignoring the file. Name the field in your own \
                     namespace instead.",
                    path.display(),
                    def.key
                );
                continue;
            }
            reg.fields.insert(def.key.clone(), def);
        }
        Ok(reg)
    }

    pub fn get(&self, name: &str) -> Option<&FieldDef> {
        self.fields.get(name)
    }

    /// What to prompt for under `name`: the operator's definition if there is
    /// one, else a secret string labelled with the name itself.
    ///
    /// The fallback is the normal path, not the exception — it is what makes
    /// `--field acme:token` work with no ceremony anywhere. A name this host
    /// has never heard of is a perfectly good name; it carries no meaning the
    /// host is entitled to interpret, so it is presented verbatim rather than
    /// dressed in invented words.
    pub fn resolve(&self, name: &str) -> FieldDef {
        self.get(name).cloned().unwrap_or_else(|| FieldDef {
            key: name.to_string(),
            label: name.to_string(),
            field_type: string_type(),
            secret: true,
            required: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_field_name_is_well_known() {
        // `ACT-CONSTANTS.md` §8 registers field TYPES and the members of an
        // OAuth value. It registers no names, so neither does this — a registry
        // with no operator definitions knows nothing, and `Default` is the
        // whole of how you get one.
        let r = FieldRegistry::default();
        for gone in ["std:username", "std:password", "std:token"] {
            assert!(
                r.get(gone).is_none(),
                "{gone} was vocabulary, and vocabulary is not the host's to issue"
            );
        }
    }

    #[test]
    fn a_type_is_never_a_field_name() {
        // The two registered types and the two retired shape ids resolve to
        // nothing: a type says how a value is encoded, never what it is called.
        let r = FieldRegistry::default();
        for gone in ["std:string", "std:oauth2", "std:basic", "std:opaque"] {
            assert!(r.get(gone).is_none(), "{gone} is a type, never a name");
        }
    }

    #[test]
    fn a_name_resolves_to_a_secret_string_labelled_by_itself() {
        // What makes `--field acme:token` work with no ceremony: a name the
        // host has never heard of is a perfectly good name, presented verbatim
        // rather than dressed in invented words.
        let d = FieldRegistry::default().resolve("acme:token");
        assert_eq!(d.key, "acme:token");
        assert_eq!(d.label, "acme:token");
        assert_eq!(d.field_type, "std:string");
        assert!(d.secret);
    }

    #[test]
    fn an_operator_definition_resolves_over_the_bare_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("t.toml"),
            "key = \"acme:tenant\"\nlabel = \"Tenant\"\n",
        )
        .unwrap();
        let r = FieldRegistry::load(dir.path()).unwrap();
        assert_eq!(
            r.resolve("acme:tenant").label,
            "Tenant",
            "the operator's word, not the raw name"
        );
    }

    #[test]
    fn operator_files_add_names_but_never_mint_a_std_one() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("acme.toml"),
            "key = \"acme:tenant\"\nlabel = \"Tenant\"\nsecret = false\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("evil.toml"),
            "key = \"std:password\"\nlabel = \"Hijacked\"\n",
        )
        .unwrap();

        let r = FieldRegistry::load(dir.path()).unwrap();
        let acme = r.get("acme:tenant").expect("operator names load");
        assert!(!acme.secret, "an operator may say a field is not material");
        assert_eq!(acme.field_type, "std:string", "type defaults when omitted");
        assert!(
            r.get("std:password").is_none(),
            "the std: namespace is the spec's; a local file must not mint into it"
        );
    }

    #[test]
    fn a_toml_field_may_name_its_type() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("acme.toml"),
            "key = \"acme:tok\"\nlabel = \"Tok\"\ntype = \"std:oauth2\"\n",
        )
        .unwrap();
        let r = FieldRegistry::load(dir.path()).unwrap();
        assert_eq!(r.get("acme:tok").unwrap().field_type, "std:oauth2");
    }
}
