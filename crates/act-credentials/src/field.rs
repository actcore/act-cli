//! The registry of well-known credential **field names**.
//!
//! There are no credential "shapes" or "kinds" here, and that is the point. A
//! credential is a set of named fields; each field's type says how its value is
//! encoded and how it is acquired (design §3.2). What a registry can usefully
//! say is what a *name* means — its label, whether its value is material, and
//! its type — so that is all it says.
//!
//! An earlier version grouped fields into named shapes (`std:basic` and friends)
//! and made a credential an instance of one. That was the old kind model wearing
//! a new word: it minted `std:` ids the spec never registered, it overloaded
//! `std:oauth2` as both a field type and a shape id, and it forced a credential
//! into a fixed list when the whole model rests on fields being independent.
//! `ACT-CONSTANTS.md` §8 registers types and names — never shapes — and this is
//! now the same thing in code.

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
    /// component may mark one optional — and always true for a registered name,
    /// which describes what a name means rather than what any credential needs.
    #[serde(default = "yes")]
    pub required: bool,
}

fn yes() -> bool {
    true
}

fn string_type() -> String {
    "std:string".to_string()
}

/// Well-known field names plus whatever an operator defined.
#[derive(Debug, Clone, Default)]
pub struct FieldRegistry {
    fields: BTreeMap<String, FieldDef>,
}

fn f(key: &str, label: &str, field_type: &str) -> FieldDef {
    FieldDef {
        key: key.into(),
        label: label.into(),
        field_type: field_type.into(),
        secret: true,
        required: true,
    }
}

impl FieldRegistry {
    /// The names registered in `ACT-CONSTANTS.md` §8.2, and only those.
    pub fn builtin() -> Self {
        let defs = vec![
            // Both halves of a password credential are material, the username
            // included: which account authenticates is not the agent's choice.
            f("std:username", "Username", "std:string"),
            f("std:password", "Password", "std:string"),
            // One field whose value is the OAuth map (§8.3), not three flat
            // ones — that is the shape act_sdk::credentials reads.
            f("std:token", "OAuth token", "std:oauth2"),
        ];
        Self {
            fields: defs.into_iter().map(|d| (d.key.clone(), d)).collect(),
        }
    }

    /// Built-ins plus every `*.toml` in `dir`, each defining one field. An
    /// operator may add names but never redefine a `std:` one — the registry
    /// is the shared vocabulary, and a local file must not change what a
    /// well-known name means for everyone reading it.
    pub fn load(dir: &Path) -> std::io::Result<Self> {
        let mut reg = Self::builtin();
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
                    "act: warning: {} defines '{}', which is in the registry-governed \
                     std: namespace — ignoring the file and keeping the registered \
                     definition",
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

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.fields.keys().map(String::as_str)
    }

    /// What to prompt for under `name`: the registered definition, or — for a
    /// name nobody registered — a secret string labelled with the name itself.
    ///
    /// The fallback is deliberate and is what makes `--field acme:token` work
    /// without ceremony. A name the registry does not know is still a perfectly
    /// good name; it simply carries no shared meaning, so the host presents it
    /// verbatim rather than inventing words for it.
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
    fn only_the_names_the_spec_registers_are_builtin() {
        let r = FieldRegistry::builtin();
        let mut names: Vec<&str> = r.names().collect();
        names.sort();
        assert_eq!(
            names,
            ["std:password", "std:token", "std:username"],
            "ACT-CONSTANTS 8.2 and nothing else"
        );
    }

    #[test]
    fn there_are_no_shapes() {
        // The old model grouped fields under ids like `std:basic`, which the
        // spec never registered and which overloaded `std:oauth2` as both a
        // field type and a group id. Nothing may resolve those now.
        let r = FieldRegistry::builtin();
        for gone in ["std:basic", "std:opaque", "std:string", "std:oauth2"] {
            assert!(
                r.get(gone).is_none(),
                "{gone} is a type or a former shape, never a field name"
            );
        }
    }

    #[test]
    fn the_oauth_field_carries_the_map_type() {
        let r = FieldRegistry::builtin();
        let tok = r.get("std:token").expect("registered");
        assert_eq!(tok.field_type, "std:oauth2", "its value is the 8.3 map");
        assert!(tok.secret);
    }

    #[test]
    fn both_halves_of_a_password_credential_are_material() {
        let r = FieldRegistry::builtin();
        for name in ["std:username", "std:password"] {
            let d = r.get(name).expect("registered");
            assert!(
                d.secret,
                "{name}: which account authenticates is not public"
            );
            assert_eq!(d.field_type, "std:string");
        }
    }

    #[test]
    fn an_unregistered_name_resolves_to_a_secret_string_labelled_by_itself() {
        // What makes `--field acme:token` work with no ceremony: a name nobody
        // registered is still a good name, it just carries no shared meaning,
        // so it is presented verbatim rather than dressed in invented words.
        let d = FieldRegistry::builtin().resolve("acme:token");
        assert_eq!(d.key, "acme:token");
        assert_eq!(d.label, "acme:token");
        assert_eq!(d.field_type, "std:string");
        assert!(d.secret);
    }

    #[test]
    fn a_registered_name_resolves_to_its_definition() {
        let d = FieldRegistry::builtin().resolve("std:username");
        assert_eq!(d.label, "Username", "the registry's word, not the raw name");
    }

    #[test]
    fn operator_files_add_names_but_never_redefine_a_std_one() {
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
        assert_eq!(
            r.get("std:password").unwrap().label,
            "Password",
            "a local file must not change what a well-known name means"
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
