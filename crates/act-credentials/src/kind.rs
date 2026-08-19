use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldDef {
    pub key: String,
    pub label: String,
    /// How this field is encoded and acquired (design §3.2). `std:opaque` is a
    /// CBOR string obtained by prompting; `std:oauth2` is a CBOR map obtained by
    /// running the flow. Defaults to `std:opaque` so every existing definition
    /// and every hand-written TOML keeps working unchanged.
    #[serde(rename = "type", default = "opaque")]
    pub field_type: String,
    #[serde(default = "yes")]
    pub secret: bool,
    #[serde(default = "yes")]
    pub required: bool,
}

fn yes() -> bool {
    true
}

fn opaque() -> String {
    "std:opaque".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KindDef {
    pub id: String,
    pub fields: Vec<FieldDef>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct KindRegistry {
    kinds: BTreeMap<String, KindDef>,
}

fn f(key: &str, label: &str, secret: bool, required: bool) -> FieldDef {
    FieldDef {
        key: key.into(),
        label: label.into(),
        field_type: opaque(),
        secret,
        required,
    }
}

impl KindRegistry {
    pub fn builtin() -> Self {
        let defs = vec![
            KindDef {
                id: "std:opaque".into(),
                description: Some("A single opaque value — bearer token or API key".into()),
                fields: vec![f("std:value", "Value", true, true)],
            },
            KindDef {
                id: "std:basic".into(),
                description: Some("Username and password".into()),
                // Both halves are secret: the username selects which account
                // authenticates, which is not the agent's choice to make.
                fields: vec![
                    f("std:username", "Username", true, true),
                    f("std:password", "Password", true, true),
                ],
            },
            KindDef {
                id: "std:oauth2".into(),
                description: Some("OAuth 2 access token".into()),
                fields: vec![
                    f("std:access-token", "Access token", true, true),
                    f("std:expires-at", "Expires at", false, false),
                    f("std:scopes", "Scopes", false, false),
                ],
            },
        ];
        Self {
            kinds: defs.into_iter().map(|d| (d.id.clone(), d)).collect(),
        }
    }

    /// Built-ins plus every `*.toml` in `dir`. User definitions may add new
    /// kinds but never replace a `std:` one.
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
            let def: KindDef = toml::from_str(&text).map_err(std::io::Error::other)?;
            if def.id.starts_with("std:") {
                continue;
            }
            reg.kinds.insert(def.id.clone(), def);
        }
        Ok(reg)
    }

    pub fn get(&self, id: &str) -> Option<&KindDef> {
        self.kinds.get(id)
    }

    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.kinds.keys().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_kinds_are_present_and_shaped() {
        let r = KindRegistry::builtin();
        let basic = r.get("std:basic").expect("std:basic registered");
        let keys: Vec<&str> = basic.fields.iter().map(|f| f.key.as_str()).collect();
        assert_eq!(keys, vec!["std:username", "std:password"]);
        assert!(
            basic.fields.iter().all(|f| f.secret),
            "both halves are a unit"
        );

        let opaque = r.get("std:opaque").unwrap();
        assert_eq!(opaque.fields.len(), 1);
        assert_eq!(opaque.fields[0].key, "std:value");

        let oauth = r.get("std:oauth2").unwrap();
        assert!(
            oauth
                .fields
                .iter()
                .any(|f| f.key == "std:access-token" && f.required)
        );
        assert!(
            oauth
                .fields
                .iter()
                .any(|f| f.key == "std:scopes" && !f.required)
        );

        assert!(r.get("std:nonesuch").is_none());
    }

    #[test]
    fn user_kinds_add_but_never_override_std() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("acme.toml"),
            r#"
id = "acme:badge"
[[fields]]
key = "acme:serial"
label = "Badge serial"
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("evil.toml"),
            r#"
id = "std:basic"
[[fields]]
key = "std:value"
label = "Hijacked"
"#,
        )
        .unwrap();

        let r = KindRegistry::load(dir.path()).unwrap();
        assert!(r.get("acme:badge").is_some(), "user kinds load");
        assert_eq!(
            r.get("std:basic").unwrap().fields.len(),
            2,
            "a std: kind cannot be redefined from user data"
        );
    }

    #[test]
    fn a_field_defaults_to_the_opaque_type() {
        let r = KindRegistry::builtin();
        let basic = r.get("std:basic").expect("builtin");
        for f in &basic.fields {
            assert_eq!(
                f.field_type, "std:opaque",
                "{} should default to a prompted string",
                f.key
            );
        }
    }

    #[test]
    fn a_user_kind_may_name_a_field_type() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("acme.toml"),
            r#"
id = "acme:badge"
[[fields]]
key = "acme:tenant"
label = "Tenant"
type = "std:opaque"
secret = false
"#,
        )
        .unwrap();
        let r = KindRegistry::load(dir.path()).unwrap();
        let f = &r.get("acme:badge").expect("user kind").fields[0];
        assert_eq!(f.field_type, "std:opaque");
        assert!(!f.secret);
    }
}
