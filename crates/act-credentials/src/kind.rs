use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldDef {
    pub key: String,
    pub label: String,
    /// How this field is encoded and acquired (design §3.2). `std:string` is a
    /// CBOR string obtained by prompting; `std:oauth2` is a CBOR map obtained by
    /// running the flow. Defaults to `std:string` so every existing definition
    /// and every hand-written TOML keeps working unchanged.
    #[serde(rename = "type", default = "string_type")]
    pub field_type: String,
    #[serde(default = "yes")]
    pub secret: bool,
    #[serde(default = "yes")]
    pub required: bool,
}

fn yes() -> bool {
    true
}

fn string_type() -> String {
    "std:string".to_string()
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
        field_type: string_type(),
        secret,
        required,
    }
}

/// A field whose value is a map, not a scalar — currently only `std:oauth2`.
fn oauth(key: &str, label: &str) -> FieldDef {
    FieldDef {
        key: key.into(),
        label: label.into(),
        field_type: "std:oauth2".into(),
        secret: true,
        required: true,
    }
}

impl KindRegistry {
    /// The registered multi-field shapes.
    ///
    /// There is deliberately **no single-string shape**. One existed, holding a
    /// field called `std:value`, and that name was pure scaffolding: it told a
    /// reader nothing, while the whole model rests on field names carrying the
    /// meaning. A credential that is one string is one *named* field, and the
    /// person storing it names it — `act secret set --field acme:token`.
    ///
    /// What stays registered is what is genuinely shared and genuinely
    /// meaningful: `std:username`/`std:password`, and the OAuth credential's
    /// `std:token`.
    pub fn builtin() -> Self {
        let defs = vec![
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
                description: Some("OAuth 2 credential, acquired by the browser flow".into()),
                // ONE field. Its value is an object holding std:access-token,
                // std:expires-at and std:scopes — the shape act_sdk::credentials
                // reads. Three flat fields is the pre-migration shape and is
                // exactly what this replaces.
                fields: vec![oauth("std:token", "OAuth token")],
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

    /// A registry holding exactly one kind, built in memory rather than
    /// loaded from disk.
    ///
    /// `act login` uses this for a component that names its own field list
    /// (design §4.3): rather than re-implementing the "not std:string is
    /// refused" rule against that field list directly, it wraps the
    /// declaration in a one-off `KindDef` and routes it through
    /// `prompts_for` exactly as a `--kind` lookup would — one
    /// implementation of the rule, regardless of which source the fields
    /// came from.
    pub fn single(def: KindDef) -> Self {
        Self {
            kinds: BTreeMap::from([(def.id.clone(), def)]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_registers_exactly_the_one_kind_given() {
        let def = KindDef {
            id: "default".to_string(),
            fields: vec![f("acme:tenant", "Tenant", false, true)],
            description: None,
        };
        let reg = KindRegistry::single(def);
        assert_eq!(reg.get("default").unwrap().fields[0].key, "acme:tenant");
        assert!(
            reg.get("std:string").is_none(),
            "a one-off registry does not also carry the builtins"
        );
        assert_eq!(reg.ids().collect::<Vec<_>>(), vec!["default"]);
    }

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

        let oauth = r.get("std:oauth2").unwrap();
        assert_eq!(oauth.fields.len(), 1, "one field, whose value is the map");
        assert_eq!(oauth.fields[0].key, "std:token");
        assert_eq!(oauth.fields[0].field_type, "std:oauth2");

        assert!(r.get("std:nonesuch").is_none());
    }

    #[test]
    fn the_oauth2_shape_is_one_field_not_three() {
        // This is the divergence the plan exists to close: the SDK reads an
        // OAuth credential as ONE field holding a map. Three flat fields would
        // be unreadable by it.
        let r = KindRegistry::builtin();
        let o = r.get("std:oauth2").expect("builtin");
        assert_eq!(o.fields.len(), 1, "one field, whose value is the map");
        assert_eq!(o.fields[0].key, "std:token");
        assert_eq!(o.fields[0].field_type, "std:oauth2");
    }

    #[test]
    fn there_is_no_single_string_shape() {
        // A one-string credential is one *named* field, and only the person
        // storing it knows the name. A registered shape would have to invent
        // one — `std:value` did, and told a reader nothing while the whole
        // model rests on names carrying meaning. `act secret set --field NAME`
        // replaces it.
        let r = KindRegistry::builtin();
        for gone in ["std:opaque", "std:string"] {
            assert!(
                r.get(gone).is_none(),
                "{gone} must not be a registered shape"
            );
        }
        assert!(r.get("std:basic").is_some(), "multi-field shapes stay");
        assert!(r.get("std:oauth2").is_some());
    }

    #[test]
    fn basic_is_two_string_fields() {
        let r = KindRegistry::builtin();
        let b = r.get("std:basic").expect("builtin");
        assert_eq!(b.fields.len(), 2);
        assert!(b.fields.iter().all(|f| f.field_type == "std:string"));
        assert!(b.fields.iter().all(|f| f.secret), "both halves are secret");
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
    fn a_toml_field_with_no_type_defaults_to_string() {
        // The serde default on `FieldDef::field_type`, which is what an
        // operator relies on when they omit `type` — and which the builtins
        // cannot exercise, because they set it explicitly.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("acme.toml"),
            "id = \"acme:untyped\"\n[[fields]]\nkey = \"acme:k\"\nlabel = \"K\"\n",
        )
        .unwrap();
        let r = KindRegistry::load(dir.path()).unwrap();
        assert_eq!(
            r.get("acme:untyped").expect("user kind").fields[0].field_type,
            "std:string",
            "a field with no `type` is a prompted string"
        );
    }

    #[test]
    fn the_builtin_string_shapes_are_typed_explicitly() {
        let r = KindRegistry::builtin();
        for f in &r.get("std:basic").expect("builtin").fields {
            assert_eq!(f.field_type, "std:string", "{}", f.key);
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
type = "std:string"
secret = false
"#,
        )
        .unwrap();
        let r = KindRegistry::load(dir.path()).unwrap();
        let f = &r.get("acme:badge").expect("user kind").fields[0];
        assert_eq!(f.field_type, "std:string");
        assert!(!f.secret);
    }
}
