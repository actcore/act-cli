use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// A credential value. `Debug` and `Display` are redacted, so the spec's
/// "never logged" holds by construction rather than by discipline — and it
/// holds for an object's members too, which a derived Debug would print.
/// `#[serde(transparent)]` is load-bearing and must stay: it is what keeps the
/// stored JSON equal to the value itself, so a string field is a string on disk
/// and an object field an object. Dropping it would wrap every existing stored
/// credential in a layer and make it unreadable, silently.
///
/// `Eq` is deliberately absent — `serde_json::Value` holds an `f64` and is only
/// `PartialEq`.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretValue(serde_json::Value);

impl SecretValue {
    pub fn new(v: impl Into<serde_json::Value>) -> Self {
        Self(v.into())
    }

    /// The only way to read the value. Named so that call sites are greppable.
    pub fn expose(&self) -> &serde_json::Value {
        &self.0
    }

    /// The value as text, for a `std:string` field. `None` for any other JSON
    /// type — an object is not a string with extra steps.
    pub fn expose_str(&self) -> Option<&str> {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(<redacted>)")
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// What the store holds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecretRecord {
    pub kind: String,
    /// Revealable: returned to the component.
    pub fields: BTreeMap<String, SecretValue>,
    /// Host-only: refresh tokens, issuer binding. Never projected.
    #[serde(default)]
    pub host_only: BTreeMap<String, SecretValue>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub expires_at: Option<i64>,
}

/// What the component receives.
#[derive(Debug, Clone, PartialEq)]
pub struct Secret {
    pub kind: String,
    pub fields: BTreeMap<String, SecretValue>,
}

/// Non-secret metadata, safe to list and to show a user.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecretInfo {
    pub key: String,
    pub kind: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub expires_at: Option<i64>,
}

impl SecretRecord {
    pub fn project(&self) -> Secret {
        Secret {
            kind: self.kind.clone(),
            fields: self.fields.clone(),
        }
    }

    pub fn info(&self, key: &str) -> SecretInfo {
        SecretInfo {
            key: key.to_string(),
            kind: self.kind.clone(),
            description: self.description.clone(),
            expires_at: self.expires_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> SecretRecord {
        let mut fields = BTreeMap::new();
        fields.insert("std:access-token".to_string(), SecretValue::new("at-123"));
        let mut host_only = BTreeMap::new();
        host_only.insert("std:refresh-token".to_string(), SecretValue::new("rt-456"));
        SecretRecord {
            kind: "std:oauth2".into(),
            fields,
            host_only,
            description: Some("Notion".into()),
            expires_at: Some(1_800_000_000),
        }
    }

    #[test]
    fn projection_drops_the_host_only_compartment() {
        let projected = record().project();
        assert!(projected.fields.contains_key("std:access-token"));
        assert!(
            !projected.fields.contains_key("std:refresh-token"),
            "a refresh token must never cross the sandbox boundary"
        );
    }

    #[test]
    fn debug_never_prints_a_value() {
        let rendered = format!("{:?}", record());
        assert!(!rendered.contains("at-123"));
        assert!(!rendered.contains("rt-456"));
        assert!(
            rendered.contains("std:oauth2"),
            "non-secret fields stay legible"
        );
    }

    #[test]
    fn an_object_value_round_trips() {
        let v = SecretValue::new(serde_json::json!({
            "std:access-token": "at",
            "std:expires-at": 1_760_000_000u64,
        }));
        assert_eq!(v.expose()["std:access-token"], "at");
        assert_eq!(v.expose_str(), None, "an object is not a string");
    }

    #[test]
    fn a_string_value_still_reads_as_a_string() {
        let v = SecretValue::new("sekrit");
        assert_eq!(v.expose_str(), Some("sekrit"));
    }

    #[test]
    fn debug_and_display_redact_an_object_including_its_members() {
        // The phase-1 guarantee, restated for the shape that did not exist
        // then: a map's members are material too, and a derived Debug on the
        // inner Value would print every one of them.
        let v = SecretValue::new(serde_json::json!({
            "std:access-token": "ghp-sentinel-token",
            "std:scopes": ["repo"],
        }));
        for rendered in [format!("{v:?}"), format!("{v}")] {
            assert!(
                !rendered.contains("ghp-sentinel-token") && !rendered.contains("repo"),
                "redaction leaked: {rendered}"
            );
            assert!(rendered.contains("redacted"), "must say so: {rendered}");
        }
    }
}
