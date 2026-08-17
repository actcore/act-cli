use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// A credential value. `Debug` and `Display` are redacted, so the spec's
/// "never log a value" rule is a property of the type rather than a habit.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(v: impl Into<String>) -> Self {
        Self(v.into())
    }
    /// The only way to read the value. Named so that call sites are greppable.
    pub fn expose(&self) -> &str {
        &self.0
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret {
    pub kind: String,
    pub fields: BTreeMap<String, SecretValue>,
}

/// Non-secret metadata, safe to list and to show a user.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
}
