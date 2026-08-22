//! Pure, host-testable kernel logic. `lib.rs` wraps this in `#[wasm_bindgen]`.
//! Reuses the `act-policy` PDP; only the JSON marshalling lives here.

use std::collections::BTreeMap;

use futures::FutureExt;
use serde::Deserialize;
use serde_json::Value;

use act_policy::Decision;
use act_policy::grant::{CapabilityGrant, GrantPolicy, PolicyMode};
use act_policy::provider::{CompiledCeiling, ProviderRegistry, ResourceOp};

/// Physical classes we always resolve a ceiling for (native does the same: an
/// undeclared physical cap resolves against an empty declaration → hard deny).
const PHYSICAL: [&str; 3] = ["wasi:filesystem", "wasi:http", "wasi:sockets"];

/// The compiled per-run policy: one ceiling per capability id.
pub struct Kernel {
    ceilings: BTreeMap<String, Box<dyn CompiledCeiling>>,
}

// ---- JSON deserialization mirrors act-cli/src/config.rs (GrantPolicy has no serde) ----

#[derive(Deserialize)]
struct PolicyJson {
    #[serde(default)]
    default: Option<String>,
    #[serde(flatten)]
    entries: BTreeMap<String, GrantJson>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum GrantJson {
    Simple(String),
    Structured {
        mode: String,
        #[serde(default)]
        allow: Vec<Value>,
        #[serde(default)]
        deny: Vec<Value>,
    },
}

impl GrantJson {
    fn to_grant(&self) -> Result<CapabilityGrant, String> {
        match self {
            GrantJson::Simple(m) => Ok(CapabilityGrant {
                mode: PolicyMode::parse(m).map_err(|e| e.to_string())?,
                ..Default::default()
            }),
            GrantJson::Structured { mode, allow, deny } => Ok(CapabilityGrant {
                mode: PolicyMode::parse(mode).map_err(|e| e.to_string())?,
                allow: allow.clone(),
                deny: deny.clone(),
            }),
        }
    }
}

fn parse_policy(policy_json: &str) -> Result<GrantPolicy, String> {
    let pj: PolicyJson = serde_json::from_str(policy_json).map_err(|e| e.to_string())?;
    let default = match pj.default {
        Some(s) => PolicyMode::parse(&s).map_err(|e| e.to_string())?,
        None => PolicyMode::Ask,
    };
    let mut entries = BTreeMap::new();
    for (k, g) in &pj.entries {
        entries.insert(k.clone(), g.to_grant()?);
    }
    Ok(GrantPolicy { default, entries })
}

/// Declared caps: `{ "<capId>": { "constraints": [ ... ] , ... }, ... }`.
/// Only `constraints` is read here.
#[derive(Deserialize)]
struct DeclaredCap {
    #[serde(default, alias = "allow")]
    constraints: Vec<Value>,
}

fn parse_declared(declared_json: &str) -> Result<BTreeMap<String, Vec<Value>>, String> {
    let map: BTreeMap<String, DeclaredCap> =
        serde_json::from_str(declared_json).map_err(|e| e.to_string())?;
    Ok(map.into_iter().map(|(k, v)| (k, v.constraints)).collect())
}

impl Kernel {
    pub fn build(declared_caps_json: &str, policy_json: &str) -> Result<Kernel, String> {
        let declared = parse_declared(declared_caps_json)?;
        let policy = parse_policy(policy_json)?;
        let registry = ProviderRegistry::with_builtins();

        // Resolve a ceiling for every physical class plus every declared cap id
        // (so semantic/generic caps declared by the component are classifiable).
        let mut ids: Vec<String> = PHYSICAL.iter().map(|s| s.to_string()).collect();
        for id in declared.keys() {
            if !ids.contains(id) {
                ids.push(id.clone());
            }
        }

        let mut ceilings: BTreeMap<String, Box<dyn CompiledCeiling>> = BTreeMap::new();
        let empty: Vec<Value> = Vec::new();
        for id in ids {
            let decl = declared.get(&id).unwrap_or(&empty);
            let grant = policy.resolve(&id);
            let ceiling = registry
                .lookup(&id)
                .resolve(&id, Some(decl), &grant)
                // Under --no-default-features every provider's `resolve` is
                // synchronous (no DNS); the future is Ready on first poll.
                .now_or_never()
                .expect("resolve completes synchronously without the host feature")
                .map_err(|e| format!("resolve {id}: {e}"))?;
            ceilings.insert(id, ceiling);
        }
        Ok(Kernel { ceilings })
    }

    pub fn classify_json(&self, op_json: &str) -> Result<&'static str, String> {
        #[derive(Deserialize)]
        struct OpJson {
            #[serde(rename = "capId")]
            cap_id: String,
            #[serde(default)]
            key: String,
            #[serde(default)]
            action: String,
            #[serde(default)]
            attrs: Value,
        }
        let o: OpJson = serde_json::from_str(op_json).map_err(|e| e.to_string())?;
        let op = ResourceOp {
            cap_id: o.cap_id.clone(),
            key: o.key,
            action: o.action,
            attrs: if o.attrs.is_null() {
                Value::Null
            } else {
                o.attrs
            },
        };
        let decision = match self.ceilings.get(&o.cap_id) {
            Some(c) => c.classify(&op),
            // No ceiling for this id (an undeclared, unresolved semantic cap) → deny.
            None => Decision::Deny,
        };
        Ok(match decision {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::Ask => "ask",
        })
    }

    pub fn ceiling_summary_json(&self) -> String {
        let mut obj = serde_json::Map::new();
        for (id, c) in &self.ceilings {
            let mode = match c.effective_mode() {
                PolicyMode::Deny => "deny",
                PolicyMode::Allowlist => "allowlist",
                PolicyMode::Open => "open",
                PolicyMode::Ask => "ask",
            };
            obj.insert(
                id.clone(),
                serde_json::json!({ "declared": c.declared(), "mode": mode }),
            );
        }
        Value::Object(obj).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Component declares wasi:http ceiling api.example.com:443 (any scheme/method);
    // operator policy is allowlist for that host. In-ceiling GET → allow.
    #[test]
    fn http_allowlist_in_ceiling_allows() {
        let declared = r#"{"wasi:http":{"constraints":[{"host":"api.example.com"}]}}"#;
        let policy = r#"{"default":"deny","wasi:http":{"mode":"allowlist","allow":[{"host":"api.example.com"}]}}"#;
        let k = Kernel::build(declared, policy).unwrap();
        let op = r#"{"capId":"wasi:http","key":"api.example.com:443","action":"GET","attrs":{"scheme":"https"}}"#;
        assert_eq!(k.classify_json(op).unwrap(), "allow");
    }

    // Off-allowlist host → deny.
    #[test]
    fn http_off_allowlist_denies() {
        let declared = r#"{"wasi:http":{"constraints":[{"host":"api.example.com"}]}}"#;
        let policy = r#"{"default":"deny","wasi:http":{"mode":"allowlist","allow":[{"host":"api.example.com"}]}}"#;
        let k = Kernel::build(declared, policy).unwrap();
        let op = r#"{"capId":"wasi:http","key":"evil.example.com:443","action":"GET","attrs":{"scheme":"https"}}"#;
        assert_eq!(k.classify_json(op).unwrap(), "deny");
    }

    // In-ceiling host under default `ask` → ask.
    #[test]
    fn http_ask_mode_asks_in_ceiling() {
        let declared = r#"{"wasi:http":{"constraints":[{"host":"api.example.com"}]}}"#;
        let policy = r#"{"default":"ask"}"#;
        let k = Kernel::build(declared, policy).unwrap();
        let op = r#"{"capId":"wasi:http","key":"api.example.com:443","action":"GET","attrs":{"scheme":"https"}}"#;
        assert_eq!(k.classify_json(op).unwrap(), "ask");
    }

    // Undeclared physical cap → hard deny even under `ask` (out of ceiling).
    #[test]
    fn http_undeclared_denies_without_ask() {
        let declared = r#"{}"#;
        let policy = r#"{"default":"ask"}"#;
        let k = Kernel::build(declared, policy).unwrap();
        let op = r#"{"capId":"wasi:http","key":"api.example.com:443","action":"GET","attrs":{"scheme":"https"}}"#;
        assert_eq!(k.classify_json(op).unwrap(), "deny");
    }
}
