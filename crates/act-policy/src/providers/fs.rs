//! Built-in filesystem provider — wraps the Stage 1 FsMatcher.

use std::collections::BTreeMap;

use act_types::{Capabilities, CapabilityRequest};

use crate::Decision;
use crate::effective::effective_fs;
use crate::fs_matcher::{FsAccess, FsMatcher};
use crate::grant::{CapabilityGrant, FsAllow, FsConfig, PolicyError};
use crate::provider::{CapabilityProvider, CompiledCeiling, ResourceOp};

pub struct FsProvider;

#[async_trait::async_trait]
impl CapabilityProvider for FsProvider {
    async fn resolve(
        &self,
        cap_id: &str,
        declared: &[serde_json::Value],
        grant: &CapabilityGrant,
    ) -> Result<Box<dyn CompiledCeiling>, PolicyError> {
        // Build the user FsConfig from the grant.
        let user = fs_config_from_grant(grant)?;
        // Build a Capabilities with this cap_id's declared constraints.
        // IMPORTANT: if declared is empty, don't insert the key at all — so
        // effective_fs treats it as "undeclared" (→ deny, declared=false).
        let caps = caps_from_declared(cap_id, declared);
        // Intersect via effective_fs.
        let eff = effective_fs(&user, &caps);
        // Capture the effective mode before consuming `eff`.
        let effective_mode = eff.config.mode;
        // Compile the matcher from the effective config.
        let matcher = FsMatcher::compile(&eff.config)?;
        Ok(Box::new(FsCeiling {
            matcher,
            effective_mode,
            is_declared: eff.declared,
        }))
    }
}

struct FsCeiling {
    matcher: FsMatcher,
    effective_mode: crate::grant::PolicyMode,
    is_declared: bool,
}

impl CompiledCeiling for FsCeiling {
    fn classify(&self, op: &ResourceOp) -> Decision {
        let access = if op.action == "write" {
            FsAccess::Write
        } else {
            FsAccess::Read
        };
        self.matcher.decide(std::path::Path::new(&op.key), access)
    }

    fn declared(&self) -> bool {
        self.is_declared
    }

    fn effective_mode(&self) -> crate::grant::PolicyMode {
        self.effective_mode
    }
}

/// Convert a `CapabilityGrant` into an `FsConfig` (user-side config).
fn fs_config_from_grant(grant: &CapabilityGrant) -> Result<FsConfig, PolicyError> {
    let allow = grant
        .allow
        .iter()
        .map(|c| {
            let a: act_types::FilesystemAllow =
                serde_json::from_value(c.clone()).map_err(|e| PolicyError::Constraint {
                    cap: "wasi:filesystem",
                    source: e,
                })?;
            Ok(FsAllow {
                glob: a.path,
                mode: a.mode,
            })
        })
        .collect::<Result<Vec<_>, PolicyError>>()?;
    let deny = grant
        .deny
        .iter()
        .map(|c| {
            let a: act_types::FilesystemAllow =
                serde_json::from_value(c.clone()).map_err(|e| PolicyError::Constraint {
                    cap: "wasi:filesystem",
                    source: e,
                })?;
            Ok(a.path)
        })
        .collect::<Result<Vec<_>, PolicyError>>()?;
    Ok(FsConfig {
        mode: grant.mode,
        allow,
        deny,
    })
}

/// Build a `Capabilities` struct containing only `cap_id`'s declared constraints.
/// When `declared` is empty, returns an empty `Capabilities` so that `effective_fs`
/// treats this as "undeclared" (→ deny, `declared=false`).
fn caps_from_declared(cap_id: &str, declared: &[serde_json::Value]) -> Capabilities {
    if declared.is_empty() {
        return Capabilities::default();
    }
    let req = CapabilityRequest {
        constraints: declared.to_vec(),
        ..Default::default()
    };
    Capabilities(BTreeMap::from([(cap_id.to_string(), req)]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decision;
    use crate::grant::{CapabilityGrant, PolicyMode};
    use crate::provider::{CapabilityProvider, ResourceOp};
    use serde_json::json;

    #[tokio::test]
    async fn fs_provider_enforces_ro_write_deny() {
        let p = FsProvider;
        // declared rw on /data/**, user grants allowlist /data/**
        let declared = vec![json!({"path":"/data/**","mode":"rw"})];
        let grant = CapabilityGrant {
            mode: PolicyMode::Allowlist,
            allow: vec![json!({"path":"/data/**","mode":"ro"})], // user narrows to ro
            deny: vec![],
        };
        let c = p
            .resolve("wasi:filesystem", &declared, &grant)
            .await
            .unwrap();
        let op = |action: &str| ResourceOp {
            cap_id: "wasi:filesystem".into(),
            key: "/data/x".into(),
            action: action.into(),
            attrs: serde_json::Value::Null,
        };
        assert_eq!(c.classify(&op("read")), Decision::Allow);
        assert_eq!(c.classify(&op("write")), Decision::Deny); // ro grant ⇒ write denied
    }

    #[tokio::test]
    async fn fs_provider_undeclared_denies_all() {
        let p = FsProvider;
        let grant = CapabilityGrant {
            mode: PolicyMode::Open,
            allow: vec![],
            deny: vec![],
        };
        let c = p.resolve("wasi:filesystem", &[], &grant).await.unwrap();
        let op = ResourceOp {
            cap_id: "wasi:filesystem".into(),
            key: "/data/x".into(),
            action: "read".into(),
            attrs: serde_json::Value::Null,
        };
        // No declaration → effective deny regardless of grant.
        assert_eq!(c.classify(&op), Decision::Deny);
        assert!(!c.declared());
    }

    #[tokio::test]
    async fn fs_provider_open_grant_allows_declared_path() {
        let p = FsProvider;
        let declared = vec![json!({"path":"/tmp/**","mode":"rw"})];
        let grant = CapabilityGrant {
            mode: PolicyMode::Open,
            allow: vec![],
            deny: vec![],
        };
        let c = p
            .resolve("wasi:filesystem", &declared, &grant)
            .await
            .unwrap();
        let op = ResourceOp {
            cap_id: "wasi:filesystem".into(),
            key: "/tmp/test.txt".into(),
            action: "read".into(),
            attrs: serde_json::Value::Null,
        };
        assert_eq!(c.classify(&op), Decision::Allow);
        assert!(c.declared());
    }
}
