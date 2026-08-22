//! Generic (semantic) capability provider — glob matching over attrs.
//!
//! Handles any capability class that is not wasi:filesystem, wasi:http, or
//! wasi:sockets. Uses `globset` to match constraint key→value pairs against
//! `op.attrs`.
//!
//! **Undeclared-consent asymmetry:**
//! Physical providers (fs/http/sockets): empty `declared` → deny (no ceiling).
//! This provider: empty `declared` → **unbounded** ceiling.
//! Under `Ask` mode, undeclared + ask → `Ask` (NOT deny), because there is no
//! physical resource to misuse; the consent system governs access.

use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::Decision;
use crate::grant::{CapabilityGrant, PolicyError, PolicyMode};
use crate::provider::{CapabilityProvider, CompiledCeiling, Explained, ResourceOp};

pub struct GenericProvider;

#[async_trait::async_trait]
impl CapabilityProvider for GenericProvider {
    async fn resolve(
        &self,
        _cap_id: &str,
        declared: Option<&[serde_json::Value]>,
        grant: &CapabilityGrant,
    ) -> Result<Box<dyn CompiledCeiling>, PolicyError> {
        let declared = declared.unwrap_or(&[]);
        // Unbounded ceiling when nothing is declared (no physical resource ceiling).
        let unbounded = declared.is_empty();
        let is_declared = !declared.is_empty();

        // Compile allow constraints from the grant.
        let allow_sets = compile_constraint_globs(&grant.allow)?;
        let deny_sets = compile_constraint_globs(&grant.deny)?;

        Ok(Box::new(GenericCeiling {
            mode: grant.mode,
            allow_sets,
            deny_sets,
            is_declared,
            unbounded,
        }))
    }
}

/// A compiled constraint set: a list of (key → GlobSet) pairs.
/// A constraint matches when **every** key in it has a glob matching the
/// stringified `attrs[key]`.
struct CompiledConstraint {
    /// Each entry: (key, compiled glob set for that key's patterns).
    key_globs: Vec<(String, GlobSet)>,
    /// Rendering of the original constraint JSON — reported as the "rule"
    /// when this constraint is the one that decided.
    source: String,
}

impl CompiledConstraint {
    fn matches(&self, attrs: &serde_json::Value) -> bool {
        self.key_globs.iter().all(|(key, glob_set)| {
            let val = attrs.get(key);
            if let Some(val) = val {
                let s = match val {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                glob_set.is_match(&s)
            } else {
                false
            }
        })
    }
}

struct GenericCeiling {
    mode: PolicyMode,
    allow_sets: Vec<CompiledConstraint>,
    deny_sets: Vec<CompiledConstraint>,
    is_declared: bool,
    /// True when declared slice was empty → treat ceiling as universal.
    unbounded: bool,
}

impl GenericCeiling {
    /// The same mode-dispatch `classify` used to run, but returning the
    /// matching allow constraint (rendered as JSON text) alongside the
    /// decision. Both trait methods are expressed in terms of this so the
    /// decision output cannot drift between them.
    fn matched(&self, op: &ResourceOp) -> (Decision, Option<String>) {
        // Deny wins first: any deny constraint matching → Deny.
        if self.deny_sets.iter().any(|c| c.matches(&op.attrs)) {
            return (Decision::Deny, None);
        }

        match self.mode {
            PolicyMode::Deny => (Decision::Deny, None),
            PolicyMode::Open => (Decision::Allow, None),
            PolicyMode::Allowlist => {
                // Allow iff some allow constraint matches.
                match self.allow_sets.iter().find(|c| c.matches(&op.attrs)) {
                    Some(c) => (Decision::Allow, Some(c.source.clone())),
                    None => (Decision::Deny, None),
                }
            }
            PolicyMode::Ask => {
                // In-ceiling = unbounded OR some allow constraint matches.
                // Unbounded means no declaration was present (generic class never
                // declared), so the ceiling is treated as universal — any request
                // gets a prompt rather than a hard deny.
                if self.unbounded {
                    (Decision::Ask, None)
                } else if let Some(c) = self.allow_sets.iter().find(|c| c.matches(&op.attrs)) {
                    (Decision::Ask, Some(c.source.clone()))
                } else {
                    (Decision::Deny, None)
                }
            }
        }
    }
}

impl CompiledCeiling for GenericCeiling {
    fn classify(&self, op: &ResourceOp) -> Decision {
        self.matched(op).0
    }

    fn classify_explained(&self, op: &ResourceOp) -> Explained {
        let (decision, rule) = self.matched(op);
        Explained { decision, rule }
    }

    fn declared(&self) -> bool {
        self.is_declared
    }
}

/// Compile a list of constraint Values into `CompiledConstraint`s.
/// Each Value is expected to be a JSON object mapping key → glob-pattern string.
fn compile_constraint_globs(
    cs: &[serde_json::Value],
) -> Result<Vec<CompiledConstraint>, PolicyError> {
    cs.iter()
        .map(|c| {
            let source = c.to_string();
            let obj = match c.as_object() {
                Some(obj) => obj,
                None => {
                    // Non-object constraint: treat as empty (always-match or never-match?).
                    // We treat it as a zero-key constraint that always matches (matches everything).
                    return Ok(CompiledConstraint {
                        key_globs: vec![],
                        source,
                    });
                }
            };
            let mut key_globs = Vec::new();
            for (key, val) in obj {
                let pattern = match val {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                let mut builder = GlobSetBuilder::new();
                let glob = Glob::new(&pattern).map_err(|e| PolicyError::Glob {
                    pat: pattern.clone(),
                    source: e,
                })?;
                builder.add(glob);
                let glob_set = builder.build().map_err(|e| PolicyError::Glob {
                    pat: pattern.clone(),
                    source: e,
                })?;
                key_globs.push((key.clone(), glob_set));
            }
            Ok(CompiledConstraint { key_globs, source })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decision;
    use crate::grant::{CapabilityGrant, PolicyMode};
    use crate::provider::{CapabilityProvider, ResourceOp};

    #[tokio::test]
    async fn generic_provider_globs_args() {
        let p = GenericProvider;
        let declared = vec![serde_json::json!({"database":"staging_*"})];
        let grant = CapabilityGrant {
            mode: PolicyMode::Allowlist,
            allow: vec![serde_json::json!({"database":"staging_*"})],
            deny: vec![],
        };
        let c = p
            .resolve("db:truncate", Some(&declared), &grant)
            .await
            .unwrap();
        let op = |db: &str| ResourceOp {
            cap_id: "db:truncate".into(),
            key: db.into(),
            action: "".into(),
            attrs: serde_json::json!({"database": db}),
        };
        assert_eq!(c.classify(&op("staging_events")), Decision::Allow);
        assert_eq!(c.classify(&op("prod_users")), Decision::Deny); // no glob match
    }

    #[tokio::test]
    async fn generic_provider_permits_undeclared() {
        let p = GenericProvider;
        let op = ResourceOp {
            cap_id: "db:truncate".into(),
            key: "orders".into(),
            action: "".into(),
            attrs: serde_json::json!({"table":"orders"}),
        };

        // Undeclared + open grant → Allow (no declaration ceiling to bound it).
        let open = CapabilityGrant {
            mode: PolicyMode::Open,
            allow: vec![],
            deny: vec![],
        };
        assert_eq!(
            p.resolve("db:truncate", None, &open)
                .await
                .unwrap()
                .classify(&op),
            Decision::Allow
        );

        // Undeclared + deny grant → Deny.
        let deny = CapabilityGrant {
            mode: PolicyMode::Deny,
            allow: vec![],
            deny: vec![],
        };
        assert_eq!(
            p.resolve("db:truncate", None, &deny)
                .await
                .unwrap()
                .classify(&op),
            Decision::Deny
        );

        // Undeclared + ask grant (the default) → Ask (prompt), NOT deny — there is
        // no ceiling to be "out of".
        let ask = CapabilityGrant {
            mode: PolicyMode::Ask,
            allow: vec![],
            deny: vec![],
        };
        assert_eq!(
            p.resolve("db:truncate", None, &ask)
                .await
                .unwrap()
                .classify(&op),
            Decision::Ask
        );
    }

    #[tokio::test]
    async fn with_builtins_routes_classes() {
        use crate::provider::ProviderRegistry;
        let r = ProviderRegistry::with_builtins();
        // db:* has no typed provider → generic; wasi:filesystem → fs provider.
        assert!(
            r.lookup("db:truncate")
                .resolve("db:truncate", None, &Default::default())
                .await
                .is_ok()
        );
        assert!(
            r.lookup("wasi:filesystem")
                .resolve("wasi:filesystem", None, &Default::default())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn generic_deny_wins_over_allow() {
        let p = GenericProvider;
        let grant = CapabilityGrant {
            mode: PolicyMode::Allowlist,
            allow: vec![serde_json::json!({"table": "orders"})],
            deny: vec![serde_json::json!({"table": "orders"})],
        };
        let c = p.resolve("db:read", None, &grant).await.unwrap();
        let op = ResourceOp {
            cap_id: "db:read".into(),
            key: "orders".into(),
            action: "".into(),
            attrs: serde_json::json!({"table": "orders"}),
        };
        assert_eq!(c.classify(&op), Decision::Deny);
    }
}
