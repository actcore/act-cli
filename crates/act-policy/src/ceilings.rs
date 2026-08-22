//! The per-run ceiling set: one compiled ceiling per capability id.
//!
//! Both hosts resolve the same set the same way — the native runtime and the
//! browser PDP. They are kept here rather than in either host because they
//! have already drifted once on which classes get resolved, and that question
//! decides whether a declared semantic class is enforceable or merely
//! documented.

use std::collections::BTreeMap;
use std::sync::Arc;

use act_types::constants::{CAP_FILESYSTEM, CAP_HTTP, CAP_SOCKETS};

use crate::grant::{GrantPolicy, PolicyError};
use crate::provider::{CompiledCeiling, ProviderRegistry};

/// Classes a host resolves whether or not the component declared them.
///
/// An undeclared one resolves against `None` and hard-denies, but it still
/// gets a row — the audit header reports a mode for every class an operator
/// might have expected to see, including the ones this artifact does not use.
pub const ALWAYS_RESOLVED: &[&str] = &[
    CAP_FILESYSTEM,
    CAP_HTTP,
    CAP_SOCKETS,
    crate::providers::credentials::CAP_CREDENTIALS,
];

/// Resolve one ceiling per capability id: every [`ALWAYS_RESOLVED`] class,
/// plus every class the component declared.
///
/// `declared` maps a capability id to its declared constraint list; a bare
/// declaration is an entry with an empty list, which is why the map's *keys*
/// carry the declaredness rather than the values. A semantic class absent from
/// it gets no ceiling at all, and callers MUST deny an operation whose id has
/// no ceiling.
pub async fn resolve_ceilings(
    registry: &ProviderRegistry,
    declared: &BTreeMap<String, Vec<serde_json::Value>>,
    policy: &GrantPolicy,
) -> Result<BTreeMap<String, Arc<dyn CompiledCeiling>>, PolicyError> {
    let mut ids: Vec<&str> = ALWAYS_RESOLVED.to_vec();
    for id in declared.keys() {
        if !ids.contains(&id.as_str()) {
            ids.push(id);
        }
    }

    let mut out: BTreeMap<String, Arc<dyn CompiledCeiling>> = BTreeMap::new();
    for id in ids {
        let grant = policy.resolve(id);
        let ceiling = registry
            .lookup(id)
            .resolve(id, declared.get(id).map(Vec::as_slice), &grant)
            .await?;
        out.insert(id.to_string(), Arc::from(ceiling));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decision;
    use crate::provider::ResourceOp;

    #[tokio::test]
    async fn resolves_every_always_class_plus_every_declared_one() {
        let registry = ProviderRegistry::with_builtins();
        let declared = BTreeMap::from([
            (
                "db:drop".to_string(),
                vec![serde_json::json!({"key": "test_*"})],
            ),
            ("wasi:http".to_string(), Vec::new()),
        ]);
        let ceilings = resolve_ceilings(&registry, &declared, &GrantPolicy::default())
            .await
            .unwrap();

        // Every always-resolved class has a row even when undeclared, so the
        // audit header can report a mode for it.
        for id in ALWAYS_RESOLVED.iter().copied() {
            assert!(ceilings.contains_key(id), "{id} must always resolve");
        }
        // Plus the declared semantic class.
        assert!(ceilings.contains_key("db:drop"));
        assert!(ceilings["db:drop"].declared());
        // An always-resolved class the manifest never mentioned is undeclared.
        assert!(!ceilings["wasi:filesystem"].declared());
        // A declared class is resolved whether or not its provider reports it
        // as constrained. (The physical providers derive declaredness from
        // their constraint list, so a bare `wasi:http` table still reads as
        // undeclared to them — pre-existing behaviour this plan preserves.)
        assert!(ceilings.contains_key("wasi:http"));

        // The loop must hand each id *its own* declared constraints, not a
        // shared empty list. `db:drop` was declared with `[{"key": "test_*"}]`
        // and the default policy's mode is Ask, so a key matching that glob
        // asks while one outside it is denied outright — if `resolve_ceilings`
        // dropped the constraint list (e.g. passed `Some(&[])` for every id),
        // both keys would come back `Ask` because a bare declaration leaves
        // the class itself as the ceiling.
        let op = |key: &str| ResourceOp {
            cap_id: "db:drop".into(),
            key: key.into(),
            action: "request".into(),
            attrs: serde_json::Value::Null,
        };
        assert_eq!(
            ceilings["db:drop"].classify(&op("test_events")),
            Decision::Ask
        );
        assert_eq!(
            ceilings["db:drop"].classify(&op("production")),
            Decision::Deny
        );
    }

    #[tokio::test]
    async fn an_undeclared_semantic_class_gets_no_row() {
        let registry = ProviderRegistry::with_builtins();
        let ceilings = resolve_ceilings(&registry, &BTreeMap::new(), &GrantPolicy::default())
            .await
            .unwrap();
        assert!(
            !ceilings.contains_key("db:drop"),
            "a class the manifest never declared is not resolved; callers deny \
             an unresolved id outright"
        );
    }
}
