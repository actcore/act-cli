//! Generic (semantic) capability provider — glob matching over attrs.
//!
//! Handles any capability class that is not wasi:filesystem, wasi:http,
//! wasi:sockets, or act:credentials — those four have their own typed
//! providers. Uses `globset` to match constraint dimension→value pairs
//! against `op.attrs` — except the dimension named `key`, which resolves
//! from `op.key` instead (see `KEY_DIMENSION`).
//!
//! **The manifest is the ceiling.** A class absent from the component's
//! `act:component` manifest is denied under every mode, and no grant widens
//! it. A class declared with constraints is denied for any operation those
//! constraints do not match, *before* the grant mode is consulted — so `open`
//! means "the grant imposes no further constraint", never "ignore what the
//! artifact declared".

use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::Decision;
use crate::grant::{CapabilityGrant, PolicyError, PolicyMode};
use crate::provider::{CapabilityProvider, CompiledCeiling, Explained, ResourceOp};

/// The constraint dimension that always resolves from `ResourceOp::key`
/// rather than from `attrs`. `op.key` is guest-authored (the host builds it
/// from the guest's own request), so this is not a provenance guarantee —
/// it guarantees there is exactly one `key`: the same value that is shown
/// to the human, recorded in the audit, and matched here, so a second `key`
/// hidden inside `attrs` cannot shadow it.
const KEY_DIMENSION: &str = "key";

pub struct GenericProvider;

#[async_trait::async_trait]
impl CapabilityProvider for GenericProvider {
    async fn resolve(
        &self,
        _cap_id: &str,
        declared: Option<&[serde_json::Value]>,
        grant: &CapabilityGrant,
    ) -> Result<Box<dyn CompiledCeiling>, PolicyError> {
        Ok(Box::new(GenericCeiling {
            mode: grant.mode,
            allow_sets: compile_constraint_globs(&grant.allow)?,
            deny_sets: compile_constraint_globs(&grant.deny)?,
            declared_sets: match declared {
                Some(d) => Some(compile_constraint_globs(d)?),
                None => None,
            },
        }))
    }
}

/// A compiled constraint set: a list of (dimension → GlobSet) pairs.
/// A constraint matches when **every** dimension in it has a glob matching
/// the stringified value. The dimension named `key` (`KEY_DIMENSION`) is the
/// one exception: it never reads `attrs`, resolving from `ResourceOp::key`
/// instead — every other dimension resolves from the stringified
/// `attrs[dimension]`.
///
/// A dimension can be **absent** from `op.attrs` — `attrs` is wholly
/// guest-authored (it comes straight from the request's `args`), so a
/// component can always choose not to send one. What an absent dimension
/// should count as depends on which side of the grant the constraint is on,
/// which is why there are two matchers below instead of one:
///
/// * **allow / declared** constraints are *permissions*: they fail closed by
///   requiring a match, so an absent dimension — nothing to match — makes
///   the constraint **not match** (`matches`). A permission a component
///   never earns by omission is the correct default.
/// * **deny** constraints are *prohibitions*: they must fail closed in the
///   opposite direction, so an absent dimension makes the constraint
///   **match** (`matches_for_deny`). Otherwise a component evades any deny
///   written over an `attrs`-backed dimension just by not sending it — an
///   operator writing `deny: [{"table": "events"}]` expects that to hold
///   even against a request that names no table at all, not to open a hole
///   the guest controls the shape of.
///
/// `key` is unaffected by this split either way: it is host-resolved from
/// `ResourceOp::key`, which is never optional, so there is nothing for either
/// matcher to treat as absent.
struct CompiledConstraint {
    /// Each entry: (key, compiled glob set for that key's patterns).
    key_globs: Vec<(String, GlobSet)>,
    /// Rendering of the original constraint JSON — reported as the "rule"
    /// when this constraint is the one that decided.
    source: String,
}

impl CompiledConstraint {
    /// Permission-side match (allow / declared): an absent dimension does
    /// not match. See the struct doc for why the two sides differ.
    fn matches(&self, op: &ResourceOp) -> bool {
        self.dimensions_match(op, false)
    }

    /// Prohibition-side match (deny): an absent dimension counts as
    /// matching, so a deny cannot be evaded by simply not sending the
    /// dimension it is written over. See the struct doc.
    fn matches_for_deny(&self, op: &ResourceOp) -> bool {
        self.dimensions_match(op, true)
    }

    fn dimensions_match(&self, op: &ResourceOp, absent_matches: bool) -> bool {
        self.key_globs.iter().all(|(dim, glob_set)| {
            if dim == KEY_DIMENSION {
                // Never read `attrs` for this one: a guest-supplied "key"
                // inside args must not shadow the subject the human was
                // shown and the audit recorded. Always present, so
                // `absent_matches` never applies here.
                return glob_set.is_match(&op.key);
            }
            match op.attrs.get(dim) {
                Some(serde_json::Value::String(s)) => glob_set.is_match(s),
                Some(other) => glob_set.is_match(other.to_string().as_str()),
                None => absent_matches,
            }
        })
    }
}

struct GenericCeiling {
    mode: PolicyMode,
    allow_sets: Vec<CompiledConstraint>,
    deny_sets: Vec<CompiledConstraint>,
    /// `None` when the class is absent from the manifest. `Some(&[])` is a
    /// bare declaration: declared, and constraining no dimension.
    declared_sets: Option<Vec<CompiledConstraint>>,
}

impl GenericCeiling {
    /// The same mode-dispatch `classify` used to run, but returning the
    /// attributed reason for whichever verdict was reached — the matching
    /// allow constraint (rendered as JSON text) when one matched, otherwise
    /// the reason the request was refused — alongside the decision. Both
    /// trait methods are expressed in terms of this so the decision output
    /// cannot drift between them.
    fn matched(&self, op: &ResourceOp) -> (Decision, Option<String>) {
        // 1. Deny wins, always and first. Fail-closed the other way from
        //    allow/declared: a dimension the deny names but this op omits
        //    counts as matching, so `deny: [{"table": "events"}]` still
        //    refuses a request that sends no `table` at all — see
        //    `CompiledConstraint::matches_for_deny`.
        if let Some(c) = self.deny_sets.iter().find(|c| c.matches_for_deny(op)) {
            return (Decision::Deny, Some(c.source.clone()));
        }

        // 2. The declaration gates every mode. Absent → denied. Present with
        //    constraints → the op must match one of them.
        let declared_sets = match &self.declared_sets {
            None => return (Decision::Deny, Some("not declared in act:component".into())),
            Some(sets) => sets,
        };
        if !declared_sets.is_empty() && !declared_sets.iter().any(|c| c.matches(op)) {
            return (Decision::Deny, Some("outside the declared ceiling".into()));
        }

        // 3. Only now the grant mode.
        match self.mode {
            PolicyMode::Deny => (Decision::Deny, None),
            PolicyMode::Open => (Decision::Allow, None),
            PolicyMode::Allowlist => match self.allow_sets.iter().find(|c| c.matches(op)) {
                Some(c) => (Decision::Allow, Some(c.source.clone())),
                None => (Decision::Deny, None),
            },
            PolicyMode::Ask => match self.allow_sets.iter().find(|c| c.matches(op)) {
                Some(c) => (Decision::Ask, Some(c.source.clone())),
                // In-ceiling and the grant names no narrower allowlist: ask.
                None if self.allow_sets.is_empty() => (Decision::Ask, None),
                None => (Decision::Deny, None),
            },
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
        self.declared_sets.is_some()
    }

    fn effective_mode(&self) -> PolicyMode {
        if self.declared_sets.is_some() {
            self.mode
        } else {
            PolicyMode::Deny
        }
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
                    // Non-object constraint: compiles to a zero-key constraint
                    // that always matches. On the declared side this now gates
                    // a capability class (a malformed entry degrades to the
                    // bare-declaration ceiling), but it cannot widen anything
                    // beyond what a bare declaration already grants, since the
                    // declaration and its malformations both come from the
                    // artifact author. On the grant side it already meant
                    // "this rule matches everything" before this change.
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
    async fn generic_provider_denies_undeclared() {
        let op = ResourceOp {
            cap_id: "db:truncate".into(),
            key: "orders".into(),
            action: "request".into(),
            attrs: serde_json::json!({"table": "orders"}),
        };
        // The manifest is the ceiling: a class the component never declared is
        // denied under every mode, and no grant can widen it.
        for mode in [
            PolicyMode::Open,
            PolicyMode::Deny,
            PolicyMode::Ask,
            PolicyMode::Allowlist,
        ] {
            let grant = CapabilityGrant {
                mode,
                allow: vec![serde_json::json!({"table": "orders"})],
                deny: vec![],
            };
            let c = GenericProvider
                .resolve("db:truncate", None, &grant)
                .await
                .unwrap();
            assert_eq!(
                c.classify(&op),
                Decision::Deny,
                "undeclared class must deny under mode {mode}"
            );
            assert!(!c.declared());
        }
    }

    #[tokio::test]
    async fn open_grant_does_not_step_over_the_declaration() {
        // `--allow db:drop` opens the class to its *declared* ceiling. It must not
        // authorize a drop of production against a declaration of test_* only.
        let declared = vec![serde_json::json!({"key": "test_*"})];
        let grant = CapabilityGrant {
            mode: PolicyMode::Open,
            allow: vec![],
            deny: vec![],
        };
        let c = GenericProvider
            .resolve("db:drop", Some(&declared), &grant)
            .await
            .unwrap();
        let op = |key: &str| ResourceOp {
            cap_id: "db:drop".into(),
            key: key.into(),
            action: "request".into(),
            attrs: serde_json::Value::Null,
        };
        assert_eq!(c.classify(&op("test_events")), Decision::Allow);
        assert_eq!(c.classify(&op("production")), Decision::Deny);
    }

    #[tokio::test]
    async fn allowlist_grant_wider_than_the_declaration_does_not_widen_the_ceiling() {
        // The grant's allowlist names `*` — deliberately wider than the
        // declaration. The declaration still gates: only test_* is in ceiling.
        let declared = vec![serde_json::json!({"key": "test_*"})];
        let grant = CapabilityGrant {
            mode: PolicyMode::Allowlist,
            allow: vec![serde_json::json!({"key": "*"})],
            deny: vec![],
        };
        let c = GenericProvider
            .resolve("db:drop", Some(&declared), &grant)
            .await
            .unwrap();
        let op = |key: &str| ResourceOp {
            cap_id: "db:drop".into(),
            key: key.into(),
            action: "request".into(),
            attrs: serde_json::Value::Null,
        };
        assert_eq!(c.classify(&op("test_events")), Decision::Allow);
        assert_eq!(c.classify(&op("production")), Decision::Deny);
    }

    #[tokio::test]
    async fn ask_grant_wider_than_the_declaration_does_not_widen_the_ceiling() {
        // Same shape under Ask: the grant's allowlist names `*`, but the
        // declaration still gates which ops are even in ceiling to be asked about.
        let declared = vec![serde_json::json!({"key": "test_*"})];
        let grant = CapabilityGrant {
            mode: PolicyMode::Ask,
            allow: vec![serde_json::json!({"key": "*"})],
            deny: vec![],
        };
        let c = GenericProvider
            .resolve("db:drop", Some(&declared), &grant)
            .await
            .unwrap();
        let op = |key: &str| ResourceOp {
            cap_id: "db:drop".into(),
            key: key.into(),
            action: "request".into(),
            attrs: serde_json::Value::Null,
        };
        assert_eq!(c.classify(&op("test_events")), Decision::Ask);
        assert_eq!(c.classify(&op("production")), Decision::Deny);
    }

    #[tokio::test]
    async fn bare_declaration_leaves_the_class_unconstrained() {
        // `[std.capabilities."db:drop"]` with only a description declares the class
        // and constrains no dimension: the class itself is the ceiling.
        let grant = CapabilityGrant {
            mode: PolicyMode::Ask,
            allow: vec![],
            deny: vec![],
        };
        let c = GenericProvider
            .resolve("db:drop", Some(&[]), &grant)
            .await
            .unwrap();
        let op = ResourceOp {
            cap_id: "db:drop".into(),
            key: "anything".into(),
            action: "request".into(),
            attrs: serde_json::Value::Null,
        };
        assert_eq!(c.classify(&op), Decision::Ask);
        assert!(c.declared());
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
        let declared = vec![serde_json::json!({"table": "orders"})];
        let c = p.resolve("db:read", Some(&declared), &grant).await.unwrap();
        let op = ResourceOp {
            cap_id: "db:read".into(),
            key: "orders".into(),
            action: "".into(),
            attrs: serde_json::json!({"table": "orders"}),
        };
        assert_eq!(c.classify(&op), Decision::Deny);
    }

    #[tokio::test]
    async fn key_is_a_matchable_dimension() {
        let declared = vec![serde_json::json!({"key": "test_*"})];
        let grant = CapabilityGrant {
            mode: PolicyMode::Allowlist,
            allow: vec![serde_json::json!({"key": "test_*"})],
            deny: vec![],
        };
        let c = GenericProvider
            .resolve("db:drop", Some(&declared), &grant)
            .await
            .unwrap();
        let op = |key: &str| ResourceOp {
            cap_id: "db:drop".into(),
            key: key.into(),
            action: "request".into(),
            attrs: serde_json::Value::Null,
        };
        // Matched from op.key alone — no attrs at all.
        assert_eq!(c.classify(&op("test_events")), Decision::Allow);
        assert_eq!(c.classify(&op("production")), Decision::Deny);
    }

    #[tokio::test]
    async fn host_key_beats_a_guest_supplied_key_in_attrs() {
        let declared = vec![serde_json::json!({"key": "test_*"})];
        let grant = CapabilityGrant {
            mode: PolicyMode::Allowlist,
            allow: vec![serde_json::json!({"key": "test_*"})],
            deny: vec![],
        };
        let c = GenericProvider
            .resolve("db:drop", Some(&declared), &grant)
            .await
            .unwrap();
        // The guest puts a compliant-looking "key" in args while the real subject
        // is production. The host-derived key must win, or the prompt a human
        // approved would not be the operation policy authorized.
        let op = ResourceOp {
            cap_id: "db:drop".into(),
            key: "production".into(),
            action: "request".into(),
            attrs: serde_json::json!({"key": "test_decoy"}),
        };
        assert_eq!(c.classify(&op), Decision::Deny);
    }

    #[tokio::test]
    async fn a_constraint_can_require_both_key_and_an_attrs_dimension() {
        // One constraint naming both `key` (host-derived) and `table` (attrs-backed)
        // requires both to match — `.all()` over the dimensions, not just one.
        let declared = vec![serde_json::json!({"key": "test_*", "table": "orders"})];
        let grant = CapabilityGrant {
            mode: PolicyMode::Allowlist,
            allow: vec![serde_json::json!({"key": "test_*", "table": "orders"})],
            deny: vec![],
        };
        let c = GenericProvider
            .resolve("db:drop", Some(&declared), &grant)
            .await
            .unwrap();
        let op = |key: &str, table: &str| ResourceOp {
            cap_id: "db:drop".into(),
            key: key.into(),
            action: "request".into(),
            attrs: serde_json::json!({"table": table}),
        };
        // Matches `key` only: table is wrong → denied.
        assert_eq!(c.classify(&op("test_events", "users")), Decision::Deny);
        // Matches `table` only: key is wrong → denied.
        assert_eq!(c.classify(&op("production", "orders")), Decision::Deny);
        // Matches both → allowed.
        assert_eq!(c.classify(&op("test_events", "orders")), Decision::Allow);
    }

    #[tokio::test]
    async fn a_deny_over_an_omitted_attrs_dimension_still_denies() {
        // I1: `attrs` is wholly guest-authored, so a component can evade any
        // deny written over an attrs-backed dimension by simply not sending
        // it — unless the deny side fails closed on absence. Reproduces the
        // reviewer's CLI repro (`--grant '{"db:drop":{"mode":"open","deny":
        // [{"table":"events"}]}}'` against a request that never names a
        // table) at the provider level: before the fix this returned Allow.
        let grant = CapabilityGrant {
            mode: PolicyMode::Open,
            allow: vec![],
            deny: vec![serde_json::json!({"table": "events"})],
        };
        let c = GenericProvider
            .resolve("db:drop", Some(&[]), &grant)
            .await
            .unwrap();
        let op_without_table = ResourceOp {
            cap_id: "db:drop".into(),
            key: "analytics".into(),
            action: "request".into(),
            attrs: serde_json::Value::Null,
        };
        assert_eq!(
            c.classify(&op_without_table),
            Decision::Deny,
            "a deny over `table` must refuse a request that sends no table at all"
        );
        // The deny still bounds only what it names: a table it doesn't
        // mention, present and non-matching, must not also trip it.
        let op_other_table = ResourceOp {
            cap_id: "db:drop".into(),
            key: "analytics".into(),
            action: "request".into(),
            attrs: serde_json::json!({"table": "orders"}),
        };
        assert_eq!(c.classify(&op_other_table), Decision::Allow);
        // And the table it does name is still denied when present.
        let op_matching_table = ResourceOp {
            cap_id: "db:drop".into(),
            key: "analytics".into(),
            action: "request".into(),
            attrs: serde_json::json!({"table": "events"}),
        };
        assert_eq!(c.classify(&op_matching_table), Decision::Deny);
    }

    #[tokio::test]
    async fn a_deny_over_key_is_unaffected_by_the_fail_closed_change() {
        // `key` is host-resolved from `ResourceOp::key` and is never
        // optional, so the deny-side "absent counts as matching" rule has
        // nothing to change here: a deny over `key` must keep working
        // exactly as before.
        let grant = CapabilityGrant {
            mode: PolicyMode::Open,
            allow: vec![],
            deny: vec![serde_json::json!({"key": "production"})],
        };
        let c = GenericProvider
            .resolve("db:drop", Some(&[]), &grant)
            .await
            .unwrap();
        let op = |key: &str| ResourceOp {
            cap_id: "db:drop".into(),
            key: key.into(),
            action: "request".into(),
            attrs: serde_json::Value::Null,
        };
        assert_eq!(c.classify(&op("production")), Decision::Deny);
        assert_eq!(c.classify(&op("analytics")), Decision::Allow);
    }

    #[tokio::test]
    async fn an_allow_over_an_omitted_dimension_still_fails_to_match() {
        // The permission side is unchanged by I1's fix: an allowlist entry
        // naming a dimension the request doesn't send must still fail to
        // match, not be rescued by the same "absent counts as matching"
        // rule that now applies to deny.
        let grant = CapabilityGrant {
            mode: PolicyMode::Allowlist,
            allow: vec![serde_json::json!({"table": "orders"})],
            deny: vec![],
        };
        let c = GenericProvider
            .resolve("db:read", Some(&[]), &grant)
            .await
            .unwrap();
        let op = ResourceOp {
            cap_id: "db:read".into(),
            key: "orders".into(),
            action: "request".into(),
            attrs: serde_json::Value::Null,
        };
        assert_eq!(
            c.classify(&op),
            Decision::Deny,
            "an allow naming a dimension the request omits must not match"
        );
    }

    #[tokio::test]
    async fn a_declared_constraint_with_an_invalid_glob_fails_to_resolve() {
        // globset rejects an unclosed character class (`allow_unclosed_class:
        // false`). A bad declaration must fail at ceiling-resolution time
        // rather than silently degrading to some other behavior.
        let declared = vec![serde_json::json!({"key": "test_["})];
        let grant = CapabilityGrant {
            mode: PolicyMode::Ask,
            allow: vec![],
            deny: vec![],
        };
        let result = GenericProvider
            .resolve("db:drop", Some(&declared), &grant)
            .await;
        assert!(result.is_err());
    }
}
