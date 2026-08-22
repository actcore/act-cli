//! Host side of `act:consent/consent-authority` — the gate a component asks
//! before taking an action the host cannot see it taking.
//!
//! ## Two layers, the same shape as `act:credentials`
//!
//! [`ConsentGate`] is the whole of the decision logic. It owns no wasmtime
//! types, so ACT-CONSENT.md §4's procedure is unit-testable against real
//! compiled ceilings with no engine, no linker and no guest.
//!
//! Around it sits the generated-trait bridge. `request` is an `async func` in
//! WIT, so bindgen lowers it through `func_wrap_concurrent`: the generated
//! [`consent_authority::HostWithStore`] method is an **associated function
//! taking a [`wasmtime::component::Accessor`]**, not a method on `&self`, and
//! the impl target is the `HasData` marker rather than `HostState`. The
//! bridge reaches host state through the accessor, decodes the request, and
//! calls the gate. `credentials.rs`'s module header explains the same shape at
//! greater length.
//!
//! ## Why refusals are indistinguishable
//!
//! Every path here returns `deny` — undeclared, denied by grant, refused by a
//! human, no channel to ask on. That is ACT-CONSENT.md §8.4: a component that
//! could tell those apart could map the operator's policy by varying its
//! requests. The distinction lives in the audit trail, which the operator
//! reads and the component cannot.

use std::collections::BTreeMap;
use std::sync::Arc;

use act_policy::provider::CompiledCeiling;
use wasmtime::component::{HasSelf, Linker};

use crate::bindings::act::consent::{consent_authority, types};
use crate::store::HostState;

/// The host's answer, straight from the WIT enum. Not a host-side copy: one
/// type means the bridge cannot lower a verdict into the wrong variant, and
/// §8.4's "every refusal is the same value" is a property of the type rather
/// than of a conversion someone has to keep right.
pub(crate) use types::Decision;

/// The sub-operation recorded for a consent decision. Consent has no
/// sub-operations — the class *is* the action — so this is a constant, and it
/// exists only to fill the audit's action column with something.
///
/// It reaches the record on the two statically-decided paths. The `ask` path
/// goes through `CapDecisionRecord::answered`, which hardcodes
/// `action: String::new()` for every capability class, so a consent decision
/// taken by a human is recorded with an empty action like any other. That is
/// pre-existing shared behaviour, not something this class chose.
const ACTION: &str = "request";

/// One component run's semantic-authorization gate.
///
/// Assembled per call from [`HostState`], which is why the shared pieces are
/// `Arc`s rather than owned: `cache` in particular must be the run's one
/// cache, or §5's "remember the decision for at least the component run"
/// would hold only for the length of a single call, and a component could
/// wear a human down by asking again.
pub(crate) struct ConsentGate {
    /// Every declared class the host does not wire interception for. **A miss
    /// here is what "undeclared" means** — see [`ConsentGate::decide`].
    ///
    /// `create_store` builds it as every resolved ceiling minus
    /// `ALWAYS_RESOLVED`, so the four classes the host enforces by
    /// interception are absent and a consent request naming one of them is
    /// refused. That is deliberate: those already have a gate on the
    /// boundary, and a second door that could answer "allow" for them would
    /// be either redundant or a way around the first.
    semantic_ceilings: Arc<BTreeMap<String, Arc<dyn CompiledCeiling>>>,
    prompter: Arc<dyn act_policy::consent::ConsentPrompter>,
    cache: Arc<act_policy::consent::DecisionCache>,
    /// The reference the operator supplied for this component, for the prompt
    /// line. Never a name the guest chose (ACT-CONSENT.md §5).
    component: String,
}

impl ConsentGate {
    fn from_accessor(
        accessor: &wasmtime::component::Accessor<HostState, HasSelf<HostState>>,
    ) -> Self {
        accessor.with(|mut access| {
            let state: &mut HostState = access.get();
            Self {
                semantic_ceilings: state.semantic_ceilings.clone(),
                prompter: state.consent_prompter.clone(),
                cache: state.consent_cache.clone(),
                component: state.component_ref.clone(),
            }
        })
    }

    /// The decision procedure of ACT-CONSENT.md §4, in order.
    ///
    /// Step 1 has two clauses — the class is empty, **or** it is absent from
    /// the component's declared capabilities — and both run before anything
    /// else and before the prompter exists as a possibility, so a refusal
    /// depends on the manifest and on nothing else.
    ///
    /// A class the component never declared has no ceiling in
    /// `semantic_ceilings` at all: that deny is on the **map miss**, not on a
    /// fallback `resolve(class, None, ..)`. Resolving a ceiling for it would
    /// reach the same verdict and lose the reason, which §7.2 requires the audit
    /// to carry. The empty class gets its own check because the map miss does
    /// not reliably cover it — see the comment on that check.
    ///
    /// Steps 2 to 4 are the compiled ceiling's own `classify_explained`: deny
    /// constraints first, then the declaration, then the grant mode. Consent
    /// adds nothing to that order — it is the same intersection every physical
    /// class is decided by, which is the whole point of routing semantic
    /// classes through the ordinary policy surface.
    pub(crate) async fn decide(
        &self,
        class: &str,
        key: &str,
        summary: &str,
        args: &serde_json::Value,
    ) -> Decision {
        use crate::audit::{CapDecisionRecord, Decision4, emit_cap_decision};

        // §4 step 1, first clause: an empty class. Checked rather than left to
        // the map lookup below, which would catch it only for as long as `""`
        // happens to be absent. It need not be: §3.3 forbids declaring a
        // non-concrete class, but nothing enforces §3.3, so a manifest with
        // `[std.capabilities.""]` gets a real ceiling row from
        // `resolve_ceilings` and would then run the ordinary grant path — up
        // to and including asking a human a question that names no class.
        if class.is_empty() {
            emit_cap_decision(&CapDecisionRecord::statik_with_reason(
                class,
                key,
                ACTION,
                Decision4::Deny,
                "deny",
                None,
                Some("empty capability class"),
            ));
            return Decision::Deny;
        }

        let Some(ceiling) = self.semantic_ceilings.get(class) else {
            emit_cap_decision(&CapDecisionRecord::statik_with_reason(
                class,
                key,
                ACTION,
                Decision4::Deny,
                "deny",
                None,
                Some("class not declared in act:component"),
            ));
            return Decision::Deny;
        };

        let op = act_policy::provider::ResourceOp {
            cap_id: class.to_string(),
            key: key.to_string(),
            action: ACTION.to_string(),
            attrs: args.clone(),
        };
        let explained = ceiling.classify_explained(&op);
        let mode = ceiling.effective_mode().to_string();

        match explained.decision {
            act_policy::Decision::Allow => {
                emit_cap_decision(&CapDecisionRecord::statik(
                    class,
                    key,
                    ACTION,
                    Decision4::Allow,
                    &mode,
                    explained.rule,
                ));
                Decision::Allow
            }
            act_policy::Decision::Deny => {
                emit_cap_decision(&CapDecisionRecord::statik(
                    class,
                    key,
                    ACTION,
                    Decision4::Deny,
                    &mode,
                    explained.rule,
                ));
                Decision::Deny
            }
            // Deliberately silent until the verdict exists; the record is emitted
            // below, mirroring `fs_policy::resolve_ask`.
            act_policy::Decision::Ask => {
                let allowed = self
                    .cache
                    .decide_cached(
                        &*self.prompter,
                        act_policy::consent::ConsentAsk {
                            cap_id: class.to_string(),
                            key: key.to_string(),
                            summary: crate::consent::prompt_line(
                                Some(&self.component),
                                class,
                                key,
                                summary,
                            ),
                        },
                    )
                    .await;
                emit_cap_decision(&CapDecisionRecord::answered(class, key, allowed));
                if allowed {
                    Decision::Allow
                } else {
                    Decision::Deny
                }
            }
        }
    }

    #[cfg(test)]
    fn for_test(
        semantic_ceilings: BTreeMap<String, Arc<dyn CompiledCeiling>>,
        prompter: Arc<dyn act_policy::consent::ConsentPrompter>,
    ) -> Self {
        Self {
            semantic_ceilings: Arc::new(semantic_ceilings),
            prompter,
            cache: Arc::new(act_policy::consent::DecisionCache::new()),
            component: "./test.wasm".to_string(),
        }
    }
}

/// Read the request's `args` as policy dimensions.
///
/// Anything that is not a CBOR map carries no dimensions rather than being an
/// error (ACT-CONSENT.md §2.2): `key` still matches, and the guest learns
/// nothing from a malformed blob that it would not have learned from an empty
/// one. Undecodable bytes take the same path — refusing here would turn a
/// component's encoding bug into a distinguishable outcome, which §8.4
/// forbids.
fn args_to_attrs(args: &[u8]) -> serde_json::Value {
    match act_types::cbor::cbor_to_json(args) {
        Ok(v @ serde_json::Value::Object(_)) => v,
        _ => serde_json::Value::Null,
    }
}

// ── WIT bridge ─────────────────────────────────────────────────────────────

/// Both interfaces get a `Host` impl on `&mut HostState`, and on nothing
/// else, for the same reason `act:credentials` does: `skip_mut_forwarding_impls`
/// suppresses bindgen's blanket `&mut T` forwarding impls, and `add_to_linker`
/// requires `for<'a> D::Data<'a>: Host` — which is `&'a mut HostState` under
/// `HasSelf<HostState>`, and that is the whole of the requirement.
impl consent_authority::Host for &mut HostState {}
impl types::Host for &mut HostState {}

/// Register both `act:consent` instances in the linker.
///
/// Both, not one: `consent-authority` uses types from `types`, so the
/// elaborated world imports both instances, and a guest importing
/// `act:consent/consent-authority` fails instantiation on an unregistered
/// `act:consent/types@0.1.0`. The interface carries no functions, but the
/// instance must still exist.
pub(crate) fn add_to_linker(linker: &mut Linker<HostState>) -> anyhow::Result<()> {
    types::add_to_linker::<HostState, HasSelf<HostState>>(linker, |s| s)
        .map_err(|e| anyhow::anyhow!("failed to add act:consent/types to linker: {e}"))?;
    consent_authority::add_to_linker::<HostState, HasSelf<HostState>>(linker, |s| s).map_err(
        |e| anyhow::anyhow!("failed to add act:consent/consent-authority to linker: {e}"),
    )?;
    Ok(())
}

impl consent_authority::HostWithStore<HostState> for HasSelf<HostState> {
    /// `meta` is accepted and not read. Its job in ACT-CONSENT.md §7.1 is to
    /// anchor the decision to a session, and the record this emits is already
    /// anchored: `emit_cap_decision` writes an event inside the in-flight
    /// `act.tool_call` span, which carries `act.session.id`. It never selects
    /// policy — that is keyed on the class and the key alone — so reading it
    /// here could only widen what a guest-supplied value can influence.
    async fn request(
        accessor: &wasmtime::component::Accessor<HostState, Self>,
        req: consent_authority::ConsentRequest,
        _meta: consent_authority::Metadata,
    ) -> Decision {
        let gate = ConsentGate::from_accessor(accessor);
        let attrs = args_to_attrs(&req.args);
        gate.decide(&req.class, &req.key, &req.summary, &attrs)
            .await
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use act_policy::consent::{ConsentAsk, ConsentPrompter};
    use act_policy::grant::PolicyMode;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A prompter that must never run. Its `decide` panics, and that panic is
    /// the assertion: a test using it asserts the operator was not consulted.
    struct PanickingPrompter;

    #[async_trait::async_trait]
    impl ConsentPrompter for PanickingPrompter {
        async fn decide(&self, ask: &ConsentAsk) -> bool {
            panic!("the operator must not be consulted, but was asked: {ask:?}");
        }
    }

    struct CountingPrompter {
        allow: bool,
        calls: AtomicUsize,
    }

    impl CountingPrompter {
        fn allowing() -> Self {
            Self {
                allow: true,
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl ConsentPrompter for CountingPrompter {
        async fn decide(&self, _ask: &ConsentAsk) -> bool {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.allow
        }
    }

    /// One declared semantic class under a bare grant of `mode`.
    async fn ceilings_declaring(
        class: &str,
        declared: &[serde_json::Value],
        mode: PolicyMode,
    ) -> BTreeMap<String, Arc<dyn act_policy::provider::CompiledCeiling>> {
        ceilings_granted(
            class,
            declared,
            act_policy::grant::CapabilityGrant {
                mode,
                allow: Vec::new(),
                deny: Vec::new(),
            },
        )
        .await
    }

    /// One declared semantic class, resolved through the real provider
    /// registry against `grant` — the same call `create_store` makes, so
    /// these tests hold the ceiling the host would actually build rather
    /// than a stand-in.
    ///
    /// The `ALWAYS_RESOLVED` filter below deliberately mirrors `create_store`,
    /// which is the copy that actually enforces "a physically-enforced class
    /// is not reachable through consent". This one only reproduces the shape
    /// of the map the gate is handed.
    async fn ceilings_granted(
        class: &str,
        declared: &[serde_json::Value],
        grant: act_policy::grant::CapabilityGrant,
    ) -> BTreeMap<String, Arc<dyn act_policy::provider::CompiledCeiling>> {
        use act_policy::grant::GrantPolicy;

        let policy = GrantPolicy {
            default: grant.mode,
            entries: BTreeMap::from([(class.to_string(), grant)]),
        };
        let declared = BTreeMap::from([(class.to_string(), declared.to_vec())]);
        let all = act_policy::ceilings::resolve_ceilings(
            &act_policy::provider::ProviderRegistry::with_builtins(),
            &declared,
            &policy,
        )
        .await
        .expect("resolve");
        all.into_iter()
            .filter(|(id, _)| !act_policy::ceilings::ALWAYS_RESOLVED.contains(&id.as_str()))
            .collect()
    }

    #[tokio::test]
    async fn an_undeclared_class_denies_without_reaching_the_prompter() {
        // ACT-CONSENT.md §4 step 1: the refusal must not depend on anything but
        // the manifest, and the operator must not be consulted. A prompter that
        // panics proves it was never called.
        let gate = ConsentGate::for_test(BTreeMap::new(), Arc::new(PanickingPrompter));
        let decision = gate
            .decide(
                "db:drop",
                "analytics",
                "Drop database \"analytics\"",
                &json!({}),
            )
            .await;
        assert_eq!(decision, Decision::Deny);
    }

    #[tokio::test]
    async fn a_declared_class_outside_its_ceiling_denies() {
        let gate = ConsentGate::for_test(
            ceilings_declaring("db:drop", &[json!({"key": "test_*"})], PolicyMode::Open).await,
            Arc::new(PanickingPrompter),
        );
        assert_eq!(
            gate.decide("db:drop", "production", "Drop production", &json!({}))
                .await,
            Decision::Deny
        );
    }

    #[tokio::test]
    async fn ask_reaches_the_prompter_once_per_key_and_is_remembered() {
        let prompter = Arc::new(CountingPrompter::allowing());
        let gate = ConsentGate::for_test(
            ceilings_declaring("db:drop", &[], PolicyMode::Ask).await,
            prompter.clone(),
        );
        assert_eq!(
            gate.decide("db:drop", "a", "s", &json!({})).await,
            Decision::Allow
        );
        assert_eq!(
            gate.decide("db:drop", "a", "s", &json!({})).await,
            Decision::Allow
        );
        assert_eq!(
            prompter.calls(),
            1,
            "the same (class, key) must not re-prompt"
        );
        assert_eq!(
            gate.decide("db:drop", "b", "s", &json!({})).await,
            Decision::Allow
        );
        assert_eq!(
            prompter.calls(),
            2,
            "a different key is a different question"
        );
    }

    #[tokio::test]
    async fn a_physically_enforced_class_is_not_reachable_through_consent() {
        // wasi:http is declared here and still refused: it is enforced on the
        // boundary, and consent must not become a second door that can answer
        // "allow" for it.
        //
        // Note what actually holds this in production: `create_store`'s own
        // `ALWAYS_RESOLVED` filter, which `ceilings_declaring` deliberately
        // mirrors so these tests see the map the host would build. Deleting
        // the filter in `store.rs` would not turn this test red — the e2e
        // tests are the layer that can see that. What this pins is that the
        // gate adds no bypass of its own on top of the filtered map.
        let gate = ConsentGate::for_test(
            ceilings_declaring("wasi:http", &[], PolicyMode::Open).await,
            Arc::new(PanickingPrompter),
        );
        assert_eq!(
            gate.decide("wasi:http", "api.example.com", "s", &json!({}))
                .await,
            Decision::Deny
        );
    }

    #[tokio::test]
    async fn an_empty_class_denies_even_when_the_manifest_declares_it() {
        // ACT-CONSENT.md §4 step 1 has two clauses: absent from the declared
        // capabilities, *or empty*. The map miss covers the first. This is the
        // second, and it needs a check of its own: §3.3 forbids declaring such
        // a class, but nothing enforces §3.3 -- `act-build validate` checks
        // only `name` and `version` -- so a manifest carrying
        // `[std.capabilities.""]` reaches `resolve_ceilings`, which hands the
        // empty key a real ceiling row like any other.
        //
        // The ceilings below therefore *declare* `""`. Under a map-miss-only
        // implementation the `ask` case would put the request to a human as
        // `./test.wasm requests : analytics` -- a question naming no class at
        // all -- and the `open` case would allow it outright.
        for mode in [PolicyMode::Ask, PolicyMode::Open] {
            let ceilings = ceilings_declaring("", &[], mode).await;
            assert!(
                ceilings.contains_key(""),
                "the fixture must declare the empty class, or this test is \
                 just the map-miss case again"
            );
            let gate = ConsentGate::for_test(ceilings, Arc::new(PanickingPrompter));
            assert_eq!(
                gate.decide("", "analytics", "s", &json!({})).await,
                Decision::Deny,
                "an empty class must be refused under {mode:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_deny_constraint_beats_an_otherwise_open_grant() {
        // §4 step 2: a deny constraint in the effective grant wins, and it
        // wins before the mode is reached -- so `open` does not rescue a key
        // the operator named in `deny`.
        let ceilings = ceilings_granted(
            "db:drop",
            &[],
            act_policy::grant::CapabilityGrant {
                mode: PolicyMode::Open,
                allow: Vec::new(),
                deny: vec![json!({"key": "production"})],
            },
        )
        .await;
        let gate = ConsentGate::for_test(ceilings, Arc::new(PanickingPrompter));
        assert_eq!(
            gate.decide("db:drop", "production", "s", &json!({})).await,
            Decision::Deny
        );
        assert_eq!(
            gate.decide("db:drop", "analytics", "s", &json!({})).await,
            Decision::Allow,
            "the deny constraint must bound the key it names and nothing else"
        );
    }

    #[tokio::test]
    async fn a_deny_mode_grant_refuses_a_declared_class_without_asking() {
        // §4 step 4, first bullet: mode `deny` refuses, and refuses without
        // consulting anyone.
        let gate = ConsentGate::for_test(
            ceilings_declaring("db:drop", &[], PolicyMode::Deny).await,
            Arc::new(PanickingPrompter),
        );
        assert_eq!(
            gate.decide("db:drop", "analytics", "s", &json!({})).await,
            Decision::Deny
        );
    }

    #[tokio::test]
    async fn an_allowlist_grant_bounds_the_key_without_asking() {
        // §4 step 4: allowlist allows a matching request and denies the rest,
        // and neither outcome consults a human.
        let ceilings = ceilings_granted(
            "db:drop",
            &[],
            act_policy::grant::CapabilityGrant {
                mode: PolicyMode::Allowlist,
                allow: vec![json!({"key": "test_*"})],
                deny: Vec::new(),
            },
        )
        .await;
        let gate = ConsentGate::for_test(ceilings, Arc::new(PanickingPrompter));
        assert_eq!(
            gate.decide("db:drop", "test_scratch", "s", &json!({}))
                .await,
            Decision::Allow
        );
        assert_eq!(
            gate.decide("db:drop", "production", "s", &json!({})).await,
            Decision::Deny
        );
    }

    #[tokio::test]
    async fn an_ask_grant_carrying_an_allowlist_refuses_outside_it_rather_than_prompting() {
        // §4 step 4, last sentence: a single approval must not be able to
        // authorize what the operator's own allowlist excluded, so a request
        // outside it is refused rather than put to a human.
        let ceilings = ceilings_granted(
            "db:drop",
            &[],
            act_policy::grant::CapabilityGrant {
                mode: PolicyMode::Ask,
                allow: vec![json!({"key": "test_*"})],
                deny: Vec::new(),
            },
        )
        .await;
        let gate = ConsentGate::for_test(ceilings, Arc::new(PanickingPrompter));
        assert_eq!(
            gate.decide("db:drop", "production", "s", &json!({})).await,
            Decision::Deny
        );
    }

    #[tokio::test]
    async fn a_key_hidden_in_args_cannot_shadow_the_one_that_was_shown() {
        // §8.1: there is exactly one key, and it is the one a human was shown
        // and the audit recorded. The gate must build `ResourceOp::key` from
        // the request and `attrs` from `args` -- swapped, a component would
        // pass an in-ceiling key in `args` and act on a different subject.
        let gate = ConsentGate::for_test(
            ceilings_declaring("db:drop", &[json!({"key": "test_*"})], PolicyMode::Open).await,
            Arc::new(PanickingPrompter),
        );
        assert_eq!(
            gate.decide(
                "db:drop",
                "production",
                "s",
                &json!({"key": "test_scratch"})
            )
            .await,
            Decision::Deny
        );
    }

    #[test]
    fn args_that_are_not_a_cbor_map_carry_no_dimensions() {
        // §2.2: not an error -- `key` still matches. A component whose args
        // encoding is wrong must not get a distinguishable outcome (§8.4).
        let mut text = Vec::new();
        ciborium::into_writer(&"not a map", &mut text).unwrap();
        assert_eq!(args_to_attrs(&text), serde_json::Value::Null);
        assert_eq!(args_to_attrs(&[]), serde_json::Value::Null);
        assert_eq!(args_to_attrs(&[0xff, 0xff, 0xff]), serde_json::Value::Null);

        let mut map = Vec::new();
        ciborium::into_writer(&json!({"table": "events"}), &mut map).unwrap();
        assert_eq!(args_to_attrs(&map), json!({"table": "events"}));
    }

    #[tokio::test]
    async fn a_declared_dimension_outside_key_is_matched_from_args() {
        // §3.2: `key` resolves from the request, every other dimension from
        // `args`. Without this the declared ceiling could only ever narrow on
        // one axis.
        let gate = ConsentGate::for_test(
            ceilings_declaring("db:drop", &[json!({"table": "events"})], PolicyMode::Open).await,
            Arc::new(PanickingPrompter),
        );
        assert_eq!(
            gate.decide("db:drop", "analytics", "s", &json!({"table": "events"}))
                .await,
            Decision::Allow
        );
        assert_eq!(
            gate.decide("db:drop", "analytics", "s", &json!({"table": "users"}))
                .await,
            Decision::Deny
        );
    }

    #[tokio::test]
    async fn no_channel_degrades_to_deny() {
        let gate = ConsentGate::for_test(
            ceilings_declaring("db:drop", &[], PolicyMode::Ask).await,
            Arc::new(act_policy::consent::DenyPrompter),
        );
        assert_eq!(
            gate.decide("db:drop", "a", "s", &json!({})).await,
            Decision::Deny
        );
    }
}
