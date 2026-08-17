//! Host side of `act:credentials/store`.
//!
//! Session handling lives here rather than in the transports so both MCP and
//! HTTP get identical behaviour; `runtime/sessions.rs` is the single point both
//! already pass through.
//!
//! ## Two layers, on purpose
//!
//! [`CredentialHost`] is synchronous, owns no wasmtime types, and is the whole
//! of the credential logic: compartment projection, session liveness, the audit
//! record. It is unit-testable against a real store with no engine, no linker
//! and no guest.
//!
//! Around it sits the generated-trait bridge. `act:credentials/store`'s two
//! functions are `async func` in WIT, so bindgen lowers them through
//! `func_wrap_concurrent`: the generated `HostWithStore<T>` methods are
//! **associated functions taking an [`Accessor`]**, not methods on `&self`, and
//! the impl target is the `HasData` marker rather than `HostState`. The bridge
//! reaches host state through the accessor, resolves the capability decision
//! (which may await a human), and then calls the synchronous host. Nothing
//! about the credential logic itself has to be written twice, or written async.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use act_credentials::record::{Secret, SecretInfo};
use act_credentials::store::CredentialStore;
use act_policy::providers::credentials::CAP_CREDENTIALS;
use wasmtime::component::{HasSelf, Linker};

use super::HostState;
use super::bindings::act::credentials::{store, types};

/// Why the host refused, in the terms `CredentialHost` can decide in. Maps
/// onto the WIT `secret-error` variants and nothing else — see [`to_wit`].
#[derive(Debug, PartialEq, Eq)]
pub enum HostError {
    NotFound,
    Denied,
    InvalidSession,
    Unavailable(String),
}

impl HostError {
    fn to_wit(&self) -> store::SecretError {
        match self {
            HostError::NotFound => store::SecretError::NotFound,
            HostError::Denied => store::SecretError::Denied,
            HostError::InvalidSession => store::SecretError::InvalidSession,
            HostError::Unavailable(d) => store::SecretError::Unavailable(d.clone()),
        }
    }
}

pub struct CredentialHost {
    store: Arc<dyn CredentialStore>,
    component: String,
    live_sessions: Mutex<HashSet<String>>,
}

impl CredentialHost {
    pub fn new(store: Arc<dyn CredentialStore>, component: String) -> Self {
        Self {
            store,
            component,
            live_sessions: Mutex::new(HashSet::new()),
        }
    }

    /// The component reference this host serves, as the operator wrote it.
    /// It is the profile namespace — the boundary the whole design rests on
    /// (spec §2.1) — and it is what a consent prompt must name (spec §5.5).
    pub fn component(&self) -> &str {
        &self.component
    }

    pub fn note_session_opened(&self, id: &str) {
        self.live_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.to_string());
    }

    pub fn note_session_closed(&self, id: &str) {
        self.live_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
    }

    fn live(&self, id: &str) -> bool {
        self.live_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(id)
    }

    /// A hit returns the projection only. The host-only compartment — refresh
    /// tokens, issuer binding — never crosses the boundary (spec D4).
    ///
    /// The caller must have resolved the `act:credentials` capability decision
    /// *before* getting here: a denial must not depend on whether the key
    /// exists, or `denied` becomes a probing channel (spec §3.4).
    pub fn get_secret(&self, session: &str, key: &str) -> Result<Secret, HostError> {
        if !self.live(session) {
            return Err(HostError::InvalidSession);
        }
        match self.store.get(&self.component, key) {
            Ok(Some(rec)) => {
                // The one record that says material left the host. Emitted
                // on the audit target, which `RUST_LOG` cannot silence.
                crate::audit::emit_credential_issue(&crate::audit::CredentialIssueRecord {
                    component_ref: self.component.clone(),
                    session_id: session.to_string(),
                    key: key.to_string(),
                    kind: rec.kind.clone(),
                });
                Ok(rec.project())
            }
            Ok(None) => Err(HostError::NotFound),
            Err(e) => Err(HostError::Unavailable(e.to_string())),
        }
    }

    /// Metadata only — no value can reach this path, because `SecretInfo` has
    /// no field that could hold one. Deliberately unaudited (spec §9): a
    /// listing hands over nothing, and recording it would bury the issue
    /// records that matter.
    pub fn list_secrets(&self, session: Option<&str>) -> Result<Vec<SecretInfo>, HostError> {
        if let Some(id) = session
            && !self.live(id)
        {
            return Err(HostError::InvalidSession);
        }
        self.store
            .list(Some(&self.component))
            .map_err(|e| HostError::Unavailable(e.to_string()))
    }
}

/// Where the file backend lives when the operator has not named one.
///
/// `act secret set` will grow an explicit `--credentials-backend`; until then
/// this is the single path the writer and the reader have to agree on, so it
/// lives next to the reader rather than in either caller.
pub fn default_store_root() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("act").join("credentials"))
}

// ── WIT bridge ─────────────────────────────────────────────────────────────

/// `Host` is implemented for `&mut HostState` on *both* interfaces:
/// `skip_mut_forwarding_impls` suppresses bindgen's blanket `&mut T`
/// forwarding impls, while both `store::add_to_linker` and
/// `types::add_to_linker` require `for<'a> D::Data<'a>: Host` — which is
/// `&'a mut HostState` under `HasSelf<HostState>`.
impl store::Host for HostState {}
impl store::Host for &mut HostState {}
impl types::Host for &mut HostState {}

/// Register both `act:credentials` instances in the linker.
///
/// Both, not one: `store` uses types from `types`, so the elaborated world
/// imports both instances, and a guest importing `act:credentials/store`
/// fails instantiation on an unregistered `act:credentials/types@0.1.0`. The
/// interface carries no functions, but the instance must still exist.
pub fn add_to_linker(linker: &mut Linker<HostState>) -> anyhow::Result<()> {
    types::add_to_linker::<HostState, HasSelf<HostState>>(linker, |s| s)
        .map_err(|e| anyhow::anyhow!("failed to add act:credentials/types to linker: {e}"))?;
    store::add_to_linker::<HostState, HasSelf<HostState>>(linker, |s| s)
        .map_err(|e| anyhow::anyhow!("failed to add act:credentials/store to linker: {e}"))?;
    Ok(())
}

/// Everything the gate below needs, cloned out of the store in one
/// `Accessor::with` so nothing borrows host state across an await.
struct GateContext {
    host: Option<Arc<CredentialHost>>,
    ceiling: Arc<dyn act_policy::provider::CompiledCeiling>,
    prompter: Arc<dyn act_policy::consent::ConsentPrompter>,
    cache: Arc<act_policy::consent::DecisionCache>,
}

impl GateContext {
    fn from(accessor: &wasmtime::component::Accessor<HostState, HasSelf<HostState>>) -> Self {
        accessor.with(|mut access| {
            let state: &mut HostState = access.get();
            Self {
                host: state.credentials.clone(),
                ceiling: state.credentials_ceiling.clone(),
                prompter: state.consent_prompter.clone(),
                cache: state.consent_cache.clone(),
            }
        })
    }

    /// Resolve the `act:credentials` decision for one operation, exactly as
    /// the fs / http / sockets gates do: classify against the compiled
    /// ceiling, emit the typed decision record, and let `ask` reach the
    /// operator through the shared prompter and per-run cache.
    ///
    /// Runs *before* the store is touched, so a refusal never depends on
    /// whether the key exists (spec §3.4).
    async fn allows(&self, key: &str, action: &str, hint: Option<&str>) -> bool {
        let component = self.host.as_ref().map(|h| h.component().to_string());
        use crate::audit::{CapDecisionRecord, Decision4, emit_cap_decision};

        let op = act_policy::provider::ResourceOp {
            cap_id: CAP_CREDENTIALS.to_string(),
            key: key.to_string(),
            action: action.to_string(),
            attrs: serde_json::Value::Null,
        };
        let explained = self.ceiling.classify_explained(&op);
        let mode = self.ceiling.effective_mode().to_string();
        match explained.decision {
            act_policy::Decision::Allow => {
                emit_cap_decision(&CapDecisionRecord::statik(
                    CAP_CREDENTIALS,
                    key,
                    action,
                    Decision4::Allow,
                    &mode,
                    explained.rule,
                ));
                true
            }
            act_policy::Decision::Deny => {
                emit_cap_decision(&CapDecisionRecord::statik(
                    CAP_CREDENTIALS,
                    key,
                    action,
                    Decision4::Deny,
                    &mode,
                    explained.rule,
                ));
                false
            }
            // Deliberately silent until the verdict exists; the record is
            // emitted below, mirroring `fs_policy::resolve_ask`.
            act_policy::Decision::Ask => {
                let allowed = self
                    .cache
                    .decide_cached(
                        &*self.prompter,
                        act_policy::consent::ConsentAsk {
                            cap_id: CAP_CREDENTIALS.to_string(),
                            key: key.to_string(),
                            summary: consent_summary(component.as_deref(), action, key, hint),
                        },
                    )
                    .await;
                emit_cap_decision(&CapDecisionRecord::answered(CAP_CREDENTIALS, key, allowed));
                allowed
            }
        }
    }
}

/// Longest guest-authored `hint` shown on a consent prompt.
const HINT_LIMIT: usize = 120;

/// Build the one line a human is asked to approve.
///
/// Everything but the hint is host-derived (spec §5.5: "a descriptor signals
/// that something is needed; it never instructs the host where to go, what to
/// run, or what to say"). `component` leads, because §5.5 requires the
/// component reference be displayed prominently: the whole question is
/// *which* artifact is asking, and a prompt that only named the key would let
/// any component borrow another's reputation. It is the reference the
/// operator themselves passed on the command line, threaded through
/// `CredentialHost::component`, never anything the guest chose.
///
/// The hint is the component's own words, so it is attributed, stripped of
/// control and bidi-override characters, and truncated. The prompters escape
/// the finished line as well (`runtime::consent::consent_line`) — this is the
/// inner of two layers, and it is the one that keeps the guest's text
/// *readable* rather than exploded into `\u{...}` escapes.
///
/// The component **digest** is still missing, and cannot be added from here:
/// `ConsentAsk` carries no digest for any capability class.
fn consent_summary(component: Option<&str>, action: &str, key: &str, hint: Option<&str>) -> String {
    let base = match component {
        Some(c) => format!("{c} requests credential {action}: {key}"),
        None => format!("credential {action}: {key}"),
    };
    match hint.map(sanitize_hint) {
        Some(h) if !h.is_empty() => format!("{base} — component says: \"{h}\""),
        _ => base,
    }
}

/// Blank out anything that could forge or disguise prompt text, then truncate.
///
/// Uses the audit trail's own `needs_escape` rather than `char::is_control`:
/// the latter is Unicode category `Cc` only and misses the bidi controls
/// (U+202A-202E, U+2066-2069) and line separators (U+2028/2029). A
/// right-to-left override makes a terminal *display* a different string than
/// the one supplied — which is worth strictly more on a prompt a human is
/// about to answer than on an audit line read afterwards, so the more
/// sensitive surface must not carry the weaker predicate.
fn sanitize_hint(hint: &str) -> String {
    let cleaned: String = hint
        .chars()
        .map(|c| {
            if crate::audit::render::needs_escape(c) {
                ' '
            } else {
                c
            }
        })
        .collect();
    let cleaned = cleaned.trim();
    match cleaned.char_indices().nth(HINT_LIMIT) {
        Some((idx, _)) => format!("{}…", &cleaned[..idx]),
        None => cleaned.to_string(),
    }
}

/// Encode a stored field for the guest. WIT types the value as `cbor`
/// (`list<u8>`), so every value crosses as a dCBOR text string — the same
/// encoding tool arguments and metadata already use.
fn to_wit_secret(secret: Secret) -> store::Secret {
    store::Secret {
        kind: secret.kind,
        fields: secret
            .fields
            .into_iter()
            .map(|(name, value)| (name, act_types::cbor::to_cbor(&value.expose().to_string())))
            .collect(),
    }
}

fn to_wit_info(info: SecretInfo) -> store::SecretInfo {
    store::SecretInfo {
        key: info.key,
        kind: info.kind,
        description: info.description,
        // WIT types expiry as `u64`; the record allows any `i64`. A negative
        // timestamp is not representable, so it is reported as "no expiry"
        // rather than wrapping into a date centuries away.
        expires_at: info.expires_at.and_then(|e| u64::try_from(e).ok()),
    }
}

/// A run with no credential store configured at all. Distinct from a denial:
/// nothing was refused, there was simply nowhere to look.
const NO_STORE: &str = "no credential store is configured for this run";

/// Serve one `list-secrets`, gate included.
///
/// Split out of the trait impl so the gate is reachable from a test: the impl
/// can only be entered with a live `Accessor`, which needs an engine, a linker
/// and a guest, while a `GateContext` is four `Arc`s anyone can build. The
/// trait method below is then nothing but "get the context, call this".
async fn serve_list(
    ctx: &GateContext,
    session: Option<&str>,
) -> Result<Vec<store::SecretInfo>, store::SecretError> {
    // The listing is scoped to the whole profile, not to one key, so the
    // gate is asked about the profile — `*` is the only honest key here.
    if !ctx.allows("*", "list", None).await {
        return Err(HostError::Denied.to_wit());
    }
    let Some(host) = &ctx.host else {
        return Err(store::SecretError::Unavailable(NO_STORE.into()));
    };
    host.list_secrets(session)
        .map(|infos| infos.into_iter().map(to_wit_info).collect())
        .map_err(|e| e.to_wit())
}

/// Serve one `get-secret`, gate included. See [`serve_list`] for why it is a
/// free function.
///
/// The order is load-bearing: the gate resolves *before* the store is touched,
/// so a refusal cannot depend on whether the key exists (spec §3.4 — otherwise
/// `denied` becomes a probing channel).
async fn serve_get(
    ctx: &GateContext,
    session: &str,
    want: &store::SecretRequest,
) -> Result<store::Secret, store::SecretError> {
    if !ctx.allows(&want.key, "get", want.hint.as_deref()).await {
        return Err(HostError::Denied.to_wit());
    }
    let Some(host) = &ctx.host else {
        return Err(store::SecretError::Unavailable(NO_STORE.into()));
    };
    // `want.kind` is a provisioning hint, not a retrieval filter (spec
    // §3.4): the component inspects `secret.kind` and decides for itself.
    host.get_secret(session, &want.key)
        .map(to_wit_secret)
        .map_err(|e| e.to_wit())
}

impl store::HostWithStore<HostState> for HasSelf<HostState> {
    async fn list_secrets(
        accessor: &wasmtime::component::Accessor<HostState, Self>,
        session: Option<String>,
    ) -> Result<Vec<store::SecretInfo>, store::SecretError> {
        let ctx = GateContext::from(accessor);
        serve_list(&ctx, session.as_deref()).await
    }

    async fn get_secret(
        accessor: &wasmtime::component::Accessor<HostState, Self>,
        session: String,
        want: store::SecretRequest,
    ) -> Result<store::Secret, store::SecretError> {
        let ctx = GateContext::from(accessor);
        serve_get(&ctx, &session, &want).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use act_credentials::backend::file::FileStore;
    use act_credentials::record::{SecretRecord, SecretValue};
    use act_credentials::store::CredentialStore;
    use std::collections::BTreeMap;

    fn host(dir: &std::path::Path) -> CredentialHost {
        let store = FileStore::new(dir.to_path_buf());
        let mut fields = BTreeMap::new();
        fields.insert("std:value".to_string(), SecretValue::new("tok"));
        let mut host_only = BTreeMap::new();
        host_only.insert("std:refresh-token".to_string(), SecretValue::new("rt"));
        store
            .put(
                "comp",
                "notion",
                &SecretRecord {
                    kind: "std:opaque".into(),
                    fields,
                    host_only,
                    description: None,
                    expires_at: None,
                },
            )
            .unwrap();
        CredentialHost::new(Arc::new(store), "comp".to_string())
    }

    // ── the capability gate ───────────────────────────────────────────────
    //
    // `GateContext` is four `Arc`s and `serve_get` / `serve_list` are free
    // functions, so the decision path is reachable here without an engine, a
    // linker or a guest. These are the tests that hold the gate itself; the
    // ones above hold `CredentialHost` underneath it.

    use act_credentials::store::StoreError;
    use act_policy::consent::{ConsentAsk, ConsentPrompter, DecisionCache, DenyPrompter};
    use act_policy::grant::{CapabilityGrant, PolicyMode};
    use act_policy::provider::CapabilityProvider;
    use act_policy::providers::credentials::CredentialsProvider;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Wraps a real store and counts reads, so a test can assert that a
    /// refusal happened *before* the lookup rather than after it.
    struct CountingStore {
        inner: FileStore,
        gets: AtomicUsize,
        lists: AtomicUsize,
    }

    impl CredentialStore for CountingStore {
        fn get(&self, component: &str, key: &str) -> Result<Option<SecretRecord>, StoreError> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            self.inner.get(component, key)
        }
        fn put(&self, component: &str, key: &str, rec: &SecretRecord) -> Result<(), StoreError> {
            self.inner.put(component, key, rec)
        }
        fn erase(&self, component: &str, key: &str) -> Result<(), StoreError> {
            self.inner.erase(component, key)
        }
        fn list(&self, component: Option<&str>) -> Result<Vec<SecretInfo>, StoreError> {
            self.lists.fetch_add(1, Ordering::SeqCst);
            self.inner.list(component)
        }
        fn writable(&self) -> bool {
            self.inner.writable()
        }
    }

    /// Says yes to everything and counts how often it was asked, so a test
    /// can tell "cached" from "prompted twice".
    struct AllowPrompter(AtomicUsize);

    #[async_trait::async_trait]
    impl ConsentPrompter for AllowPrompter {
        async fn decide(&self, _ask: &ConsentAsk) -> bool {
            self.0.fetch_add(1, Ordering::SeqCst);
            true
        }
    }

    async fn ceiling(
        declared: bool,
        mode: PolicyMode,
    ) -> Arc<dyn act_policy::provider::CompiledCeiling> {
        // The sentinel `declared` slice is what `runtime::declared_constraints`
        // synthesizes for a manifest that carries the class; an empty slice is
        // what it returns for one that does not.
        let declared: Vec<serde_json::Value> = if declared {
            vec![serde_json::json!({})]
        } else {
            Vec::new()
        };
        Arc::from(
            CredentialsProvider
                .resolve(
                    CAP_CREDENTIALS,
                    &declared,
                    &CapabilityGrant {
                        mode,
                        allow: vec![],
                        deny: vec![],
                    },
                )
                .await
                .expect("resolve"),
        )
    }

    /// A gate context over a store that has the `notion` key, so any failure
    /// below is the gate's doing and not a missing record.
    fn gate_ctx(
        dir: &std::path::Path,
        ceiling: Arc<dyn act_policy::provider::CompiledCeiling>,
        prompter: Arc<dyn ConsentPrompter>,
    ) -> (GateContext, Arc<CountingStore>) {
        let seeded = host(dir); // writes `comp` / `notion` through a FileStore
        drop(seeded);
        let store = Arc::new(CountingStore {
            inner: FileStore::new(dir.to_path_buf()),
            gets: AtomicUsize::new(0),
            lists: AtomicUsize::new(0),
        });
        let h = Arc::new(CredentialHost::new(store.clone(), "comp".to_string()));
        h.note_session_opened("s1");
        (
            GateContext {
                host: Some(h),
                ceiling,
                prompter,
                cache: Arc::new(DecisionCache::new()),
            },
            store,
        )
    }

    fn want(key: &str) -> store::SecretRequest {
        store::SecretRequest {
            key: key.to_string(),
            kind: None,
            resource: None,
            scopes: vec![],
            hint: None,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_undeclared_class_is_refused_no_matter_what_was_granted() {
        // The whole premise of `act:credentials`: a grant cannot widen a
        // class the artifact never declared.
        for mode in [PolicyMode::Open, PolicyMode::Allowlist, PolicyMode::Ask] {
            let c = ceiling(false, mode).await;
            let dir = tempfile::tempdir().unwrap();
            let (ctx, store) = gate_ctx(dir.path(), c, Arc::new(DenyPrompter));
            assert!(!ctx.allows("notion", "get", None).await, "mode {mode:?}");
            assert!(
                matches!(
                    serve_get(&ctx, "s1", &want("notion")).await,
                    Err(store::SecretError::Denied)
                ),
                "mode {mode:?}"
            );
            assert_eq!(
                store.gets.load(Ordering::SeqCst),
                0,
                "a refusal must not reach the store — otherwise `denied` timing \
                 leaks whether the key exists (spec §3.4), mode {mode:?}"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_denied_grant_is_refused_even_though_the_class_was_declared() {
        let dir = tempfile::tempdir().unwrap();
        let (ctx, store) = gate_ctx(
            dir.path(),
            ceiling(true, PolicyMode::Deny).await,
            Arc::new(DenyPrompter),
        );
        assert!(!ctx.allows("notion", "get", None).await);
        assert!(matches!(
            serve_get(&ctx, "s1", &want("notion")).await,
            Err(store::SecretError::Denied)
        ));
        assert_eq!(store.gets.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ask_with_no_prompt_channel_degrades_to_deny() {
        // `ask` is the default mode and headless runs get `DenyPrompter`, so
        // this is what an unattended `act call` actually does.
        let dir = tempfile::tempdir().unwrap();
        let (ctx, store) = gate_ctx(
            dir.path(),
            ceiling(true, PolicyMode::Ask).await,
            Arc::new(DenyPrompter),
        );
        assert!(!ctx.allows("notion", "get", None).await);
        assert!(matches!(
            serve_get(&ctx, "s1", &want("notion")).await,
            Err(store::SecretError::Denied)
        ));
        assert_eq!(store.gets.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_approved_ask_serves_the_credential_and_is_not_asked_twice() {
        let dir = tempfile::tempdir().unwrap();
        let prompter = Arc::new(AllowPrompter(AtomicUsize::new(0)));
        let (ctx, store) = gate_ctx(
            dir.path(),
            ceiling(true, PolicyMode::Ask).await,
            prompter.clone(),
        );

        let got = serve_get(&ctx, "s1", &want("notion"))
            .await
            .expect("served");
        assert_eq!(got.kind, "std:opaque");
        assert_eq!(store.gets.load(Ordering::SeqCst), 1);

        // Second request for the same key: the per-run cache answers, so the
        // human is not re-prompted for a decision they already made.
        assert!(serve_get(&ctx, "s1", &want("notion")).await.is_ok());
        assert_eq!(
            prompter.0.load(Ordering::SeqCst),
            1,
            "one prompt per (class, key) per run"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_open_grant_on_a_declared_class_needs_no_prompt_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let prompter = Arc::new(AllowPrompter(AtomicUsize::new(0)));
        let (ctx, _store) = gate_ctx(
            dir.path(),
            ceiling(true, PolicyMode::Open).await,
            prompter.clone(),
        );
        assert!(serve_get(&ctx, "s1", &want("notion")).await.is_ok());
        assert_eq!(prompter.0.load(Ordering::SeqCst), 0, "static allow");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_listing_is_gated_too_and_a_refusal_never_reaches_the_index() {
        let dir = tempfile::tempdir().unwrap();
        let (ctx, store) = gate_ctx(
            dir.path(),
            ceiling(false, PolicyMode::Open).await,
            Arc::new(DenyPrompter),
        );
        assert!(matches!(
            serve_list(&ctx, Some("s1")).await,
            Err(store::SecretError::Denied)
        ));
        assert_eq!(store.lists.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_run_with_no_store_reports_unavailable_rather_than_denied() {
        // Nothing was refused — there was simply nowhere to look. Reporting
        // `denied` would send the operator to fix a grant that is fine.
        let ctx = GateContext {
            host: None,
            ceiling: ceiling(true, PolicyMode::Open).await,
            prompter: Arc::new(DenyPrompter),
            cache: Arc::new(DecisionCache::new()),
        };
        assert!(matches!(
            serve_get(&ctx, "s1", &want("notion")).await,
            Err(store::SecretError::Unavailable(_))
        ));
    }

    #[test]
    fn a_hit_returns_only_the_revealable_compartment() {
        let dir = tempfile::tempdir().unwrap();
        let h = host(dir.path());
        h.note_session_opened("s1");

        let got = h.get_secret("s1", "notion").expect("found");
        assert_eq!(got.kind, "std:opaque");
        let keys: Vec<&String> = got.fields.keys().collect();
        assert_eq!(keys, vec!["std:value"]);
    }

    #[test]
    fn a_miss_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let h = host(dir.path());
        h.note_session_opened("s1");
        assert!(matches!(
            h.get_secret("s1", "absent"),
            Err(HostError::NotFound)
        ));
    }

    #[test]
    fn a_closed_session_stops_being_served() {
        let dir = tempfile::tempdir().unwrap();
        let h = host(dir.path());
        h.note_session_opened("s1");
        h.note_session_closed("s1");
        assert!(matches!(
            h.get_secret("s1", "notion"),
            Err(HostError::InvalidSession)
        ));
    }

    #[test]
    fn an_unknown_session_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let h = host(dir.path());
        assert!(matches!(
            h.get_secret("nope", "notion"),
            Err(HostError::InvalidSession)
        ));
    }

    #[test]
    fn closing_one_session_does_not_close_another() {
        // The bridges keep several sessions open at once (spec §8.2), so a
        // close must be keyed, not a flush.
        let dir = tempfile::tempdir().unwrap();
        let h = host(dir.path());
        h.note_session_opened("s1");
        h.note_session_opened("s2");
        h.note_session_closed("s1");
        assert!(h.get_secret("s2", "notion").is_ok());
        assert!(matches!(
            h.get_secret("s1", "notion"),
            Err(HostError::InvalidSession)
        ));
    }

    #[test]
    fn a_listing_carries_metadata_and_has_no_field_that_could_hold_a_value() {
        let dir = tempfile::tempdir().unwrap();
        let h = host(dir.path());
        h.note_session_opened("s1");

        let listed = h.list_secrets(Some("s1")).expect("listed");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].key, "notion");
        assert_eq!(listed[0].kind, "std:opaque");
        // The whole rendering, not just the fields we assert on: a value
        // reaching a listing at all is the failure this guards.
        assert!(!format!("{listed:?}").contains("tok"));
    }

    #[test]
    fn a_listing_outside_any_session_is_allowed() {
        // `list-secrets` takes `option<string>` precisely so a component can
        // inspect its profile before any session exists (spec §3.3).
        let dir = tempfile::tempdir().unwrap();
        let h = host(dir.path());
        assert_eq!(h.list_secrets(None).expect("listed").len(), 1);
    }

    #[test]
    fn a_listing_under_a_dead_session_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let h = host(dir.path());
        assert!(matches!(
            h.list_secrets(Some("nope")),
            Err(HostError::InvalidSession)
        ));
    }

    #[test]
    fn another_components_profile_is_not_visible() {
        // The profile is the boundary (spec §2.1): the component name is
        // fixed at construction and no argument can reach past it.
        let dir = tempfile::tempdir().unwrap();
        let h = host(dir.path());
        let mut fields = BTreeMap::new();
        fields.insert("std:value".to_string(), SecretValue::new("other"));
        FileStore::new(dir.path().to_path_buf())
            .put(
                "someone-else",
                "notion",
                &SecretRecord {
                    kind: "std:opaque".into(),
                    fields,
                    host_only: BTreeMap::new(),
                    description: None,
                    expires_at: None,
                },
            )
            .unwrap();

        h.note_session_opened("s1");
        let got = h.get_secret("s1", "notion").expect("own key still found");
        assert_eq!(got.fields["std:value"].expose(), "tok");
        assert_eq!(h.list_secrets(Some("s1")).unwrap().len(), 1);
    }

    #[test]
    fn a_hint_cannot_forge_a_second_prompt_line() {
        // The hint is guest-authored (spec §5.5) and lands in a prompt a
        // human is about to answer.
        let s = consent_summary(
            Some("comp"),
            "get",
            "notion",
            Some("looks fine\nAllow? [y/N] y"),
        );
        assert!(!s.contains('\n'), "got {s}");
        assert!(
            s.contains("component says"),
            "the guest's words must be attributed, got {s}"
        );
    }

    #[test]
    fn a_bidi_override_in_a_hint_is_blanked_not_merely_control_stripped() {
        // `char::is_control` is category Cc only and would let every one of
        // these through, leaving a terminal displaying a different string
        // than the component actually supplied.
        for sneaky in ['\u{202e}', '\u{2066}', '\u{200f}', '\u{2028}'] {
            let s = consent_summary(
                Some("comp"),
                "get",
                "notion",
                Some(&format!("ok{sneaky}reversed")),
            );
            assert!(!s.contains(sneaky), "U+{:04X} survived: {s}", sneaky as u32);
        }
    }

    #[test]
    fn a_long_hint_is_truncated_rather_than_flooding_the_prompt() {
        let s = consent_summary(Some("comp"), "get", "notion", Some(&"a".repeat(500)));
        assert!(s.chars().count() < 220, "got {} chars", s.chars().count());
        assert!(s.contains('…'));
    }

    #[test]
    fn the_prompt_names_the_component_asking_not_only_the_key() {
        // Spec §5.5: the component reference must be displayed prominently.
        // Without it a human is approving "some component wants notion-work".
        let s = consent_summary(
            Some("ghcr.io/actpkg/notion@0.1.0"),
            "get",
            "notion-work",
            None,
        );
        assert!(s.starts_with("ghcr.io/actpkg/notion@0.1.0"), "got {s}");
        assert!(s.contains("notion-work"), "got {s}");
    }

    #[test]
    fn no_hint_leaves_the_prompt_host_authored_end_to_end() {
        let s = consent_summary(None, "get", "notion", None);
        assert_eq!(s, "credential get: notion");
    }

    #[test]
    fn a_value_crosses_the_boundary_as_cbor_not_as_a_bare_string() {
        // The guest decodes `secret-fields` with the same dCBOR reader it
        // uses for tool arguments; a raw string would decode to garbage.
        let dir = tempfile::tempdir().unwrap();
        let h = host(dir.path());
        h.note_session_opened("s1");
        let wit = to_wit_secret(h.get_secret("s1", "notion").unwrap());

        assert_eq!(wit.kind, "std:opaque");
        assert_eq!(wit.fields.len(), 1);
        let (name, bytes) = &wit.fields[0];
        assert_eq!(name, "std:value");
        let decoded: String = act_types::cbor::from_cbor(bytes).expect("dCBOR text string");
        assert_eq!(decoded, "tok");
    }

    #[test]
    fn every_host_error_has_a_distinct_wit_variant() {
        // A collapse here would report a missing credential as a policy
        // refusal, sending the user to fix the wrong thing (spec §3.4).
        assert!(matches!(
            HostError::NotFound.to_wit(),
            store::SecretError::NotFound
        ));
        assert!(matches!(
            HostError::Denied.to_wit(),
            store::SecretError::Denied
        ));
        assert!(matches!(
            HostError::InvalidSession.to_wit(),
            store::SecretError::InvalidSession
        ));
        match HostError::Unavailable("disk gone".into()).to_wit() {
            store::SecretError::Unavailable(d) => assert_eq!(d, "disk gone"),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn a_negative_expiry_reads_as_no_expiry_rather_than_a_far_future_date() {
        let info = to_wit_info(SecretInfo {
            key: "k".into(),
            kind: "std:opaque".into(),
            description: None,
            expires_at: Some(-1),
        });
        assert_eq!(info.expires_at, None);

        let ok = to_wit_info(SecretInfo {
            key: "k".into(),
            kind: "std:opaque".into(),
            description: Some("note".into()),
            expires_at: Some(1_800_000_000),
        });
        assert_eq!(ok.expires_at, Some(1_800_000_000));
        assert_eq!(ok.description.as_deref(), Some("note"));
    }
}
