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
//! **associated functions taking a [`wasmtime::component::Accessor`]**, not methods on `&self`, and
//! the impl target is the `HasData` marker rather than `HostState`. The bridge
//! reaches host state through the accessor, resolves the capability decision
//! (which may await a human), and then calls the synchronous host. Nothing
//! about the credential logic itself has to be written twice, or written async.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use act_credentials::backend::BackendChoice;
use act_credentials::record::{Secret, SecretInfo};
use act_credentials::store::CredentialStore;
use act_policy::providers::credentials::CAP_CREDENTIALS;
use wasmtime::component::{HasSelf, Linker};

use super::HostState;
use super::bindings::act::credentials::{store, types};
use crate::consent::{sanitize_hint, truncate_field};

/// Why the host refused, in the terms `CredentialHost` can decide in. Maps
/// onto the WIT `secret-error` variants and nothing else, through this
/// type's private `to_wit`.
#[derive(Debug, PartialEq, Eq)]
pub enum HostError {
    NotFound,
    Denied,
    InvalidSession,
    Unavailable(String),
}

/// What the guest is told when the store could not be read.
///
/// Host-authored and constant on purpose. `StoreError::Encoding` is built from
/// `serde_json`'s message, and serde's `invalid type` text embeds the offending
/// JSON scalar — so forwarding the detail hands stored credential material to
/// the guest, which puts it in a tool result. Externally-materialised store
/// files are a first-class source (design §5.6), and the pipelines that render
/// them emit JSON numbers without being asked, so a numeric PIN or account id
/// is exactly the shape that reaches this path. The detail goes to the host's
/// log at `warn`, where the operator can see it and the agent cannot.
const STORE_UNREADABLE: &str = "the credential store could not be read";

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

/// How a credential too close to expiry is renewed.
///
/// A seam, and deliberately a narrow one. Renewing means speaking OAuth to an
/// authorization server — discovery, a client registration, a token endpoint —
/// and this runtime holds no opinion about protocols: it knows only that a
/// stored value carries an expiry and an issuer, and that something outside can
/// turn those into a fresh value. `act-cli` implements it over
/// `act:credentials`' OAuth flow; an embedder with a different upstream
/// implements it differently, or passes none and gets no renewal.
///
/// Nothing here mentions OAuth for that reason. What crosses is what any
/// renewal must produce.
#[async_trait::async_trait]
pub trait CredentialRefresher: Send + Sync {
    /// Renew one credential. The error is a diagnostic for the host's log — it
    /// reaches no component, and MUST NOT carry credential material.
    async fn refresh(&self, req: RefreshRequest<'_>) -> Result<Refreshed, String>;
}

/// What the runtime knows and a refresher needs.
pub struct RefreshRequest<'a> {
    /// The authorization server the credential was acquired from, as recorded
    /// in the host-only compartment when it was acquired.
    pub issuer: &'a str,
    /// The host-only refresh token. It never leaves the host by any other path.
    pub refresh_token: &'a str,
    /// Unix seconds, read once by the caller so a whole decision shares one
    /// clock reading.
    pub now: u64,
}

/// What a renewal produced.
pub struct Refreshed {
    pub access_token: String,
    pub expires_at: Option<u64>,
    pub scopes: Vec<String>,
    /// `None` means the server rotated nothing and the stored one still works.
    /// `Some` always replaces: a rotating server invalidates the old, and
    /// keeping it is how a credential dies at the *next* refresh instead of
    /// this one.
    pub refresh_token: Option<String>,
}

/// Unix seconds, or 0 if the clock is before the epoch — which makes every
/// credential look far from expiry rather than expired, so a broken clock
/// cannot stampede every session into refreshing at once.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The fields of this record that are too close to expiry to serve.
///
/// Only ever the `std:oauth2`-shaped ones: `needs_refresh` reads
/// `std:expires-at` out of an object, and a `std:string` field has no object to
/// read it from. That is the whole of why refresh cannot touch a sibling.
fn due_fields(rec: &act_credentials::record::SecretRecord, now: u64) -> Vec<String> {
    rec.fields
        .iter()
        .filter(|(_, v)| act_credentials::expiry::needs_refresh(v.expose(), now))
        .map(|(k, _)| k.clone())
        .collect()
}

/// Write a renewal into a record: one field's value, and its host-only half.
///
/// Every sibling is untouched because none is named here. The design calls this
/// the structural payoff of typing fields rather than credentials — "refresh
/// dropped the tenant id" is a bug this shape cannot express.
fn apply_refresh(rec: &mut act_credentials::record::SecretRecord, field: &str, r: &Refreshed) {
    let mut value = serde_json::Map::new();
    value.insert(
        "std:access-token".into(),
        serde_json::Value::String(r.access_token.clone()),
    );
    if let Some(exp) = r.expires_at {
        value.insert("std:expires-at".into(), serde_json::Value::from(exp));
    }
    if !r.scopes.is_empty() {
        value.insert(
            "std:scopes".into(),
            serde_json::Value::from(r.scopes.clone()),
        );
    }
    rec.fields.insert(
        field.to_string(),
        act_credentials::record::SecretValue::new(serde_json::Value::Object(value)),
    );

    // A rotated token replaces; an absent one leaves what was there. Both the
    // record's expiry and the field's move together, so `act secret list` does
    // not go on showing the old one.
    if let Some(new_refresh) = &r.refresh_token {
        rec.host_only.insert(
            refresh_token_slot(field),
            act_credentials::record::SecretValue::new(new_refresh.clone()),
        );
    }
    rec.expires_at = r.expires_at.map(|e| i64::try_from(e).unwrap_or(i64::MAX));
}

/// Where the issuer of a `std:oauth2` field is kept, alongside its refresh
/// token: `<field key>:std:issuer` and `<field key>:std:refresh-token`.
///
/// Namespaced by field key because a credential may hold an OAuth token per
/// upstream, and a compartment keyed by member name alone would have the second
/// overwrite the first — a loss that surfaces only at the first refresh.
pub fn issuer_slot(field: &str) -> String {
    format!("{field}:std:issuer")
}

pub fn refresh_token_slot(field: &str) -> String {
    format!("{field}:std:refresh-token")
}

pub struct CredentialHost {
    store: Arc<dyn CredentialStore>,
    component: String,
    live_sessions: Mutex<HashSet<String>>,
    refresher: Option<Arc<dyn CredentialRefresher>>,
    /// One lock per credential key, so two sessions renewing the same
    /// credential inside this process take turns. The store's advisory lock
    /// covers other processes; this covers the far more common case of two
    /// live sessions against one upstream, where a rotation would otherwise
    /// have each invalidate the other's token.
    refresh_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl CredentialHost {
    pub fn new(store: Arc<dyn CredentialStore>, component: String) -> Self {
        Self {
            store,
            component,
            live_sessions: Mutex::new(HashSet::new()),
            refresher: None,
            refresh_locks: Mutex::new(HashMap::new()),
        }
    }

    /// Give this host a way to renew credentials. Without one, a near-expiry
    /// credential is served as it is: the alternative — refusing it — would
    /// break every component whose upstream issues short-lived tokens, and the
    /// host has nothing better to offer.
    pub fn with_refresher(mut self, refresher: Arc<dyn CredentialRefresher>) -> Self {
        self.refresher = Some(refresher);
        self
    }

    /// The component reference this host serves — `resolve::profile_key` of
    /// the reference the operator wrote, not the literal spelling. It is the
    /// profile namespace — the boundary the whole design rests on (design
    /// §2.1) — and it is what a consent prompt must name (design §5.5).
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
    /// tokens, issuer binding — never crosses the boundary (design D4).
    ///
    /// The caller must have resolved the `act:credentials` capability decision
    /// *before* getting here: a denial must not depend on whether the key
    /// exists, or `denied` becomes a probing channel (design §3.4).
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
            Err(e) => {
                tracing::warn!(error = %e, "credential store read failed");
                Err(HostError::Unavailable(STORE_UNREADABLE.into()))
            }
        }
    }

    /// Renew any field of this credential that is too close to expiry, before
    /// it is served.
    ///
    /// Silent by design (design §5.4): the component asked for a credential and
    /// gets one that works. It never sees a refresh token and never re-opens a
    /// session because one expired.
    ///
    /// **Failure is not fatal.** A renewal that cannot happen — no refresher,
    /// no issuer recorded, the server refusing — leaves the stored value alone
    /// and lets it be served. It may still work: the skew is a margin, not an
    /// expiry, and a token inside it is usually still valid. Refusing here
    /// would turn a renewal problem into a failed tool call for a credential
    /// that was very likely fine, and the component's own upstream is the thing
    /// that actually knows. The attempt is logged; the reason never reaches the
    /// guest.
    pub async fn refresh_if_due(&self, key: &str, now: u64) {
        let Some(refresher) = self.refresher.clone() else {
            return;
        };
        // Cheap check first, outside the lock: the overwhelming majority of
        // calls are nowhere near expiry and must not queue behind anything.
        let Ok(Some(rec)) = self.store.get(&self.component, key) else {
            return;
        };
        if due_fields(&rec, now).is_empty() {
            return;
        }

        let lock = self.lock_for(key);
        let _held = lock.lock().await;

        // Re-read and re-decide **after** acquiring the lock. Whoever held it
        // first may have already renewed this very credential, and renewing
        // again would spend a rotation to replace a token that is fresh.
        let Ok(Some(rec)) = self.store.get(&self.component, key) else {
            return;
        };
        for field in due_fields(&rec, now) {
            let (Some(issuer), Some(refresh_token)) = (
                rec.host_only
                    .get(&issuer_slot(&field))
                    .and_then(|v| v.expose_str())
                    .map(str::to_string),
                rec.host_only
                    .get(&refresh_token_slot(&field))
                    .and_then(|v| v.expose_str())
                    .map(str::to_string),
            ) else {
                // Acquired before the host recorded either, or provisioned by
                // hand from a token someone else obtained. Nothing to renew
                // with; the value stands.
                tracing::debug!(
                    field = %field,
                    "credential is near expiry but carries no issuer and refresh token"
                );
                continue;
            };

            let refreshed = match refresher
                .refresh(RefreshRequest {
                    issuer: &issuer,
                    refresh_token: &refresh_token,
                    now,
                })
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(field = %field, error = %e, "credential refresh failed");
                    continue;
                }
            };

            let applied = self.store.update(&self.component, key, &mut |rec| {
                apply_refresh(rec, &field, &refreshed);
            });
            match applied {
                Ok(_) => tracing::info!(
                    component = %self.component,
                    key = %key,
                    field = %field,
                    "credential refreshed"
                ),
                Err(e) => tracing::warn!(error = %e, "storing a refreshed credential failed"),
            }
        }
    }

    fn lock_for(&self, key: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.refresh_locks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key.to_string())
            .or_default()
            .clone()
    }

    /// Metadata only — no value can reach this path, because `SecretInfo` has
    /// no field that could hold one. Deliberately unaudited (design §9): a
    /// listing hands over nothing, and recording it would bury the issue
    /// records that matter.
    pub fn list_secrets(&self, session: Option<&str>) -> Result<Vec<SecretInfo>, HostError> {
        if let Some(id) = session
            && !self.live(id)
        {
            return Err(HostError::InvalidSession);
        }
        self.store.list(Some(&self.component)).map_err(|e| {
            tracing::warn!(error = %e, "credential store list failed");
            HostError::Unavailable(STORE_UNREADABLE.into())
        })
    }
}

/// Where the file backend lives when the operator has not named one.
///
/// This is the path the writer (`act secret`) and the reader (`act run` /
/// `act call`) have to agree on when neither was given
/// `--credentials-backend`, so it lives next to the reader rather than in
/// either caller. `None` on a platform with no data directory.
pub fn default_store_root() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("act").join("credentials"))
}

/// Parse `--credentials-backend`, or fall back to [`default_store_root`].
///
/// The one parser for that flag: `act secret set/list/rm` and the runtime's
/// the credential host [`crate::ComponentRuntime::load`] builds both come
/// through here, so a store named on the
/// write is the store read on the run. There is no inferred backend — an
/// unrecognised value is an error, never a silent fall back to plaintext
/// (design D13/§7.4).
///
/// `Ok(None)` means only "no store location exists on this platform, and none
/// was named": the runtime treats that as no credential host, while `act
/// secret` turns it into an error naming the flag. Neither decision belongs
/// here.
pub fn resolve_backend(explicit: Option<&str>) -> anyhow::Result<Option<BackendChoice>> {
    match explicit {
        Some(s) => {
            let path = s.strip_prefix("file:").ok_or_else(|| {
                anyhow::anyhow!("unknown --credentials-backend '{s}'; expected file:<path>")
            })?;
            anyhow::ensure!(
                !path.is_empty(),
                "--credentials-backend 'file:' needs a path, e.g. file:/path/to/store"
            );
            Ok(Some(BackendChoice::File(PathBuf::from(path))))
        }
        None => Ok(default_store_root().map(BackendChoice::File)),
    }
}

/// The directory a [`BackendChoice`] lives in. A `match` rather than an
/// irrefutable `let`, so a second variant is a compile error here instead of
/// a silent assumption at every call site.
pub fn backend_root(choice: &BackendChoice) -> &Path {
    match choice {
        BackendChoice::File(p) => p,
    }
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
    /// whether the key exists (design §3.4).
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
                let has_channel = self.prompter.has_channel();
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
                emit_cap_decision(&CapDecisionRecord::answered(
                    CAP_CREDENTIALS,
                    key,
                    allowed,
                    has_channel,
                ));
                allowed
            }
        }
    }
}

/// Build the one line a human is asked to approve.
///
/// Everything but the hint is host-derived (design §5.5: "a descriptor signals
/// that something is needed; it never instructs the host where to go, what to
/// run, or what to say"). `component` leads, because §5.5 requires the
/// component reference be displayed prominently: the whole question is
/// *which* artifact is asking, and a prompt that only named the key would let
/// any component borrow another's reputation. It is the reference the
/// operator themselves passed on the command line, threaded through
/// `CredentialHost::component`, never anything the guest chose.
///
/// The hint is the component's own words, so it is attributed, stripped of
/// control and bidi-override characters, and truncated — by the shared
/// [`crate::consent::sanitize_hint`], which `act:consent`'s
/// [`crate::consent::prompt_line`] also calls, because a security helper with
/// two copies is two helpers that drift. The prompters escape the finished
/// line as well (`crate::consent::consent_line`) — this is the inner of two
/// layers, and it is the one that keeps the guest's text *readable* rather
/// than exploded into `\u{...}` escapes.
///
/// The component **digest** is still missing, and cannot be added from here:
/// `ConsentAsk` carries no digest for any capability class.
fn consent_summary(component: Option<&str>, action: &str, key: &str, hint: Option<&str>) -> String {
    // Same reasoning as `consent::prompt_line`: `key` is the guest's own
    // store-lookup descriptor and unbounded, so it is truncated here too —
    // escaping (later, whole-line) stops forgery; this stops a flood.
    let key = truncate_field(key);
    let base = match component {
        Some(c) => format!("{c} requests credential {action}: {key}"),
        None => format!("credential {action}: {key}"),
    };
    match hint.map(sanitize_hint) {
        Some(h) if !h.is_empty() => format!("{base} — component says: \"{h}\""),
        _ => base,
    }
}

/// Encode a stored field for the guest. WIT types the value as `cbor`
/// (`list<u8>`), so it is the field's *encoding* that must match its
/// declared type (design §3.2), not one fixed shape for every field.
///
/// `ciborium::into_writer` over the stored `serde_json::Value` does exactly
/// that with no per-kind branching: `serde_json::Value`'s own `Serialize`
/// impl calls `serialize_str` for a `std:string` field and `serialize_map`
/// for a `std:oauth2` one, so ciborium emits CBOR text or a CBOR map to
/// match — the two encodings §3.2's table names, and nothing else.
///
/// A field that is neither a string nor an object is refused rather than
/// encoded: it is not a shape the design promises the guest, and it is
/// exactly the case `STORE_UNREADABLE` documents — an externally-materialised
/// store file (design §5.6) can hold a bare JSON number — so it is reported the
/// same way, not turned into CBOR the guest has no reason to expect.
fn to_wit_secret(secret: Secret) -> Result<store::Secret, HostError> {
    let mut fields = Vec::with_capacity(secret.fields.len());
    for (name, value) in secret.fields {
        let json = value.expose();
        if !(json.is_string() || json.is_object()) {
            tracing::warn!(field = %name, "credential field is neither string- nor object-shaped");
            return Err(HostError::Unavailable(STORE_UNREADABLE.into()));
        }
        fields.push((name, act_types::cbor::to_cbor(json)));
    }
    Ok(store::Secret {
        kind: secret.kind,
        fields,
    })
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
/// so a refusal cannot depend on whether the key exists (design §3.4 — otherwise
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
    // Renew before serving, so what crosses is valid *now* (design §5.4). It
    // happens after the gate: a component refused the class must not be able to
    // make this host talk to an authorization server.
    host.refresh_if_due(&want.key, now_unix()).await;

    // `want.kind` is not consulted, and there is nothing it could select
    // between: retrieval is never filtered by shape (ACT-AUTH §1.1.6). The
    // component reads the fields it knows by name.
    let secret = host
        .get_secret(session, &want.key)
        .map_err(|e| e.to_wit())?;
    to_wit_secret(secret).map_err(|e| e.to_wit())
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
        fields.insert("acme:token".to_string(), SecretValue::new("tok"));
        let mut host_only = BTreeMap::new();
        host_only.insert("std:refresh-token".to_string(), SecretValue::new("rt"));
        store
            .put(
                "comp",
                "notion",
                &SecretRecord {
                    kind: "std:fields".into(),
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
        fn components(&self) -> Result<Vec<String>, StoreError> {
            self.inner.components()
        }
        fn update(
            &self,
            component: &str,
            key: &str,
            mutate: &mut dyn FnMut(&mut act_credentials::record::SecretRecord),
        ) -> Result<Option<act_credentials::record::SecretRecord>, StoreError> {
            self.inner.update(component, key, mutate)
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
        // `Some(&[])` is what `runtime::declared_constraints` returns for a
        // manifest that carries the class (even bare); `None` is what it
        // returns for one that does not.
        let declared: Option<Vec<serde_json::Value>> =
            if declared { Some(Vec::new()) } else { None };
        Arc::from(
            CredentialsProvider
                .resolve(
                    CAP_CREDENTIALS,
                    declared.as_deref(),
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
                 leaks whether the key exists (design §3.4), mode {mode:?}"
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
        assert_eq!(got.kind, "std:fields");
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

    /// The stored value a corrupt-store test must never see leave the host.
    const MATERIAL: &str = "987654321";

    /// A `secrets.json` the way an external secret-materialiser writes one:
    /// the field's value as a JSON number, which the CLI's own `set` cannot
    /// produce but `jq` / `op` / `kubectl get secret -o json` do without being
    /// asked.
    fn seed_numeric_value(dir: &std::path::Path) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            act_credentials::backend::file::secrets_path(dir),
            format!(
                r#"{{"entries":{{"comp":{{"notion":{{"kind":"std:fields","fields":{{"acme:token":{MATERIAL}}},"host_only":{{}},"description":null,"expires_at":null}}}}}}}}"#
            ),
        )
        .unwrap();
    }

    fn ctx_over(
        dir: &std::path::Path,
        ceiling: Arc<dyn act_policy::provider::CompiledCeiling>,
    ) -> GateContext {
        let h = Arc::new(CredentialHost::new(
            Arc::new(FileStore::new(dir.to_path_buf())),
            "comp".to_string(),
        ));
        h.note_session_opened("s1");
        GateContext {
            host: Some(h),
            ceiling,
            prompter: Arc::new(DenyPrompter),
            cache: Arc::new(DecisionCache::new()),
        }
    }

    /// The contract `act_sdk::credentials::Secret::as_oauth2` reads, pinned on
    /// the host side.
    ///
    /// This is the property the whole field-type migration exists to establish —
    /// that what `act secret set` writes is what the SDK reads — and it is the
    /// one no single task tested, because the two ends live in different repos.
    /// A literal round trip is not available yet: act-sdk is a sibling checkout
    /// and the published 0.14.0 predates its credentials module, so a path
    /// dev-dependency would break a lone clone of this repo. So both ends are
    /// pinned against the written registry instead — `ACT-CONSTANTS.md` §8.3 —
    /// and this is the host half.
    ///
    /// The encodings are load-bearing in a way that fails **silently**: the SDK
    /// treats a member of the wrong CBOR type as absent, so a float expiry reads
    /// as "never expires" and a non-array scopes list as "grants nothing",
    /// neither of which raises anything anywhere.
    #[test]
    fn an_oauth2_field_encodes_to_the_map_the_sdk_reads() {
        use ciborium::Value;

        let secret = Secret {
            kind: "std:oauth2".into(),
            fields: BTreeMap::from([(
                "std:token".to_string(),
                SecretValue::new(serde_json::json!({
                    "std:access-token": "at",
                    "std:expires-at": 1_760_000_000u64,
                    "std:scopes": ["repo", "read:org"],
                })),
            )]),
        };

        let wit = to_wit_secret(secret).expect("an object field is encodable");
        let (name, bytes) = &wit.fields[0];
        assert_eq!(name, "std:token");

        let decoded: Value = ciborium::from_reader(bytes.as_slice()).expect("valid CBOR");
        let Value::Map(members) = decoded else {
            panic!("ACT-CONSTANTS 8.1: a std:oauth2 value is a CBOR map, got {decoded:?}");
        };
        let member = |want: &str| {
            members
                .iter()
                .find(|(k, _)| matches!(k, Value::Text(s) if s == want))
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| panic!("8.3 registers {want}"))
        };

        assert!(
            matches!(member("std:access-token"), Value::Text(s) if s == "at"),
            "8.3: std:access-token is CBOR text"
        );
        assert!(
            matches!(member("std:expires-at"), Value::Integer(i) if u64::try_from(i) == Ok(1_760_000_000)),
            "8.3: std:expires-at is a CBOR unsigned integer — a float here reads as 'never expires'"
        );
        let Value::Array(scopes) = member("std:scopes") else {
            panic!("8.3: std:scopes is a CBOR array — anything else reads as 'grants nothing'");
        };
        assert!(
            scopes
                .iter()
                .all(|s| matches!(s, Value::Text(t) if t == "repo" || t == "read:org")),
            "8.3: std:scopes members are CBOR text"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_store_decode_error_does_not_carry_stored_material_to_the_guest() {
        // The phase's central claim, on the one path that used to break it:
        // `StoreError::Encoding` wraps serde's message, and serde's
        // `invalid type` text quotes the offending scalar. Forwarding it put
        // the stored credential in the guest's `unavailable` payload, and the
        // guest puts that in a tool result — so the agent read the value.
        // Spec §5.6 makes an externally-materialised store file a first-class
        // source, which is how a record this shape gets on disk at all.
        let dir = tempfile::tempdir().unwrap();
        seed_numeric_value(dir.path());

        let ctx = ctx_over(dir.path(), ceiling(true, PolicyMode::Open).await);
        let Err(store::SecretError::Unavailable(msg)) =
            serve_get(&ctx, "s1", &want("notion")).await
        else {
            panic!("a store that cannot be decoded must report `unavailable`");
        };

        assert!(
            !msg.contains(MATERIAL),
            "stored material reached the guest inside the error: {msg}"
        );
        assert_eq!(
            msg, STORE_UNREADABLE,
            "the guest gets a host-authored constant, never the store's own words"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_listing_over_an_undecodable_store_is_host_authored_too() {
        // `list` reads the index, which has no field that could hold a value,
        // so this is not today's leak — it is what keeps the two error sites
        // uniform, so a backend that ever lists from the records cannot
        // reintroduce it by inheriting the old `e.to_string()`.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(dir.path().join("index.json"), r#"{"version":"one"}"#).unwrap();

        let ctx = ctx_over(dir.path(), ceiling(true, PolicyMode::Open).await);
        let Err(store::SecretError::Unavailable(msg)) = serve_list(&ctx, Some("s1")).await else {
            panic!("an index that cannot be decoded must report `unavailable`");
        };
        assert_eq!(msg, STORE_UNREADABLE);
    }

    #[test]
    fn a_hit_returns_only_the_revealable_compartment() {
        let dir = tempfile::tempdir().unwrap();
        let h = host(dir.path());
        h.note_session_opened("s1");

        let got = h.get_secret("s1", "notion").expect("found");
        assert_eq!(got.kind, "std:fields");
        let keys: Vec<&String> = got.fields.keys().collect();
        assert_eq!(keys, vec!["acme:token"]);
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
        // The bridges keep several sessions open at once (design §8.2), so a
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
        assert_eq!(listed[0].kind, "std:fields");
        // The whole rendering, not just the fields we assert on: a value
        // reaching a listing at all is the failure this guards.
        assert!(!format!("{listed:?}").contains("tok"));
    }

    #[test]
    fn a_listing_outside_any_session_is_allowed() {
        // `list-secrets` takes `option<string>` precisely so a component can
        // inspect its profile before any session exists (design §3.3).
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
        // The profile is the boundary (design §2.1): the component name is
        // fixed at construction and no argument can reach past it.
        let dir = tempfile::tempdir().unwrap();
        let h = host(dir.path());
        let mut fields = BTreeMap::new();
        fields.insert("acme:token".to_string(), SecretValue::new("other"));
        FileStore::new(dir.path().to_path_buf())
            .put(
                "someone-else",
                "notion",
                &SecretRecord {
                    kind: "std:fields".into(),
                    fields,
                    host_only: BTreeMap::new(),
                    description: None,
                    expires_at: None,
                },
            )
            .unwrap();

        h.note_session_opened("s1");
        let got = h.get_secret("s1", "notion").expect("own key still found");
        assert_eq!(got.fields["acme:token"].expose_str(), Some("tok"));
        assert_eq!(h.list_secrets(Some("s1")).unwrap().len(), 1);
    }

    #[test]
    fn a_hint_cannot_forge_a_second_prompt_line() {
        // The hint is guest-authored (design §5.5) and lands in a prompt a
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
    fn a_megabyte_long_key_is_truncated_rather_than_flooding_the_prompt() {
        // M5: `key` is the store lookup key as the guest asked for it — the
        // same unbounded, guest-authored shape as `consent::prompt_line`'s
        // `key`, and fixed by the same shared `consent::truncate_field`.
        let huge_key = "x".repeat(1_000_000);
        let s = consent_summary(Some("comp"), "get", &huge_key, None);
        assert!(
            s.chars().count() < 200,
            "expected the key to be truncated, got {} chars",
            s.chars().count()
        );
        assert!(s.contains('…'), "got {s}");
        assert!(
            s.contains("comp requests credential get:"),
            "the rest of the line must still render normally, got {s}"
        );
    }

    #[test]
    fn a_value_crosses_the_boundary_as_cbor_not_as_a_bare_string() {
        // The guest decodes `secret-fields` with the same dCBOR reader it
        // uses for tool arguments; a raw string would decode to garbage.
        let dir = tempfile::tempdir().unwrap();
        let h = host(dir.path());
        h.note_session_opened("s1");
        let wit = to_wit_secret(h.get_secret("s1", "notion").unwrap()).unwrap();

        assert_eq!(wit.kind, "std:fields");
        assert_eq!(wit.fields.len(), 1);
        let (name, bytes) = &wit.fields[0];
        assert_eq!(name, "acme:token");
        let decoded: String = act_types::cbor::from_cbor(bytes).expect("dCBOR text string");
        assert_eq!(decoded, "tok");
    }

    #[test]
    fn an_object_field_crosses_the_boundary_as_a_cbor_map() {
        // The other half of the mapping the test above pins for a string:
        // `std:oauth2`'s field value is itself a JSON object, so the guest
        // must see a CBOR map for it, not text.
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path().to_path_buf());
        let mut fields = BTreeMap::new();
        fields.insert(
            "std:token".to_string(),
            SecretValue::new(serde_json::json!({
                "std:access-token": "at",
                "std:scopes": ["repo"],
            })),
        );
        store
            .put(
                "comp",
                "gh",
                &SecretRecord {
                    kind: "std:oauth2".into(),
                    fields,
                    host_only: BTreeMap::new(),
                    description: None,
                    expires_at: None,
                },
            )
            .unwrap();
        let h = CredentialHost::new(Arc::new(store), "comp".to_string());
        h.note_session_opened("s1");

        let wit = to_wit_secret(h.get_secret("s1", "gh").unwrap()).unwrap();
        assert_eq!(wit.kind, "std:oauth2");
        assert_eq!(wit.fields.len(), 1);
        let (name, bytes) = &wit.fields[0];
        assert_eq!(name, "std:token");

        let decoded = act_types::cbor::cbor_to_json(bytes).expect("dCBOR map");
        assert!(decoded.is_object(), "expected a CBOR map, got {decoded:?}");
        assert_eq!(decoded["std:access-token"], "at");
    }

    #[test]
    fn a_field_that_is_neither_string_nor_object_is_refused_not_encoded() {
        // A `std:string` field holding a bare number — the shape an external
        // secret-materialiser writes without being asked (design §5.6), and
        // exactly the case `STORE_UNREADABLE` exists to name. The guard still
        // refuses it; only the object case above is new.
        let mut fields = BTreeMap::new();
        fields.insert("acme:token".to_string(), SecretValue::new(987654321));
        let secret = Secret {
            kind: "std:string".into(),
            fields,
        };
        let Err(HostError::Unavailable(msg)) = to_wit_secret(secret) else {
            panic!("a non-string, non-object field must be refused, not encoded");
        };
        assert_eq!(msg, STORE_UNREADABLE);
    }

    #[test]
    fn every_host_error_has_a_distinct_wit_variant() {
        // A collapse here would report a missing credential as a policy
        // refusal, sending the user to fix the wrong thing (design §3.4).
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
            kind: "std:fields".into(),
            description: None,
            expires_at: Some(-1),
        });
        assert_eq!(info.expires_at, None);

        let ok = to_wit_info(SecretInfo {
            key: "k".into(),
            kind: "std:fields".into(),
            description: Some("note".into()),
            expires_at: Some(1_800_000_000),
        });
        assert_eq!(ok.expires_at, Some(1_800_000_000));
        assert_eq!(ok.description.as_deref(), Some("note"));
    }
}

/// Silent refresh, driven through `CredentialHost` with a refresher that
/// answers from memory.
///
/// No network and no OAuth: what is under test is the runtime's half — when it
/// decides to renew, what it writes, what it leaves alone, and what it does
/// when renewal is impossible. The protocol half lives in `act-cli` and is
/// tested there against a mock authorization server.
#[cfg(test)]
mod refresh_tests {
    use super::*;
    use act_credentials::backend::file::FileStore;
    use act_credentials::record::{SecretRecord, SecretValue};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const NOW: u64 = 1_700_000_000;

    /// Hands back a fixed token and counts how often it was asked.
    struct Canned {
        calls: AtomicUsize,
        rotates: bool,
    }

    #[async_trait::async_trait]
    impl CredentialRefresher for Canned {
        async fn refresh(&self, req: RefreshRequest<'_>) -> Result<Refreshed, String> {
            // Yield before counting, so a caller that is mid-refresh lets every
            // other one run. Without this the first task finishes without ever
            // suspending, the rest find a fresh credential at the cheap check
            // outside the lock, and a test of the lock proves nothing about it.
            tokio::task::yield_now().await;
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(req.issuer, "https://as.example.com");
            assert_eq!(req.refresh_token, "old-refresh");
            Ok(Refreshed {
                access_token: "new-access".into(),
                expires_at: Some(req.now + 3600),
                scopes: vec!["read".into()],
                refresh_token: self.rotates.then(|| "new-refresh".to_string()),
            })
        }
    }

    struct Refusing;

    #[async_trait::async_trait]
    impl CredentialRefresher for Refusing {
        async fn refresh(&self, _: RefreshRequest<'_>) -> Result<Refreshed, String> {
            Err("the authorization server refused".into())
        }
    }

    fn record(expires_at: u64, with_host_only: bool) -> SecretRecord {
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(
            "acme:token".to_string(),
            SecretValue::new(serde_json::json!({
                "std:access-token": "old-access",
                "std:expires-at": expires_at,
                "std:scopes": ["read"],
            })),
        );
        // A sibling, so "refresh touches one field" is a claim with something
        // to be false about.
        fields.insert("acme:tenant".to_string(), SecretValue::new("tenant-42"));
        let mut host_only = std::collections::BTreeMap::new();
        if with_host_only {
            host_only.insert(
                issuer_slot("acme:token"),
                SecretValue::new("https://as.example.com"),
            );
            host_only.insert(
                refresh_token_slot("acme:token"),
                SecretValue::new("old-refresh"),
            );
        }
        SecretRecord {
            kind: "std:fields".into(),
            fields,
            host_only,
            description: None,
            expires_at: Some(expires_at as i64),
        }
    }

    fn host_with(
        dir: &std::path::Path,
        rec: SecretRecord,
        refresher: Arc<dyn CredentialRefresher>,
    ) -> CredentialHost {
        let store = FileStore::new(dir.to_path_buf());
        store.put("comp", "default", &rec).unwrap();
        CredentialHost::new(Arc::new(store), "comp".to_string()).with_refresher(refresher)
    }

    #[tokio::test]
    async fn a_near_expiry_field_is_renewed_and_its_siblings_are_not() {
        let dir = tempfile::tempdir().unwrap();
        let canned = Arc::new(Canned {
            calls: AtomicUsize::new(0),
            rotates: true,
        });
        let host = host_with(dir.path(), record(NOW + 10, true), canned.clone());

        host.refresh_if_due("default", NOW).await;

        host.note_session_opened("s1");
        let served = host.get_secret("s1", "default").unwrap();
        let token = served.fields["acme:token"].expose().clone();
        assert_eq!(token["std:access-token"], "new-access");
        assert_eq!(token["std:expires-at"], serde_json::json!(NOW + 3600));
        assert_eq!(
            served.fields["acme:tenant"].expose_str(),
            Some("tenant-42"),
            "a sibling was never in scope"
        );
        assert_eq!(canned.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_rotated_refresh_token_replaces_the_stored_one_and_never_leaves() {
        let dir = tempfile::tempdir().unwrap();
        let host = host_with(
            dir.path(),
            record(NOW + 10, true),
            Arc::new(Canned {
                calls: AtomicUsize::new(0),
                rotates: true,
            }),
        );

        host.refresh_if_due("default", NOW).await;

        let stored = FileStore::new(dir.path().to_path_buf())
            .get("comp", "default")
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.host_only[&refresh_token_slot("acme:token")].expose_str(),
            Some("new-refresh"),
            "a rotating server invalidates the old; keeping it kills the next refresh"
        );
        // And the compartment still does not cross to a component.
        let projected = serde_json::to_string(
            &stored
                .project()
                .fields
                .iter()
                .map(|(k, v)| (k.clone(), v.expose().clone()))
                .collect::<std::collections::BTreeMap<_, _>>(),
        )
        .unwrap();
        assert!(!projected.contains("new-refresh"), "{projected}");
        assert!(!projected.contains("old-refresh"), "{projected}");
    }

    #[tokio::test]
    async fn a_server_that_rotates_nothing_leaves_the_stored_refresh_token() {
        let dir = tempfile::tempdir().unwrap();
        let host = host_with(
            dir.path(),
            record(NOW + 10, true),
            Arc::new(Canned {
                calls: AtomicUsize::new(0),
                rotates: false,
            }),
        );
        host.refresh_if_due("default", NOW).await;

        let stored = FileStore::new(dir.path().to_path_buf())
            .get("comp", "default")
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.host_only[&refresh_token_slot("acme:token")].expose_str(),
            Some("old-refresh"),
            "absent means keep, not clear"
        );
    }

    #[tokio::test]
    async fn a_credential_with_life_left_is_not_touched() {
        let dir = tempfile::tempdir().unwrap();
        let canned = Arc::new(Canned {
            calls: AtomicUsize::new(0),
            rotates: true,
        });
        let host = host_with(dir.path(), record(NOW + 86_400, true), canned.clone());

        host.refresh_if_due("default", NOW).await;

        assert_eq!(
            canned.calls.load(Ordering::SeqCst),
            0,
            "renewing a healthy token spends a rotation for nothing"
        );
        host.note_session_opened("s1");
        let served = host.get_secret("s1", "default").unwrap();
        assert_eq!(
            served.fields["acme:token"].expose()["std:access-token"],
            "old-access"
        );
    }

    #[tokio::test]
    async fn a_refusal_leaves_the_credential_and_serves_it() {
        // A renewal that cannot happen must not become a failed tool call: the
        // skew is a margin, not an expiry, and the token is usually still good.
        let dir = tempfile::tempdir().unwrap();
        let host = host_with(dir.path(), record(NOW + 10, true), Arc::new(Refusing));

        host.refresh_if_due("default", NOW).await;

        host.note_session_opened("s1");
        let served = host.get_secret("s1", "default").unwrap();
        assert_eq!(
            served.fields["acme:token"].expose()["std:access-token"],
            "old-access",
            "the stored value stands"
        );
    }

    #[tokio::test]
    async fn a_credential_with_no_issuer_recorded_is_served_as_it_is() {
        // Provisioned by hand from a token someone else obtained: there is
        // nothing to renew with, and that is not an error.
        let dir = tempfile::tempdir().unwrap();
        let canned = Arc::new(Canned {
            calls: AtomicUsize::new(0),
            rotates: true,
        });
        let host = host_with(dir.path(), record(NOW + 10, false), canned.clone());

        host.refresh_if_due("default", NOW).await;

        assert_eq!(canned.calls.load(Ordering::SeqCst), 0);
        host.note_session_opened("s1");
        assert!(host.get_secret("s1", "default").is_ok());
    }

    #[tokio::test]
    async fn concurrent_calls_renew_once() {
        // Two live sessions against one upstream is routine. Without the
        // per-key lock and the re-read after it, both refresh; with rotation
        // the second invalidates the first and the user is sent back to
        // `act login` with nothing to explain it.
        let dir = tempfile::tempdir().unwrap();
        let canned = Arc::new(Canned {
            calls: AtomicUsize::new(0),
            rotates: true,
        });
        let host = Arc::new(host_with(
            dir.path(),
            record(NOW + 10, true),
            canned.clone(),
        ));

        let mut tasks = Vec::new();
        for _ in 0..6 {
            let host = host.clone();
            tasks.push(tokio::spawn(async move {
                host.refresh_if_due("default", NOW).await;
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }

        assert_eq!(
            canned.calls.load(Ordering::SeqCst),
            1,
            "every task passed the cheap check before the first write landed, so \
             it is the re-read after the lock that makes the rest no-ops"
        );
    }
}
