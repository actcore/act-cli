// wasmtime component instantiation and actor pattern

use anyhow::Result;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::{mpsc, oneshot};
use tracing::Instrument;
use wasmtime::component::{Component, Linker, ResourceTable, Source, StreamConsumer, StreamResult};
use wasmtime::{Config, Engine, Store, StoreContextMut, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};
use wasmtime_wasi_http::WasiHttpCtx;
use wasmtime_wasi_http::p3::WasiHttpCtxView;

pub mod consent;
pub mod credentials;
pub mod elicit;
pub mod fs_policy;
pub mod http_client;
pub mod http_policy;
pub mod sessions;

// Generated bindings from WIT — fully auto-generated, no manual patching.
#[allow(unused_mut, unused_variables, dead_code)]
mod bindings;
pub use bindings::*;

/// Host state passed into the wasmtime store.
pub struct HostState {
    wasi: WasiCtx,
    table: ResourceTable,
    http_p2: WasiHttpCtx,
    http_p3: WasiHttpCtx,
    http_hooks: http_policy::PolicyHttpHooks,
    #[allow(dead_code)] // retained for Task 10 DNS resolver hook access
    http_client: Arc<http_client::ActHttpClient>,
    fs_ceiling: Arc<dyn act_policy::provider::CompiledCeiling>,
    fs_effective_mode: crate::config::PolicyMode,
    fd_paths: fs_policy::FdPathMap,
    /// Interactive-consent prompter + per-session decision cache, shared by
    /// every `ask`-mode decision point (fs / http / sockets).
    consent_prompter: Arc<dyn act_policy::consent::ConsentPrompter>,
    consent_cache: Arc<act_policy::consent::DecisionCache>,
    /// The `act:credentials/store` implementation this run serves, or `None`
    /// when no credential store is configured. Held behind an `Arc` because
    /// the component actor reaches the same object to mark sessions live and
    /// dead — see `spawn_component_actor`.
    credentials: Option<Arc<credentials::CredentialHost>>,
    /// The compiled `act:credentials` ceiling, consulted before any credential
    /// is issued. Present even when `credentials` is `None`: the audit header
    /// must report the class either way.
    credentials_ceiling: Arc<dyn act_policy::provider::CompiledCeiling>,
    /// Caps the component's wasm linear memory growth (via `store.limiter`).
    /// Default `StoreLimits` is unlimited.
    limits: StoreLimits,
}

impl HostState {
    /// Build a policy-aware filesystem view.
    fn policy_fs_view(&mut self) -> fs_policy::PolicyFilesystemCtxView<'_> {
        fs_policy::PolicyFilesystemCtxView {
            ctx: self.wasi.filesystem(),
            table: &mut self.table,
            ceiling: &self.fs_ceiling,
            fd_paths: &mut self.fd_paths,
            mode: self.fs_effective_mode,
            prompter: self.consent_prompter.clone(),
            cache: self.consent_cache.clone(),
        }
    }
}

impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl wasmtime_wasi_http::p2::WasiHttpView for HostState {
    fn http(&mut self) -> wasmtime_wasi_http::p2::WasiHttpCtxView<'_> {
        wasmtime_wasi_http::p2::WasiHttpCtxView {
            ctx: &mut self.http_p2,
            table: &mut self.table,
            hooks: &mut self.http_hooks,
        }
    }
}

impl wasmtime_wasi_http::p3::WasiHttpView for HostState {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView {
            ctx: &mut self.http_p3,
            table: &mut self.table,
            hooks: &mut self.http_hooks,
        }
    }
}

/// Create a wasmtime engine with component-model and async enabled.
pub fn create_engine() -> Result<Engine> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.wasm_component_model_async(true);
    // Enable wasm exception-handling so components carrying C++-exception
    // extensions run (e.g. numpy 2.x's pocketfft throws). Additive: components
    // without the exceptions proposal are unaffected.
    config.wasm_exceptions(true);
    // SPIKE: enable WasmGC so GC-backed guests (Kotlin/Wasm, future JVM/Dart) run.
    config.wasm_function_references(true);
    config.wasm_gc(true);
    let engine = Engine::new(&config)
        .map_err(|e| anyhow::anyhow!("failed to create wasmtime engine: {e}"))?;
    Ok(engine)
}

/// Identity of the running artifact, carried into every audit record.
#[derive(Debug, Clone)]
pub struct AuditContext {
    pub component_ref: String,
    pub digest: String,
    pub transport: crate::audit::Transport,
    /// Whether this run has any channel that can answer an interactive
    /// `ask` prompt — a real TTY (`TtyPrompter`) or an MCP client offering
    /// elicitation (`McpElicitationPrompter`). `false` for headless CLI
    /// invocations and ACT-HTTP (`DenyPrompter`), where every `ask`
    /// decision degrades to deny before a human is ever involved. Decided
    /// once, at the same point the concrete prompter is chosen, and carried
    /// here so `instantiate_component` never has to infer it from the
    /// prompter's type.
    pub has_prompt_channel: bool,
    /// `--audit-args`: record full tool-argument values in the envelope
    /// alongside the digest, instead of the digest alone. Never applies to
    /// session args — those are carried only as `session_id` regardless of
    /// this flag; see `args_as_json`, which this only gates.
    pub record_args: bool,
}

/// Pull a well-known `std:` key out of decoded call metadata for the audit
/// envelope. Only ids are ever read this way — session *args* carry auth and
/// are never logged, only the session id they produced.
fn meta_str(metadata: &[(String, String)], key: &str) -> Option<String> {
    metadata
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.clone())
        .filter(|v| !v.is_empty())
}

/// Decode the string-valued entries out of raw WIT call metadata
/// (`list<tuple<string, list<u8>>>`, each value dCBOR-encoded) so `meta_str`
/// can search them. The `std:*` correlation ids the envelope reads are always
/// CBOR text strings; anything that doesn't decode to one is dropped rather
/// than guessed at.
fn decode_meta_strings(metadata: &[(String, Vec<u8>)]) -> Vec<(String, String)> {
    metadata
        .iter()
        .filter_map(|(k, v)| {
            let value = act_types::cbor::cbor_to_json(v).ok()?;
            value.as_str().map(|s| (k.clone(), s.to_string()))
        })
        .collect()
}

/// Render tool-call arguments (dCBOR bytes) as a JSON string for the audit
/// envelope, gated by `--audit-args`. Returns `None` when the flag is unset
/// (the default — `args_sha256` is all that is ever recorded then) or when
/// the arguments fail to decode; either way the call itself proceeds
/// unaffected, since the audit trail must never influence enforcement.
/// Session args never pass through this function — `open_session_for_call`
/// only ever forwards a `session_id` into the envelope, never the args that
/// produced it.
fn args_as_json(arguments: &[u8], record_args: bool) -> Option<String> {
    if !record_args {
        return None;
    }
    let value = act_types::cbor::cbor_to_json(arguments).ok()?;
    serde_json::to_string(&value).ok()
}

/// True if any event in a completed call's result signals a guest tool-level
/// failure. `call-tool` never returns `result<tool-result, error>` — an early
/// failure is encoded as a `tool-event::error` inside an otherwise `Ok`
/// response (ACT-TOOLS §5.2), the same shape `rmcp_bridge`'s
/// `fold_events_to_result` inspects to map a call to an MCP error response.
/// The audit envelope has to look at the same signal, or every guest failure
/// audits as `ok`.
fn events_contain_error(events: &[act::tools::types::ToolEvent]) -> bool {
    events
        .iter()
        .any(|e| matches!(e, act::tools::types::ToolEvent::Error(_)))
}

/// Width of the visible request-id's counter field, in bits. See
/// `pack_visible_request_id` for why this trades off against
/// `SALT_BITS` rather than being widened freely.
const REQUEST_ID_COUNTER_BITS: u32 = 9; // 512 values

/// Width of the visible request-id's salt field, in bits. Together with
/// `COUNTER_BITS` this must sum to 24 (`render_rollup` shows the id's first
/// 6 hex digits = 24 bits — the hard ceiling on how many values can ever be
/// visually distinguishable, no matter how the id is built).
const REQUEST_ID_SALT_BITS: u32 = 24 - REQUEST_ID_COUNTER_BITS; // 15 bits, 32768 values

/// Pack a per-call counter and a per-process salt into the 24-bit value
/// rendered as `new_request_id`'s leading 6 hex digits — the only part
/// `render_rollup`'s 6-byte truncation shows an operator. A prior fix
/// (`format!("act-{:x}", hash_of(pid, counter, time))`) spent 4 of those 6
/// bytes on the literal `act-` and left only 2 hex digits (256 values) of
/// real entropy visible; a standalone repro of that exact algorithm hit a
/// birthday collision at call #23 of 40. This packs the full 24 visible
/// bits productively instead, split so both properties the review asked
/// for hold within that hard ceiling:
///
/// - the high `COUNTER_BITS` bits are the per-process call counter, so two
///   different calls in the SAME process render deterministically distinct
///   visible prefixes — not probabilistically, as long as fewer than
///   `2^COUNTER_BITS` calls have been made in this process. A *fixed-width*
///   bit field is what makes this a guarantee: a variable-width
///   counter-then-salt string (e.g. `format!("{:x}{}", counter, salt)`)
///   can have a short counter's digits absorbed into what looks like a
///   longer counter's leading digits when the salt happens to repeat the
///   right digit — confirmed a real instance by brute-force search rather
///   than asserting it from intuition: `counter=1` and `counter=0x11`
///   both render `"111111"` under that scheme at `salt=0x11111`. Bit
///   packing can't do this — the counter occupies fixed bit positions no
///   salt value can shift into.
/// - the low `SALT_BITS` bits are a per-process random salt, so two
///   different PROCESSES — the dominant real-world case, since most `act
///   call` invocations make exactly one request and so always have
///   counter == 0 — usually render different visible prefixes too.
fn pack_visible_request_id(counter: u64, salt: u32) -> u32 {
    let counter_field = (counter as u32) & ((1 << REQUEST_ID_COUNTER_BITS) - 1);
    let salt_field = salt & ((1 << REQUEST_ID_SALT_BITS) - 1);
    (counter_field << REQUEST_ID_SALT_BITS) | salt_field
}

/// Host-generated correlation id, used when the caller supplied no
/// `std:request-id`. Keeping this non-optional is what makes every audit line
/// joinable to a client log line.
///
/// The visible (6-hex-digit) part comes from `pack_visible_request_id`; see
/// its doc comment for why it's split into a counter field and a salt
/// field. `salt` is drawn once per process, from `RandomState`'s
/// OS-seeded-per-thread hasher (no new dependency); `counter` is the usual
/// per-process monotonic count. The full, un-truncated counter is appended
/// after the visible portion too, so the untruncated id (used verbatim as
/// the `act.request.id` span attribute for OTLP export, never truncated
/// there) stays globally unique for the lifetime of the process regardless
/// of the 6-byte display ceiling.
fn new_request_id() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SALT: OnceLock<u32> = OnceLock::new();
    let salt = *SALT.get_or_init(|| {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u32(std::process::id());
        hasher.finish() as u32
    });

    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);

    format!("{:06x}-{n:x}", pack_visible_request_id(n, salt))
}

/// Load a .wasm component from a file path and report the SHA-256 of its
/// bytes.
///
/// The digest identifies the exact artifact in the audit trail, so it is read
/// from the file rather than inferred from the reference — a local path and an
/// OCI cache entry are treated identically.
pub fn load_component(engine: &Engine, path: &std::path::Path) -> Result<(Component, String)> {
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("failed to read component {}: {e}", path.display()))?;
    let digest = crate::audit::sha256_hex(&bytes);
    let component = Component::from_binary(engine, &bytes)
        .map_err(|e| anyhow::anyhow!("failed to load component from {}: {e}", path.display()))?;
    Ok((component, digest))
}

/// Create a linker with WASI bindings (both P2 and P3).
pub fn create_linker(engine: &Engine) -> Result<Linker<HostState>> {
    let mut linker = Linker::new(engine);
    // Add P2 bindings (components built with wasm32-wasip2 import P2 interfaces)
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)
        .map_err(|e| anyhow::anyhow!("failed to add WASI P2 to linker: {e}"))?;
    // Shadow the default wasi:filesystem bindings with our policy-aware
    // PolicyFilesystem view. Must come AFTER add_to_linker_async registered
    // the defaults.
    linker.allow_shadowing(true);
    wasmtime_wasi::p2::bindings::filesystem::types::add_to_linker::<
        HostState,
        fs_policy::PolicyFilesystem,
    >(&mut linker, |t| t.policy_fs_view())
    .map_err(|e| anyhow::anyhow!("failed to add policy wasi:filesystem/types: {e}"))?;
    wasmtime_wasi::p2::bindings::filesystem::preopens::add_to_linker::<
        HostState,
        fs_policy::PolicyFilesystem,
    >(&mut linker, |t| t.policy_fs_view())
    .map_err(|e| anyhow::anyhow!("failed to add policy wasi:filesystem/preopens: {e}"))?;
    linker.allow_shadowing(false);
    // Add P3 bindings on top
    wasmtime_wasi::p3::add_to_linker(&mut linker)
        .map_err(|e| anyhow::anyhow!("failed to add WASI P3 to linker: {e}"))?;
    // Shadow only the p3 preopens interface. When fs mode ≠ Open, our impl
    // returns zero preopens → p3 guests can't obtain a Descriptor::Dir and
    // every path op fails. Matcher-level gating on individual p3 path ops
    // isn't possible with current wasmtime-wasi public API (Dir::open_at
    // is `pub(crate)`).
    linker.allow_shadowing(true);
    wasmtime_wasi::p3::bindings::filesystem::preopens::add_to_linker::<
        HostState,
        fs_policy::PolicyFilesystem,
    >(&mut linker, |t| t.policy_fs_view())
    .map_err(|e| anyhow::anyhow!("failed to add policy wasi:filesystem/preopens (p3): {e}"))?;
    linker.allow_shadowing(false);
    // Add WASI HTTP bindings (P2 for wasm32-wasip2 components, P3 for async)
    wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)
        .map_err(|e| anyhow::anyhow!("failed to add WASI HTTP P2 to linker: {e}"))?;
    wasmtime_wasi_http::p3::add_to_linker(&mut linker)
        .map_err(|e| anyhow::anyhow!("failed to add WASI HTTP P3 to linker: {e}"))?;
    // `act:credentials` — the one interface in `act-world` the host provides
    // and the component imports. Both its instances are registered; see
    // `credentials::add_to_linker` for why `types` is not optional.
    credentials::add_to_linker(&mut linker)?;
    Ok(linker)
}

/// Declared constraints for one capability class, as `CapabilityProvider::resolve`
/// expects them.
///
/// For `wasi:filesystem`/`wasi:http`/`wasi:sockets`, an empty result legitimately
/// means "declared with an unbounded/absent ceiling": their providers parse every
/// constraint value as a typed rule, so this stays exactly the manifest's
/// constraint list, untouched — the bulk of this function's callers must never
/// see it perturbed.
///
/// `act:credentials` is different: it is a *binary* capability class (see the
/// `declared`-slice contract documented on `act_policy::providers::credentials`)
/// whose bare-table declaration form (`[std.capabilities."act:credentials"]`)
/// always parses to an empty constraint list. Left alone that collapses
/// "declared, no constraints" into "never declared", and
/// `CredentialsProvider::resolve` denies every access permanently while the
/// audit trail reports the component as never having declared the class. So for
/// this one id — and only this one, for now — presence in the manifest decides,
/// not the constraint list, and a one-element sentinel is synthesized when
/// present, matching the contract the provider's module docs require.
fn declared_constraints(info: &ComponentInfo, cap_id: &str) -> Vec<serde_json::Value> {
    if cap_id == act_policy::providers::credentials::CAP_CREDENTIALS {
        return if info.std.capabilities.has(cap_id) {
            vec![serde_json::json!({})]
        } else {
            Vec::new()
        };
    }
    info.std
        .capabilities
        .get(cap_id)
        .map(|req| req.constraints.clone())
        .unwrap_or_default()
}

/// The capability classes over which credentials can leave the machine.
///
/// Deliberately a constant read by `warn_if_credentials_exfil_risk` itself
/// rather than a list its caller assembles: a caller that wired up only
/// `wasi:http` would reopen the identical channel under the id nobody checked,
/// and nothing about that call would look wrong at the call site.
const EXFIL_NETWORK_CAPS: [&str; 2] = [
    act_types::constants::CAP_HTTP,
    act_types::constants::CAP_SOCKETS,
];

/// Warn when a component that declares `act:credentials` also holds an `open`
/// grant on a network class it declared a reachable ceiling for.
///
/// Reading credentials and reaching the network are each unremarkable alone;
/// together they are an exfiltration channel
/// (docs/specs/2026-08-03-act-credentials-design.md §4.1). Both network classes
/// count — raw TCP over `wasi:sockets` exfiltrates exactly as well as HTTP does,
/// so warning about `wasi:http` alone would leave the same channel open under a
/// different id.
///
/// ## Why the grant alone is not the trigger
///
/// The reach is the *ceiling* — grant ∩ declaration — not the grant. Per
/// `act_policy::effective`, a class the component never declared is forced to
/// `Deny` (`effective.rs:100`), a class declared as a bare table with no
/// constraints is likewise forced to `Deny` (`effective.rs:118`), and an `open`
/// grant does not mean "everything": it collapses to `Allowlist` bounded by the
/// declaration (`effective.rs:144`). So `--allow wasi:http` on a component that
/// declared no hosts buys that component nothing at all, and warning about it
/// would be a false positive — the fastest way to teach an operator to ignore
/// every warning this host emits.
///
/// The condition is therefore `open` grant **and** a non-empty declaration:
/// exactly the case where the operator has removed their own bound and the
/// artifact's self-declaration is the only one left standing.
///
/// ## Why not `act::audit`
///
/// Emitted on this module's default target, like every other host advisory
/// (`http_policy`, `fs_policy`). The audit target is not a general-purpose log:
/// `AuditLayer::on_event` reconstructs a typed `CapDecisionRecord` and drops
/// anything without both a `cap_id` and an `act.decision` field, while
/// `crate::fmt_filter` excludes `act::audit` from the `fmt` layer precisely so
/// audit events are rendered once, by `render.rs`. A prose warning addressed to
/// `act::audit` therefore reaches neither layer and is silently swallowed. This
/// is advice about a grant the operator chose, not a decision about a resource
/// access, so the ordinary log is where it belongs.
fn warn_if_credentials_exfil_risk(
    info: &ComponentInfo,
    grant_policy: &act_policy::grant::GrantPolicy,
) {
    if !info
        .std
        .capabilities
        .has(act_policy::providers::credentials::CAP_CREDENTIALS)
    {
        return;
    }

    // Note: a declaration whose constraints are present but malformed is
    // counted as reachable here, while `effective_*` parses it, logs
    // "ignoring malformed ... constraint" and denies. Erring towards the
    // warning on a manifest that is already being complained about is the
    // safe side of that seam, and keeping this check on the raw constraint
    // list avoids duplicating each class's constraint schema here.
    let unbounded: Vec<&str> = EXFIL_NETWORK_CAPS
        .iter()
        .copied()
        .filter(|cap_id| {
            grant_policy.resolve(cap_id).mode == act_policy::grant::PolicyMode::Open
                && !declared_constraints(info, cap_id).is_empty()
        })
        .collect();
    if unbounded.is_empty() {
        return;
    }

    let classes = unbounded.join(" and ");
    tracing::warn!(
        component = %info.std.name,
        open_grants = %classes,
        "component declares act:credentials and is granted {classes} in open \
         mode: an open grant adds no bound of your own, leaving the component's \
         own declaration as the only limit on where it can reach — and it can \
         send your credentials anywhere that declaration permits. Grant an \
         allowlist you chose instead."
    );
}

/// Create a new store with WASI context, preopening directories from resolved mounts.
///
/// `grant_policy` is intersected with the component's declared capabilities via
/// `ProviderRegistry::with_builtins()`. Undeclared capability classes are always
/// denied regardless of the grant.
#[allow(clippy::too_many_arguments)]
pub async fn create_store(
    engine: &Engine,
    preopens: &[fs_policy::Preopen],
    grant_policy: &act_policy::grant::GrantPolicy,
    info: &ComponentInfo,
    max_memory: Option<usize>,
    prompter: Arc<dyn act_policy::consent::ConsentPrompter>,
    cache: Arc<act_policy::consent::DecisionCache>,
    credentials: Option<Arc<credentials::CredentialHost>>,
) -> Result<(
    Store<HostState>,
    Vec<(String, Arc<dyn act_policy::provider::CompiledCeiling>)>,
)> {
    use crate::audit::{CapDecisionRecord, Decision4, emit_cap_decision};
    use act_policy::grant::PolicyMode;
    use act_policy::provider::{CompiledCeiling, ProviderRegistry, ResourceOp};

    let registry = ProviderRegistry::with_builtins();

    // Helper: extract declared constraints for a capability id.
    let get_declared =
        |cap_id: &str| -> Vec<serde_json::Value> { declared_constraints(info, cap_id) };

    let fs_grant = grant_policy.resolve(act_types::constants::CAP_FILESYSTEM);
    let http_grant = grant_policy.resolve(act_types::constants::CAP_HTTP);
    let sockets_grant = grant_policy.resolve(act_types::constants::CAP_SOCKETS);

    // act:credentials plus an unbounded grant on either network class is an
    // exfiltration channel — see `warn_if_credentials_exfil_risk` above. It
    // resolves the classes it cares about itself, from the whole policy.
    warn_if_credentials_exfil_risk(info, grant_policy);

    let fs_ceiling: Arc<dyn CompiledCeiling> = Arc::from(
        registry
            .lookup(act_types::constants::CAP_FILESYSTEM)
            .resolve(
                act_types::constants::CAP_FILESYSTEM,
                &get_declared(act_types::constants::CAP_FILESYSTEM),
                &fs_grant,
            )
            .await
            .map_err(|e| anyhow::anyhow!("fs policy: {e}"))?,
    );
    let fs_effective_mode = fs_ceiling.effective_mode();

    let http_ceiling: Arc<dyn CompiledCeiling> = Arc::from(
        registry
            .lookup(act_types::constants::CAP_HTTP)
            .resolve(
                act_types::constants::CAP_HTTP,
                &get_declared(act_types::constants::CAP_HTTP),
                &http_grant,
            )
            .await
            .map_err(|e| anyhow::anyhow!("http policy: {e}"))?,
    );

    let sockets_ceiling: Arc<dyn CompiledCeiling> = Arc::from(
        registry
            .lookup(act_types::constants::CAP_SOCKETS)
            .resolve(
                act_types::constants::CAP_SOCKETS,
                &get_declared(act_types::constants::CAP_SOCKETS),
                &sockets_grant,
            )
            .await
            .map_err(|e| anyhow::anyhow!("sockets policy: {e}"))?,
    );
    let sockets_effective_mode = sockets_ceiling.effective_mode();

    // `act:credentials` is a semantic class with no resource constraints, so
    // `declared_constraints` hands the provider a synthesized sentinel rather
    // than a rule list — see its doc comment. It is resolved even when this
    // run has no credential store: the ceiling is what the audit header
    // reports, and a component that declared the class but got nothing must
    // still show up as `declared but not granted`.
    let credentials_grant =
        grant_policy.resolve(act_policy::providers::credentials::CAP_CREDENTIALS);
    let credentials_ceiling: Arc<dyn CompiledCeiling> = Arc::from(
        registry
            .lookup(act_policy::providers::credentials::CAP_CREDENTIALS)
            .resolve(
                act_policy::providers::credentials::CAP_CREDENTIALS,
                &get_declared(act_policy::providers::credentials::CAP_CREDENTIALS),
                &credentials_grant,
            )
            .await
            .map_err(|e| anyhow::anyhow!("credentials policy: {e}"))?,
    );

    // Captured for the instantiation audit header (Task 10), before any of
    // them get moved into `HostState` / the hooks / the sockets closure
    // below — an `Arc` clone here is cheap and keeps this function's
    // enforcement wiring below untouched. Every class the host resolves
    // belongs here: the header is assembled from this vec alone, so a class
    // left out of it is one no operator ever sees a mode for.
    let ceilings: Vec<(String, Arc<dyn CompiledCeiling>)> = vec![
        (
            act_types::constants::CAP_FILESYSTEM.to_string(),
            fs_ceiling.clone(),
        ),
        (
            act_types::constants::CAP_HTTP.to_string(),
            http_ceiling.clone(),
        ),
        (
            act_types::constants::CAP_SOCKETS.to_string(),
            sockets_ceiling.clone(),
        ),
        (
            act_policy::providers::credentials::CAP_CREDENTIALS.to_string(),
            credentials_ceiling.clone(),
        ),
    ];

    let mut builder = WasiCtxBuilder::new();
    let mut preopen_pairs = Vec::with_capacity(preopens.len());
    for mount in preopens {
        builder
            .preopened_dir(
                &mount.host,
                &mount.guest,
                wasmtime_wasi::DirPerms::all(),
                wasmtime_wasi::FilePerms::all(),
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to preopen host dir '{}' as guest '{}': {}",
                    mount.host.display(),
                    mount.guest,
                    e
                )
            })?;
        preopen_pairs.push((mount.guest.clone(), mount.host.clone()));
    }

    // Install sockets enforcement via ceiling.classify.
    {
        let sockets_ceiling_clone = sockets_ceiling.clone();
        let prompter_clone = prompter.clone();
        let cache_clone = cache.clone();
        builder
            .socket_addr_check(move |addr, reason| {
                let sockets_ceiling = sockets_ceiling_clone.clone();
                let prompter = prompter_clone.clone();
                let cache = cache_clone.clone();
                Box::pin(async move {
                    use wasmtime_wasi::sockets::SocketAddrUse;
                    let proto = match reason {
                        SocketAddrUse::TcpBind | SocketAddrUse::TcpConnect => "tcp",
                        _ => "udp",
                    };
                    let key = format!("{}:{}", addr.ip(), addr.port());
                    let op = ResourceOp {
                        cap_id: act_types::constants::CAP_SOCKETS.to_string(),
                        key: key.clone(),
                        action: String::new(),
                        attrs: serde_json::json!({"protocol": proto}),
                    };
                    let explained = sockets_ceiling.classify_explained(&op);
                    let mode = sockets_effective_mode.to_string();
                    match explained.decision {
                        act_policy::Decision::Allow => {
                            emit_cap_decision(&CapDecisionRecord::statik(
                                act_types::constants::CAP_SOCKETS,
                                &key,
                                &op.action,
                                Decision4::Allow,
                                &mode,
                                explained.rule,
                            ));
                            true
                        }
                        act_policy::Decision::Deny => {
                            emit_cap_decision(&CapDecisionRecord::statik(
                                act_types::constants::CAP_SOCKETS,
                                &key,
                                &op.action,
                                Decision4::Deny,
                                &mode,
                                explained.rule,
                            ));
                            false
                        }
                        // Deliberately silent: `ask` has not resolved yet. The
                        // record is emitted below once the consent cache /
                        // prompter answers, mirroring `fs_policy::resolve_ask`.
                        act_policy::Decision::Ask => {
                            use act_policy::consent::ConsentAsk;
                            let ask = ConsentAsk {
                                cap_id: act_types::constants::CAP_SOCKETS.to_string(),
                                key: key.clone(),
                                summary: format!("socket {proto} {addr}"),
                            };
                            let allowed =
                                tokio::spawn(
                                    async move { cache.decide_cached(&*prompter, ask).await },
                                )
                                .await
                                .unwrap_or(false);
                            emit_cap_decision(&CapDecisionRecord::answered(
                                act_types::constants::CAP_SOCKETS,
                                &key,
                                allowed,
                            ));
                            allowed
                        }
                    }
                })
            })
            .allow_tcp(true)
            .allow_udp(true)
            .allow_ip_name_lookup(sockets_effective_mode != PolicyMode::Deny);
    }

    let wasi = builder.build();

    // The HTTP client's DNS resolver filters resolved IPs against the allow/deny
    // CIDR rules — which the opaque `CompiledCeiling` does not expose — so build
    // it from the full effective HttpConfig (declaration ∩ grant), not just the
    // mode. (The hook uses the ceiling; this PEP path needs the raw rules.)
    let http_effective = act_policy::effective::effective_http(
        &act_policy::grant::to_http_config(grant_policy)?,
        &info.std.capabilities,
    )
    .config;
    let http_client = Arc::new(http_client::ActHttpClient::new(http_effective)?);

    let state = HostState {
        wasi,
        table: ResourceTable::new(),
        http_p2: WasiHttpCtx::new(),
        http_p3: WasiHttpCtx::new(),
        http_hooks: http_policy::PolicyHttpHooks::new(
            http_ceiling,
            http_client.clone(),
            prompter.clone(),
            cache.clone(),
        ),
        http_client,
        fs_ceiling,
        fs_effective_mode,
        fd_paths: fs_policy::FdPathMap {
            preopens: preopen_pairs,
            by_rep: Default::default(),
        },
        consent_prompter: prompter,
        consent_cache: cache,
        credentials,
        credentials_ceiling,
        limits: match max_memory {
            Some(bytes) => StoreLimitsBuilder::new().memory_size(bytes).build(),
            None => StoreLimits::default(),
        },
    };
    let mut store = Store::new(engine, state);
    // Enforce the linear-memory cap: when the guest grows memory past the limit,
    // `memory.grow` fails (the guest typically traps OOM) instead of letting the
    // host process balloon. No-op when `max_memory` is None (default limits).
    store.limiter(|state| &mut state.limits);
    Ok((store, ceilings))
}

// ── Component info from custom section ──

pub use act_types::ComponentInfo;

/// Read component info from the `act:component` custom section (CBOR-encoded)
/// and standard WASM metadata sections (`version`, `description`) as fallback.
pub fn read_component_info(component_bytes: &[u8]) -> Result<ComponentInfo> {
    let mut info = ComponentInfo::default();

    for payload in wasmparser::Parser::new(0).parse_all(component_bytes) {
        if let Ok(wasmparser::Payload::CustomSection(section)) = payload {
            match section.name() {
                act_types::constants::SECTION_ACT_COMPONENT => {
                    info = ciborium::from_reader(section.data())
                        .map_err(|e| anyhow::anyhow!("failed to decode act:component CBOR: {e}"))?;
                }
                "version" if info.std.version.is_empty() => {
                    info.std.version = String::from_utf8_lossy(section.data()).into_owned();
                }
                "description" if info.std.description.is_empty() => {
                    info.std.description = String::from_utf8_lossy(section.data()).into_owned();
                }
                _ => {}
            }
        }
    }

    if info.std.name.is_empty() {
        info.std.name = "unknown".to_string();
    }

    Ok(info)
}

// ── Conversion helpers ──

impl From<&act::core::types::LocalizedString> for act_types::types::LocalizedString {
    fn from(ls: &act::core::types::LocalizedString) -> Self {
        match ls {
            act::core::types::LocalizedString::Plain(s) => Self::Plain(s.clone()),
            act::core::types::LocalizedString::Localized(pairs) => Self::from(pairs.clone()),
        }
    }
}

// ── Actor types ──

/// Errors from component calls.
pub enum ComponentError {
    /// Structured tool error from the component (has kind, message, metadata).
    Tool(act::core::types::Error),
    /// Infrastructure error (wasmtime, actor channel, etc.).
    Internal(anyhow::Error),
}

pub use act_types::Metadata;

/// Requests that can be sent to the component actor.
pub enum ComponentRequest {
    ListTools {
        metadata: Metadata,
        reply: oneshot::Sender<Result<act::tools::types::ListToolsResponse, ComponentError>>,
    },
    CallTool {
        name: String,
        arguments: Vec<u8>,
        metadata: Vec<(String, Vec<u8>)>,
        reply: oneshot::Sender<Result<CallToolResult, ComponentError>>,
        /// Where a capability gate firing during this call sends its consent
        /// question. `None` for transports that prompt locally (TTY) or do not
        /// prompt at all. See `runtime::elicit` for why the ask travels back to
        /// the caller instead of the gate reaching for the peer itself.
        consent: Option<elicit::ConsentSink>,
    },
    /// Returns a JSON Schema string. Errors with `std:not-found` if the
    /// component does not export `session-provider`.
    GetOpenSessionArgsSchema {
        metadata: Vec<(String, Vec<u8>)>,
        reply: oneshot::Sender<Result<String, ComponentError>>,
    },
    /// Errors with `std:not-found` if the component does not export
    /// `session-provider`.
    OpenSession {
        args: Vec<(String, Vec<u8>)>,
        metadata: Vec<(String, Vec<u8>)>,
        reply: oneshot::Sender<Result<sessions::Session, ComponentError>>,
        /// Same routing as `CallTool::consent`. Bridges do their network I/O
        /// while opening a session, so this is where their capability gate
        /// usually fires.
        consent: Option<elicit::ConsentSink>,
    },
    /// Errors with `std:not-found` if the component does not export
    /// `session-provider`. The reply carries `()` so callers can wait for
    /// the close to complete.
    CloseSession {
        session_id: String,
        reply: oneshot::Sender<Result<(), ComponentError>>,
    },
}

/// Collected result from call-tool (stream already consumed).
pub struct CallToolResult {
    pub events: Vec<act::tools::types::ToolEvent>,
}

/// Handle to send requests to the component actor.
pub type ComponentHandle = mpsc::Sender<ComponentRequest>;

/// The generated tool-provider guest — the always-present surface of every
/// ACT component.
pub use exports::act::tools::tool_provider::Guest as ToolProvider;

/// Instantiate the component. Returns the tool-provider guest, an optional
/// SessionProvider (present iff the component exports
/// `act:sessions/session-provider`), and the store.
///
/// `act-world` declares both `tool-provider` and `session-provider` as
/// exports, but the latter is opt-in. Rather than `ActWorldIndices::new`
/// (which requires *every* declared export and would reject stateless
/// components), each interface is bound through its own per-interface
/// `GuestIndices`: tool-provider is mandatory, session-provider is looked up
/// with `.ok()` so its absence yields `None`.
///
/// Component info is read from custom sections (no instantiation needed
/// for that).
#[allow(clippy::too_many_arguments)]
pub async fn instantiate_component(
    engine: &Engine,
    component: &Component,
    linker: &Linker<HostState>,
    preopens: &[fs_policy::Preopen],
    grant_policy: &act_policy::grant::GrantPolicy,
    info: &ComponentInfo,
    max_memory: Option<usize>,
    prompter: Arc<dyn act_policy::consent::ConsentPrompter>,
    cache: Arc<act_policy::consent::DecisionCache>,
    credentials: Option<Arc<credentials::CredentialHost>>,
    audit: &AuditContext,
) -> Result<(
    ToolProvider,
    Option<sessions::SessionProvider>,
    Store<HostState>,
)> {
    use exports::act::sessions::session_provider::GuestIndices as SessionGuestIndices;
    use exports::act::tools::tool_provider::GuestIndices as ToolGuestIndices;

    let (mut store, ceilings) = create_store(
        engine,
        preopens,
        grant_policy,
        info,
        max_memory,
        prompter,
        cache,
        credentials,
    )
    .await?;

    let pre = linker
        .instantiate_pre(component)
        .map_err(|e| anyhow::anyhow!("failed to pre-instantiate component: {e}"))?;
    // Resolve export indices before instantiation. tool-provider is required;
    // session-provider is optional — a missing export makes `new` error, which
    // we map to `None` (the component is simply stateless).
    let tool_indices =
        ToolGuestIndices::new(&pre).map_err(|e| anyhow::anyhow!("tool-provider indices: {e}"))?;
    let session_indices = SessionGuestIndices::new(&pre).ok();

    let instance = pre
        .instantiate_async(&mut store)
        .await
        .map_err(|e| anyhow::anyhow!("failed to instantiate component: {e}"))?;

    let tool_provider = tool_indices
        .load(&mut store, &instance)
        .map_err(|e| anyhow::anyhow!("failed to load tool-provider: {e}"))?;

    let session_provider = match session_indices {
        Some(idx) => {
            let guest = idx
                .load(&mut store, &instance)
                .map_err(|e| anyhow::anyhow!("failed to load session-provider: {e}"))?;
            Some(sessions::SessionProvider::from_guest(&guest))
        }
        None => None,
    };

    // Audit at instantiation: what is running, and under what modes. Modelled
    // exactly like a tool call — a span with one event per capability class —
    // so the same layer machinery renders it and OTLP gets queryable per-class
    // attributes rather than a sentence.
    let inst_span = crate::audit::instantiation_span(&audit.component_ref, &audit.digest);
    {
        let _g = inst_span.enter();
        for (id, c) in &ceilings {
            crate::audit::emit_ceiling_class(&crate::audit::CeilingClassRecord {
                cap_id: id.clone(),
                mode: c.effective_mode().to_string(),
                declared: c.declared(),
                has_prompt_channel: audit.has_prompt_channel,
            });
        }
    }
    // Dropping the span closes it; the layer renders the header line and, when
    // a declared class resolved to deny, the declared-but-ungranted warning.
    drop(inst_span);

    Ok((tool_provider, session_provider, store))
}

/// Spawn the component actor task. Owns the Store, the tool-provider guest,
/// and the optional SessionProvider (present iff the component supports
/// `act:sessions/session-provider`).
///
/// Returns a handle for sending requests.
pub fn spawn_component_actor(
    tool_provider: ToolProvider,
    session_provider: Option<sessions::SessionProvider>,
    mut store: Store<HostState>,
    current_consent: Arc<elicit::CurrentConsentSink>,
    audit: AuditContext,
) -> ComponentHandle {
    let (tx, mut rx) = mpsc::channel::<ComponentRequest>(32);

    // Session-ids opened through this actor. Closed on actor shutdown
    // per ACT-SESSIONS §2.5 ("host MUST call close-session for every
    // still-open session before deinit").
    let mut tracked_sessions: Vec<String> = Vec::new();

    // The credential host, if this run has one. Taken from the store rather
    // than passed in: it is already there, and reading it here keeps the two
    // views of "which sessions are live" — this actor's `tracked_sessions`
    // and the credential host's set — updated from the same three places.
    // Every transport (MCP stdio, MCP over HTTP, `--session-args`) opens and
    // closes sessions through these requests, so wiring it here covers all
    // of them at once.
    let credentials = store.data().credentials.clone();

    tokio::spawn(async move {
        while let Some(request) = rx.recv().await {
            match request {
                ComponentRequest::ListTools { metadata, reply } => {
                    let provider = tool_provider.clone();
                    let result = store
                        .run_concurrent(async |accessor| {
                            provider
                                .call_list_tools(accessor, metadata.clone().into())
                                .await
                        })
                        .await;
                    let response = match result {
                        Ok(Ok(Ok(list_response))) => Ok(list_response),
                        Ok(Ok(Err(tool_error))) => Err(ComponentError::Tool(tool_error)),
                        Ok(Err(e)) => Err(ComponentError::Internal(anyhow::anyhow!(
                            "list-tools failed: {e}"
                        ))),
                        Err(e) => Err(ComponentError::Internal(anyhow::anyhow!(
                            "run_concurrent failed: {e}"
                        ))),
                    };
                    let _ = reply.send(response);
                }
                ComponentRequest::CallTool {
                    name,
                    arguments,
                    metadata,
                    reply,
                    consent,
                } => {
                    // Point the consent slot at this call for the duration of
                    // the guest execution. The actor serves one request at a
                    // time, so a capability gate firing below always resolves
                    // to the caller that is waiting for this reply.
                    current_consent.set(consent);
                    let provider = tool_provider.clone();

                    let started = std::time::Instant::now();
                    let meta_strings = decode_meta_strings(&metadata);
                    let audit_span = crate::audit::tool_call_span(&crate::audit::ToolCallStart {
                        component_ref: audit.component_ref.clone(),
                        digest: audit.digest.clone(),
                        tool: name.clone(),
                        args_sha256: crate::audit::sha256_hex(&arguments),
                        args_json: args_as_json(&arguments, audit.record_args),
                        session_id: meta_str(&meta_strings, act_types::constants::META_SESSION_ID),
                        agent_id: meta_str(&meta_strings, act_types::constants::META_AGENT_ID),
                        request_id: meta_str(&meta_strings, act_types::constants::META_REQUEST_ID)
                            .unwrap_or_else(new_request_id),
                        traceparent: meta_str(
                            &meta_strings,
                            act_types::constants::META_TRACEPARENT,
                        ),
                        tracestate: meta_str(&meta_strings, act_types::constants::META_TRACESTATE),
                        transport: audit.transport,
                    });

                    let collected: Arc<std::sync::Mutex<Vec<act::tools::types::ToolEvent>>> =
                        Arc::new(std::sync::Mutex::new(Vec::new()));
                    let collected2 = collected.clone();
                    let (done_tx, done_rx) = oneshot::channel::<()>();

                    let result = store
                        .run_concurrent(async |accessor| {
                            let tool_result = provider
                                .call_call_tool(
                                    accessor,
                                    name.clone(),
                                    arguments.clone(),
                                    metadata.clone(),
                                )
                                .await?;

                            accessor.with(|access| match tool_result {
                                exports::act::tools::tool_provider::ToolResult::Streaming(
                                    stream,
                                ) => {
                                    let consumer = CollectingConsumer {
                                        collected,
                                        done_tx: Some(done_tx),
                                    };
                                    let _ = stream.pipe(access, consumer);
                                }
                                exports::act::tools::tool_provider::ToolResult::Immediate(
                                    events,
                                ) => {
                                    collected
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .extend(events);
                                    let _ = done_tx.send(());
                                }
                            });

                            let _ = done_rx.await;

                            Ok::<_, wasmtime::Error>(())
                        })
                        .instrument(audit_span.clone())
                        .await;

                    let response = match result {
                        Ok(Ok(())) => {
                            let events = collected2
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .drain(..)
                                .collect();
                            Ok(CallToolResult { events })
                        }
                        Ok(Err(e)) => Err(ComponentError::Internal(anyhow::anyhow!(
                            "call-tool failed: {e}"
                        ))),
                        Err(e) => Err(ComponentError::Internal(anyhow::anyhow!(
                            "run_concurrent failed: {e}"
                        ))),
                    };
                    // Nothing is executing any more: drop the sink so a later
                    // gate outside a call cannot answer through a stale caller.
                    current_consent.set(None);
                    let outcome = match &response {
                        // `call-tool` reports a guest failure inside the event
                        // list, not via the outer Result — see
                        // `events_contain_error`.
                        Ok(r) if events_contain_error(&r.events) => {
                            crate::audit::Outcome::ToolError
                        }
                        Ok(_) => crate::audit::Outcome::Ok,
                        Err(ComponentError::Tool(_)) => crate::audit::Outcome::ToolError,
                        Err(_) => crate::audit::Outcome::HostError,
                    };
                    crate::audit::finish_tool_call(&audit_span, outcome, started.elapsed());
                    let _ = reply.send(response);
                }
                ComponentRequest::GetOpenSessionArgsSchema { metadata, reply } => {
                    let response = match &session_provider {
                        Some(sp) => {
                            let sp = sp.clone();
                            let result = store
                                .run_concurrent(async |accessor| {
                                    sp.get_open_session_args_schema
                                        .call_concurrent(&accessor, (metadata,))
                                        .await
                                })
                                .await;
                            session_call_to_response(result, |(r,)| r)
                        }
                        None => Err(ComponentError::Internal(anyhow::anyhow!(
                            "component does not export act:sessions/session-provider"
                        ))),
                    };
                    let _ = reply.send(response);
                }

                ComponentRequest::OpenSession {
                    args,
                    metadata,
                    reply,
                    consent,
                } => {
                    current_consent.set(consent);
                    let response = match &session_provider {
                        Some(sp) => {
                            let sp = sp.clone();
                            let result = store
                                .run_concurrent(async |accessor| {
                                    sp.open_session
                                        .call_concurrent(&accessor, (args, metadata))
                                        .await
                                })
                                .await;
                            let inner = session_call_to_response(result, |(r,)| r);
                            // Track open id so we can close on deinit.
                            if let Ok(s) = &inner {
                                tracked_sessions.push(s.id.clone());
                                if let Some(c) = &credentials {
                                    c.note_session_opened(&s.id);
                                }
                            }
                            inner
                        }
                        None => Err(ComponentError::Internal(anyhow::anyhow!(
                            "component does not export act:sessions/session-provider"
                        ))),
                    };
                    current_consent.set(None);
                    let _ = reply.send(response);
                }

                ComponentRequest::CloseSession { session_id, reply } => {
                    let response: Result<(), ComponentError> = match &session_provider {
                        Some(sp) => {
                            let sp = sp.clone();
                            let id = session_id.clone();
                            let result = store
                                .run_concurrent(async |accessor| {
                                    sp.close_session.call_concurrent(&accessor, (id,)).await
                                })
                                .await;
                            // Untrack regardless of error. Credentials stop
                            // being served for this id at the same moment
                            // (spec §3.3: "after close-session the host stops
                            // serving that id") — a close that the component
                            // reported as failed still ends the session from
                            // the host's side, so the two must agree.
                            tracked_sessions.retain(|sid| sid != &session_id);
                            if let Some(c) = &credentials {
                                c.note_session_closed(&session_id);
                            }
                            match result {
                                Ok(Ok(())) => Ok(()),
                                Ok(Err(e)) => Err(ComponentError::Internal(anyhow::anyhow!(
                                    "close-session failed: {e}"
                                ))),
                                Err(e) => Err(ComponentError::Internal(anyhow::anyhow!(
                                    "run_concurrent failed: {e}"
                                ))),
                            }
                        }
                        None => Err(ComponentError::Internal(anyhow::anyhow!(
                            "component does not export act:sessions/session-provider"
                        ))),
                    };
                    let _ = reply.send(response);
                }
            }
        }

        // Actor channel closed → component is shutting down. Close any
        // sessions we still track, best-effort. ACT-SESSIONS §2.5.
        if let Some(sp) = &session_provider {
            for id in std::mem::take(&mut tracked_sessions) {
                if let Some(c) = &credentials {
                    c.note_session_closed(&id);
                }
                let sp = sp.clone();
                let _ = store
                    .run_concurrent(async |accessor| {
                        sp.close_session.call_concurrent(&accessor, (id,)).await
                    })
                    .await;
            }
        }
    });

    tx
}

/// Helper for unwrapping `result<R, error>` returns from session-provider
/// typed-func calls.
fn session_call_to_response<R, F>(
    raw: wasmtime::Result<wasmtime::Result<(Result<R, act::core::types::Error>,)>>,
    extract: F,
) -> Result<R, ComponentError>
where
    F: FnOnce((Result<R, act::core::types::Error>,)) -> Result<R, act::core::types::Error>,
{
    match raw {
        Ok(Ok(tuple)) => match extract(tuple) {
            Ok(r) => Ok(r),
            Err(e) => Err(ComponentError::Tool(e)),
        },
        Ok(Err(e)) => Err(ComponentError::Internal(anyhow::anyhow!(
            "session-provider call failed: {e}"
        ))),
        Err(e) => Err(ComponentError::Internal(anyhow::anyhow!(
            "run_concurrent failed: {e}"
        ))),
    }
}

/// A StreamConsumer that collects all items into a Vec and signals completion.
struct CollectingConsumer {
    collected: Arc<std::sync::Mutex<Vec<act::tools::types::ToolEvent>>>,
    done_tx: Option<oneshot::Sender<()>>,
}

impl StreamConsumer<HostState> for CollectingConsumer {
    type Item = act::tools::types::ToolEvent;

    fn poll_consume(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        store: StoreContextMut<HostState>,
        mut source: Source<'_, Self::Item>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        let mut buffer = Vec::with_capacity(64);
        source.read(store, &mut buffer)?;

        if !buffer.is_empty() {
            self.collected
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend(buffer);
        }

        if finish {
            if let Some(tx) = self.done_tx.take() {
                let _ = tx.send(());
            }
            Poll::Ready(Ok(StreamResult::Dropped))
        } else {
            Poll::Ready(Ok(StreamResult::Completed))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_metadata_keys_are_extracted_for_the_envelope() {
        let md = vec![
            ("std:session-id".to_string(), "abc123".to_string()),
            ("std:agent-id".to_string(), "claude-code".to_string()),
            ("std:traceparent".to_string(), "00-aa-bb-01".to_string()),
            ("other".to_string(), "x".to_string()),
        ];
        assert_eq!(meta_str(&md, "std:session-id").as_deref(), Some("abc123"));
        assert_eq!(
            meta_str(&md, "std:agent-id").as_deref(),
            Some("claude-code")
        );
        assert_eq!(
            meta_str(&md, "std:traceparent").as_deref(),
            Some("00-aa-bb-01")
        );
        assert_eq!(meta_str(&md, "std:request-id"), None);
        assert_eq!(meta_str(&[], "std:session-id"), None);
    }

    #[test]
    fn visible_request_id_prefixes_are_distinct_for_hundreds_of_counters_at_one_salt() {
        // Exercises `pack_visible_request_id` directly with explicit inputs,
        // not `new_request_id`'s real global counter: that counter is one
        // `static` shared by every test in this binary (integration tests
        // in `tests/*.rs` are separate processes and don't share it, but
        // other unit tests in this same file might), so drawing "several
        // hundred" real ids and asserting they're distinct would only be
        // true assuming nothing else increments the counter concurrently —
        // a coin flip with different odds, exactly what this test replaces.
        // Fixed-width bit-packing makes the counter-side of the property
        // deterministic instead: for a FIXED salt, every counter from 0 up
        // to `2^REQUEST_ID_COUNTER_BITS - 1` (512) must pack to a distinct
        // 24-bit value — provably, not "usually" — so this holds for any
        // salt, any interleaving, any number of parallel test threads.
        let salt = 0x1234;
        let mut seen = std::collections::HashSet::new();
        for counter in 0..500u64 {
            let visible = pack_visible_request_id(counter, salt);
            assert!(
                seen.insert(visible),
                "counter {counter} collided with an earlier one at salt {salt:#x}: \
                 visible={visible:#08x}"
            );
        }
    }

    #[test]
    fn fixed_width_packing_avoids_a_confirmed_variable_width_collision() {
        // Brute-force search found a genuine collision in the rejected
        // variable-width scheme `format!("{:x}{}", counter, salt)`: counter
        // 1 and counter 0x11 both render "111111" (their first 6 chars) at
        // salt 0x11111 — the counter's own digit happens to match a run of
        // repeated digits in the salt, so a short counter's representation
        // is silently absorbed into a longer counter's leading digits.
        let naive = |counter: u64, salt: u32| -> String {
            let s = format!("{counter:x}{salt:x}");
            s.chars().take(6).collect()
        };
        assert_eq!(
            naive(1, 0x11111),
            naive(0x11, 0x11111),
            "sanity check: this is the confirmed collision in the naive scheme"
        );

        // The real, fixed-width bit-packed scheme cannot exhibit this: the
        // counter always occupies the same bit positions, so no salt value
        // can shift a shorter counter's digits into a longer one's.
        let a = format!("{:06x}", pack_visible_request_id(1, 0x11111));
        let b = format!("{:06x}", pack_visible_request_id(0x11, 0x11111));
        assert_ne!(
            a, b,
            "fixed-width packing must not reproduce the naive collision"
        );
    }

    #[test]
    fn decode_meta_strings_reads_cbor_text_and_drops_everything_else() {
        // The real call sites hand `meta_str` decoded metadata, not the raw
        // WIT tuples — this is the seam between the two.
        let raw: Vec<(String, Vec<u8>)> = vec![
            (
                "std:session-id".to_string(),
                act_types::cbor::to_cbor(&"abc123".to_string()),
            ),
            (
                "std:request-id".to_string(),
                act_types::cbor::to_cbor(&42u64),
            ),
        ];
        let decoded = decode_meta_strings(&raw);
        assert_eq!(
            meta_str(&decoded, "std:session-id").as_deref(),
            Some("abc123")
        );
        // A non-string CBOR value is dropped rather than stringified.
        assert_eq!(meta_str(&decoded, "std:request-id"), None);
    }

    #[test]
    fn a_request_id_is_always_available() {
        // Correlation must never depend on the caller having supplied an
        // id. No literal prefix is asserted here (dropped in the request-id
        // rework — a fixed `act-` literal ate 4 of the 6 bytes
        // `render_rollup` actually shows, which was the root of the
        // collision this fixed); the format is non-normative, only
        // "always present and non-repeating" is.
        let a = new_request_id();
        let b = new_request_id();
        assert_ne!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn load_component_reports_the_digest_of_the_file_bytes() {
        let engine = create_engine().expect("engine");
        let path = std::path::Path::new("tests/fixtures/ask-canary.wasm");
        if !path.exists() {
            // Fixture-dependent; skip rather than fail on a fresh checkout.
            return;
        }
        let bytes = std::fs::read(path).expect("read fixture");
        let (_component, digest) = load_component(&engine, path).expect("load");
        assert_eq!(digest, crate::audit::sha256_hex(&bytes));
    }

    // ── act:credentials declared-slice contract ───────────────────────────

    use act_policy::grant::PolicyMode;
    use act_policy::providers::credentials::CAP_CREDENTIALS;

    /// Parse an `act.toml`-shaped fragment the way the real manifest is read.
    ///
    /// These tests deliberately go through TOML rather than hand-building a
    /// `Vec<serde_json::Value>`: the entire defect being guarded against is
    /// that the *prescribed declaration syntax* parses to zero constraints.
    /// A hand-built `vec![json!({})]` would assert the fix's output while
    /// saying nothing about the input production actually receives — which is
    /// exactly how this defect survived its first review.
    fn info_from_act_toml(src: &str) -> ComponentInfo {
        toml::from_str(src).expect("act.toml fragment must parse into ComponentInfo")
    }

    #[test]
    fn a_bare_credentials_table_is_handed_to_the_provider_as_a_non_empty_slice() {
        let info = info_from_act_toml(
            r#"
            [std]
            name = "notion"

            [std.capabilities."act:credentials"]
            "#,
        );

        // Precondition — this is the trap. The spec-prescribed declaration
        // form really does parse to an empty constraint list, so the raw
        // manifest cannot distinguish "declared" from "absent" on its own.
        assert!(
            info.std
                .capabilities
                .get(CAP_CREDENTIALS)
                .expect("capability must be present in the parsed manifest")
                .constraints
                .is_empty(),
            "the bare-table form is expected to carry zero constraints; if this \
             ever changes, `declared_constraints`' credentials branch is moot"
        );

        // `CredentialsProvider::resolve` derives declared-ness from
        // `!declared.is_empty()` and sees nothing else, so a sentinel must be
        // synthesized or every credential access is denied forever while the
        // audit trail blames the component for not declaring the class.
        assert!(
            !declared_constraints(&info, CAP_CREDENTIALS).is_empty(),
            "a component that declared act:credentials must reach the provider \
             as a non-empty declared slice"
        );
    }

    #[test]
    fn an_undeclared_credentials_capability_is_handed_over_as_an_empty_slice() {
        let info = info_from_act_toml(
            r#"
            [std]
            name = "no-secrets"

            [std.capabilities."wasi:http"]
            constraints = [{ host = "api.notion.com" }]
            "#,
        );

        assert!(
            !info.std.capabilities.has(CAP_CREDENTIALS),
            "sanity: this manifest must not declare act:credentials"
        );
        assert!(
            declared_constraints(&info, CAP_CREDENTIALS).is_empty(),
            "an undeclared act:credentials must stay empty so the provider denies it"
        );
    }

    #[test]
    fn the_sentinel_is_scoped_to_credentials_and_never_perturbs_physical_classes() {
        // For wasi:filesystem/http/sockets an empty `declared` legitimately
        // means "no ceiling, deny" — and their providers parse every element
        // of the slice as a typed constraint, so a `{}` sentinel would be fed
        // to a parser expecting `{"host": ...}` / `{"path": ...}`.
        let info = info_from_act_toml(
            r#"
            [std]
            name = "bare-physical"

            [std.capabilities."wasi:filesystem"]

            [std.capabilities."wasi:http"]

            [std.capabilities."wasi:sockets"]
            "#,
        );

        for cap in [
            act_types::constants::CAP_FILESYSTEM,
            act_types::constants::CAP_HTTP,
            act_types::constants::CAP_SOCKETS,
        ] {
            assert!(
                info.std.capabilities.has(cap),
                "sanity: {cap} must be declared in this manifest"
            );
            assert!(
                declared_constraints(&info, cap).is_empty(),
                "{cap} is declared bare, so its declared slice must stay empty — \
                 no sentinel, or its provider would try to parse `{{}}` as a rule"
            );
        }
    }

    #[test]
    fn declared_constraints_passes_physical_constraints_through_verbatim() {
        let info = info_from_act_toml(
            r#"
            [std]
            name = "scoped"

            [std.capabilities."wasi:http"]
            constraints = [{ host = "api.notion.com" }, { host = "*.example.com" }]
            "#,
        );

        assert_eq!(
            declared_constraints(&info, act_types::constants::CAP_HTTP),
            vec![
                serde_json::json!({ "host": "api.notion.com" }),
                serde_json::json!({ "host": "*.example.com" }),
            ],
            "physical classes must see their manifest constraints untouched"
        );
    }

    // ── the credentials ceiling reaches the audit header ──────────────────

    /// Resolve one component's ceilings the way `instantiate_component` does,
    /// and hand back the vec the instantiation audit header is built from.
    async fn ceilings_for(
        info: &ComponentInfo,
        policy: &act_policy::grant::GrantPolicy,
    ) -> Vec<(String, Arc<dyn act_policy::provider::CompiledCeiling>)> {
        let engine = create_engine().expect("engine");
        let (_store, ceilings) = create_store(
            &engine,
            &[],
            policy,
            info,
            None,
            Arc::new(act_policy::consent::DenyPrompter),
            Arc::new(act_policy::consent::DecisionCache::new()),
            None,
        )
        .await
        .expect("create_store");
        ceilings
    }

    #[tokio::test(flavor = "current_thread")]
    async fn the_credentials_class_is_among_the_ceilings_the_audit_header_renders() {
        // `instantiate_component` emits one `act.ceiling_class` event per
        // entry of this vec and nothing else, so a class missing from it is a
        // class no operator ever sees — the component's declared credential
        // access would leave no trace in the trail at all.
        let info = info_from_act_toml(
            r#"
            [std]
            name = "notion"

            [std.capabilities."act:credentials"]
            "#,
        );
        let ceilings = ceilings_for(&info, &grants(&[(CAP_CREDENTIALS, PolicyMode::Ask)])).await;

        let (_, ceiling) = ceilings
            .iter()
            .find(|(id, _)| id == CAP_CREDENTIALS)
            .expect("act:credentials must be one of the resolved ceilings");
        assert!(
            ceiling.declared(),
            "the manifest declared it, so the header must not report otherwise"
        );
        assert_eq!(ceiling.effective_mode(), PolicyMode::Ask);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_undeclared_credentials_class_is_still_reported_and_resolves_to_deny() {
        // Reported, not omitted: the header's job is to state the mode of
        // every class, and "deny" is the answer an operator needs when a
        // component silently fails to read a credential it never declared.
        let info = info_from_act_toml(
            r#"
            [std]
            name = "crypto"
            "#,
        );
        let ceilings = ceilings_for(&info, &grants(&[(CAP_CREDENTIALS, PolicyMode::Open)])).await;

        let (_, ceiling) = ceilings
            .iter()
            .find(|(id, _)| id == CAP_CREDENTIALS)
            .expect("act:credentials must be reported even when undeclared");
        assert!(!ceiling.declared());
        assert_eq!(
            ceiling.effective_mode(),
            PolicyMode::Deny,
            "an open grant must not widen a class the component never declared"
        );
    }

    // ── the credentials + open-network warning ────────────────────────────

    /// A `MakeWriter` that accumulates formatted events in memory, so the
    /// warning can be asserted as it is actually emitted (target included)
    /// rather than by re-testing the `if` that guards it.
    #[derive(Clone, Default)]
    struct CapturedLog(Arc<std::sync::Mutex<Vec<u8>>>);

    impl CapturedLog {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).expect("utf-8 log output")
        }
    }

    impl std::io::Write for CapturedLog {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Run the warning through **the production `fmt` layer**, filter and all.
    ///
    /// Deliberately not a bare `fmt()` subscriber. `crate::fmt_filter` drops
    /// the `act::audit` and `act::guest` targets so audit events are rendered
    /// only by `render.rs`, and `AuditLayer::on_event` in turn drops any event
    /// that is not a typed capability record. An advisory addressed to
    /// `act::audit` therefore falls between the two layers and reaches no
    /// output at all — which is exactly what this warning did before, and a
    /// bare `fmt()` subscriber would have happily printed it and called the
    /// test green.
    /// A `GrantPolicy` with explicit per-class modes and everything else denied.
    fn grants(pairs: &[(&str, PolicyMode)]) -> act_policy::grant::GrantPolicy {
        act_policy::grant::GrantPolicy {
            default: PolicyMode::Deny,
            entries: pairs
                .iter()
                .map(|(id, mode)| {
                    (
                        (*id).to_string(),
                        act_policy::grant::CapabilityGrant {
                            mode: *mode,
                            allow: vec![],
                            deny: vec![],
                        },
                    )
                })
                .collect(),
        }
    }

    fn capture_exfil_warning(
        info: &ComponentInfo,
        network_grants: &[(&str, PolicyMode)],
    ) -> String {
        use tracing_subscriber::prelude::*;

        let log = CapturedLog::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_writer(log.clone())
                .with_ansi(false)
                // The default `log-level = "info"` from `config.toml`, i.e.
                // what an operator who configured nothing actually runs with.
                .with_filter(crate::fmt_filter(tracing_subscriber::EnvFilter::new(
                    "act=info",
                ))),
        );
        // Thread-local, so parallel tests don't fight over a global default.
        let policy = grants(network_grants);
        tracing::subscriber::with_default(subscriber, || {
            warn_if_credentials_exfil_risk(info, &policy);
        });
        log.contents()
    }

    /// A component with credentials **and genuine reach**: `wasi:http`
    /// declared with real hosts, so an `open` grant actually leaves it able to
    /// talk to them.
    ///
    /// The earlier version of this fixture declared `wasi:http` as a bare
    /// table, which `effective_http` forces to `Deny` — so the positive test
    /// was asserting that the host warns about a component whose HTTP ceiling
    /// blocks everything.
    fn credentials_and_reachable_http() -> ComponentInfo {
        info_from_act_toml(
            r#"
            [std]
            name = "notion-sync"

            [std.capabilities."act:credentials"]

            [std.capabilities."wasi:http"]
            constraints = [{ host = "api.notion.com" }, { host = "*.notion.so" }]
            "#,
        )
    }

    fn credentials_and_reachable_sockets() -> ComponentInfo {
        info_from_act_toml(
            r#"
            [std]
            name = "pg-sync"

            [std.capabilities."act:credentials"]

            [std.capabilities."wasi:sockets"]
            constraints = [{ host = "db.internal", ports = [5432], protocols = ["tcp"] }]
            "#,
        )
    }

    #[test]
    fn credentials_plus_open_http_warns_about_exfiltration_not_just_the_two_names() {
        let out = capture_exfil_warning(
            &credentials_and_reachable_http(),
            &[
                (act_types::constants::CAP_HTTP, PolicyMode::Open),
                (act_types::constants::CAP_SOCKETS, PolicyMode::Deny),
            ],
        );

        assert!(
            !out.is_empty(),
            "the warning must actually reach an output layer — addressed to \
             `act::audit` it is dropped by `fmt_filter` and then again by \
             `AuditLayer::on_event`, and nothing is printed at all"
        );
        assert!(
            out.contains("WARN"),
            "the combination must be reported at WARN, got: {out}"
        );
        assert!(
            out.contains("notion-sync"),
            "must name the component it is about, got: {out}"
        );
        assert!(
            out.contains("wasi:http"),
            "must name the class whose grant is open, got: {out}"
        );
        // The point of the warning is the *consequence* of the pairing. Naming
        // the two capabilities without saying what they add up to tells the
        // operator nothing they could not read off their own command line.
        assert!(
            out.contains("send your credentials anywhere that declaration permits"),
            "must state that credentials can be sent across that reach, got: {out}"
        );
        assert!(
            out.contains("only limit on where it can reach"),
            "must state that the artifact's own declaration is the last bound \
             standing once the operator's grant is open, got: {out}"
        );
        // An `open` grant collapses to `Allowlist` bounded by the declaration
        // (`effective.rs:144`), so "any host" is simply false. An overstated
        // warning is a warning operators learn to skip.
        assert!(
            !out.contains("any host"),
            "must not claim unbounded reach — an open grant is still bounded by \
             the component's declaration, got: {out}"
        );
    }

    #[test]
    fn credentials_plus_open_sockets_warns_too_because_raw_tcp_exfiltrates_as_well() {
        // Design §4.1 rests containment on credentials + http *and* sockets.
        // Covering only http would leave the identical channel open under a
        // different capability id.
        let out = capture_exfil_warning(
            &credentials_and_reachable_sockets(),
            &[
                (act_types::constants::CAP_HTTP, PolicyMode::Deny),
                (act_types::constants::CAP_SOCKETS, PolicyMode::Open),
            ],
        );

        assert!(
            out.contains("wasi:sockets"),
            "an open wasi:sockets grant must warn and name the class, got: {out}"
        );
        assert!(
            out.contains("pg-sync"),
            "must name the component it is about, got: {out}"
        );
    }

    #[test]
    fn both_network_classes_open_are_both_named() {
        let info = info_from_act_toml(
            r#"
            [std]
            name = "wide-open"

            [std.capabilities."act:credentials"]

            [std.capabilities."wasi:http"]
            constraints = [{ host = "api.example.com" }]

            [std.capabilities."wasi:sockets"]
            constraints = [{ host = "db.internal", ports = [5432], protocols = ["tcp"] }]
            "#,
        );
        let out = capture_exfil_warning(
            &info,
            &[
                (act_types::constants::CAP_HTTP, PolicyMode::Open),
                (act_types::constants::CAP_SOCKETS, PolicyMode::Open),
            ],
        );

        assert!(
            out.contains("wasi:http") && out.contains("wasi:sockets"),
            "both open classes must be named, got: {out}"
        );
    }

    #[test]
    fn an_open_grant_on_a_class_the_component_cannot_actually_reach_stays_silent() {
        // The reach is the ceiling — grant ∩ declaration — not the grant. Both
        // shapes below are forced to `Deny` by `act_policy::effective`, so the
        // component can reach nothing and there is nothing to warn about.
        // Warning here is the false positive that trains operators to ignore
        // every warning the host emits.
        let bare_declaration = info_from_act_toml(
            r#"
            [std]
            name = "bare-net"

            [std.capabilities."act:credentials"]

            [std.capabilities."wasi:http"]

            [std.capabilities."wasi:sockets"]
            "#,
        );
        let out = capture_exfil_warning(
            &bare_declaration,
            &[
                (act_types::constants::CAP_HTTP, PolicyMode::Open),
                (act_types::constants::CAP_SOCKETS, PolicyMode::Open),
            ],
        );
        assert!(
            out.is_empty(),
            "a bare network declaration is forced to Deny (effective.rs:118), so \
             an open grant on it reaches nothing and must not warn, got: {out}"
        );

        let never_declared = info_from_act_toml(
            r#"
            [std]
            name = "no-net"

            [std.capabilities."act:credentials"]
            "#,
        );
        let out = capture_exfil_warning(
            &never_declared,
            &[
                (act_types::constants::CAP_HTTP, PolicyMode::Open),
                (act_types::constants::CAP_SOCKETS, PolicyMode::Open),
            ],
        );
        assert!(
            out.is_empty(),
            "an undeclared class is forced to Deny (effective.rs:100) — \
             `--allow wasi:http` buys such a component nothing, got: {out}"
        );
    }

    #[test]
    fn neither_capability_alone_triggers_the_exfiltration_warning() {
        // Reach is bounded by a grant the operator chose, so no warning — the
        // artifact's declaration is not the only thing standing between the
        // credentials and the network.
        for mode in [PolicyMode::Deny, PolicyMode::Allowlist, PolicyMode::Ask] {
            let out = capture_exfil_warning(
                &credentials_and_reachable_http(),
                &[
                    (act_types::constants::CAP_HTTP, mode),
                    (act_types::constants::CAP_SOCKETS, mode),
                ],
            );
            assert!(
                out.is_empty(),
                "act:credentials with network in {mode} mode must not warn, got: {out}"
            );
        }

        // Wide-open network but nothing to exfiltrate: no credentials, no warning.
        let no_credentials = info_from_act_toml(
            r#"
            [std]
            name = "plain-fetcher"

            [std.capabilities."wasi:http"]
            constraints = [{ host = "api.example.com" }]

            [std.capabilities."wasi:sockets"]
            constraints = [{ host = "db.internal", ports = [5432], protocols = ["tcp"] }]
            "#,
        );
        let out = capture_exfil_warning(
            &no_credentials,
            &[
                (act_types::constants::CAP_HTTP, PolicyMode::Open),
                (act_types::constants::CAP_SOCKETS, PolicyMode::Open),
            ],
        );
        assert!(
            out.is_empty(),
            "open network without act:credentials must not warn, got: {out}"
        );
    }
}
