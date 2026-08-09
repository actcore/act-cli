// wasmtime component instantiation and actor pattern

use anyhow::Result;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tokio::sync::{mpsc, oneshot};
use tracing::Instrument;
use wasmtime::component::{Component, Linker, ResourceTable, Source, StreamConsumer, StreamResult};
use wasmtime::{Config, Engine, Store, StoreContextMut, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};
use wasmtime_wasi_http::WasiHttpCtx;
use wasmtime_wasi_http::p3::WasiHttpCtxView;

pub mod consent;
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
    pub transport: act_audit::Transport,
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
    let digest = act_audit::sha256_hex(&bytes);
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
    Ok(linker)
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
) -> Result<Store<HostState>> {
    use act_audit::{CapDecisionRecord, Decision4, emit_cap_decision};
    use act_policy::grant::PolicyMode;
    use act_policy::provider::{CompiledCeiling, ProviderRegistry, ResourceOp};

    let registry = ProviderRegistry::with_builtins();

    // Helper: extract declared constraints for a capability id.
    let get_declared = |cap_id: &str| -> Vec<serde_json::Value> {
        info.std
            .capabilities
            .get(cap_id)
            .map(|req| req.constraints.clone())
            .unwrap_or_default()
    };

    let fs_grant = grant_policy.resolve(act_types::constants::CAP_FILESYSTEM);
    let http_grant = grant_policy.resolve(act_types::constants::CAP_HTTP);
    let sockets_grant = grant_policy.resolve(act_types::constants::CAP_SOCKETS);

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
    Ok(store)
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
    CallToolStreaming {
        name: String,
        arguments: Vec<u8>,
        metadata: Vec<(String, Vec<u8>)>,
        event_tx: mpsc::Sender<SseEvent>,
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

/// Events sent through the SSE channel. Wraps stream events plus a terminal Done signal.
pub enum SseEvent {
    Stream(act::tools::types::ToolEvent),
    Done,
    Error(ComponentError),
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
) -> Result<(
    ToolProvider,
    Option<sessions::SessionProvider>,
    Store<HostState>,
)> {
    use exports::act::sessions::session_provider::GuestIndices as SessionGuestIndices;
    use exports::act::tools::tool_provider::GuestIndices as ToolGuestIndices;

    let mut store = create_store(
        engine,
        preopens,
        grant_policy,
        info,
        max_memory,
        prompter,
        cache,
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
                    let audit_span = act_audit::tool_call_span(&act_audit::ToolCallStart {
                        component_ref: audit.component_ref.clone(),
                        digest: audit.digest.clone(),
                        tool: name.clone(),
                        args_sha256: act_audit::sha256_hex(&arguments),
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
                        Ok(r) if events_contain_error(&r.events) => act_audit::Outcome::ToolError,
                        Ok(_) => act_audit::Outcome::Ok,
                        Err(ComponentError::Tool(_)) => act_audit::Outcome::ToolError,
                        Err(_) => act_audit::Outcome::HostError,
                    };
                    act_audit::finish_tool_call(&audit_span, outcome, started.elapsed());
                    let _ = reply.send(response);
                }
                ComponentRequest::CallToolStreaming {
                    name,
                    arguments,
                    metadata,
                    event_tx,
                } => {
                    let provider = tool_provider.clone();

                    let started = std::time::Instant::now();
                    let meta_strings = decode_meta_strings(&metadata);
                    let audit_span = act_audit::tool_call_span(&act_audit::ToolCallStart {
                        component_ref: audit.component_ref.clone(),
                        digest: audit.digest.clone(),
                        tool: name.clone(),
                        args_sha256: act_audit::sha256_hex(&arguments),
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

                    let (done_tx, done_rx) = oneshot::channel::<()>();
                    // This arm never collects events (they're forwarded live),
                    // so a guest `tool-event::error` has to be tracked as it
                    // passes through — set by `ForwardingConsumer` or the
                    // Immediate branch below, read after the call completes.
                    let saw_error = Arc::new(AtomicBool::new(false));

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
                                    let consumer = ForwardingConsumer {
                                        event_tx: event_tx.clone(),
                                        done_tx: Some(done_tx),
                                        saw_error: saw_error.clone(),
                                    };
                                    let _ = stream.pipe(access, consumer);
                                }
                                exports::act::tools::tool_provider::ToolResult::Immediate(
                                    events,
                                ) => {
                                    for event in events {
                                        if matches!(event, act::tools::types::ToolEvent::Error(_)) {
                                            saw_error.store(true, Ordering::Relaxed);
                                        }
                                        if event_tx.try_send(SseEvent::Stream(event)).is_err() {
                                            break;
                                        }
                                    }
                                    let _ = done_tx.send(());
                                }
                            });

                            let _ = done_rx.await;

                            Ok::<_, wasmtime::Error>(())
                        })
                        .instrument(audit_span.clone())
                        .await;

                    let outcome = match &result {
                        Ok(Ok(())) if saw_error.load(Ordering::Relaxed) => {
                            act_audit::Outcome::ToolError
                        }
                        Ok(Ok(())) => act_audit::Outcome::Ok,
                        Ok(Err(_)) | Err(_) => act_audit::Outcome::HostError,
                    };
                    act_audit::finish_tool_call(&audit_span, outcome, started.elapsed());

                    let terminal = match result {
                        Ok(Ok(())) => SseEvent::Done,
                        Ok(Err(e)) => SseEvent::Error(ComponentError::Internal(anyhow::anyhow!(
                            "call-tool failed: {e}"
                        ))),
                        Err(e) => SseEvent::Error(ComponentError::Internal(anyhow::anyhow!(
                            "run_concurrent failed: {e}"
                        ))),
                    };
                    let _ = event_tx.send(terminal).await;
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
                            // Untrack regardless of error.
                            tracked_sessions.retain(|sid| sid != &session_id);
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

/// A StreamConsumer that forwards events through an mpsc channel for SSE streaming.
struct ForwardingConsumer {
    event_tx: mpsc::Sender<SseEvent>,
    done_tx: Option<oneshot::Sender<()>>,
    /// Set when a forwarded event is `tool-event::error`, so the actor can
    /// audit the call as `ToolError` instead of `Ok` once it completes —
    /// this consumer never collects events, so this flag is the only signal.
    saw_error: Arc<AtomicBool>,
}

impl StreamConsumer<HostState> for ForwardingConsumer {
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

        for event in buffer {
            if matches!(event, act::tools::types::ToolEvent::Error(_)) {
                self.saw_error.store(true, Ordering::Relaxed);
            }
            if self.event_tx.try_send(SseEvent::Stream(event)).is_err() {
                if let Some(tx) = self.done_tx.take() {
                    let _ = tx.send(());
                }
                return Poll::Ready(Ok(StreamResult::Dropped));
            }
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
        assert_eq!(digest, act_audit::sha256_hex(&bytes));
    }
}
