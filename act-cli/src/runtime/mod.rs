// wasmtime component instantiation and actor pattern

use anyhow::Result;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::{mpsc, oneshot};
use wasmtime::component::{Component, Linker, ResourceTable, Source, StreamConsumer, StreamResult};
use wasmtime::{
    AsContextMut, Config, Engine, Store, StoreContextMut, StoreLimits, StoreLimitsBuilder,
};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};
use wasmtime_wasi_http::WasiHttpCtx;
use wasmtime_wasi_http::p3::WasiHttpCtxView;

pub mod consent;
pub mod effective;
pub mod elicit;
pub mod fs_matcher;
pub mod fs_policy;
pub mod http_client;
pub mod http_policy;
pub mod network;
pub mod sessions;
pub mod sockets_policy;

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
    http_hooks: crate::runtime::http_policy::PolicyHttpHooks,
    #[allow(dead_code)] // retained for Task 10 DNS resolver hook access
    http_client: std::sync::Arc<crate::runtime::http_client::ActHttpClient>,
    fs_matcher: crate::runtime::fs_matcher::FsMatcher,
    fs_mode: crate::config::PolicyMode,
    fd_paths: crate::runtime::fs_policy::FdPathMap,
    /// Interactive-consent prompter + per-session decision cache, shared by
    /// every `ask`-mode decision point (fs / http / sockets).
    consent_prompter: std::sync::Arc<dyn crate::runtime::consent::ConsentPrompter>,
    consent_cache: std::sync::Arc<crate::runtime::consent::DecisionCache>,
    /// Caps the component's wasm linear memory growth (via `store.limiter`).
    /// Default `StoreLimits` is unlimited.
    limits: StoreLimits,
}

impl HostState {
    /// Build a policy-aware filesystem view.
    fn policy_fs_view(&mut self) -> crate::runtime::fs_policy::PolicyFilesystemCtxView<'_> {
        crate::runtime::fs_policy::PolicyFilesystemCtxView {
            ctx: self.wasi.filesystem(),
            table: &mut self.table,
            matcher: &self.fs_matcher,
            fd_paths: &mut self.fd_paths,
            mode: self.fs_mode,
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
    let engine = Engine::new(&config)
        .map_err(|e| anyhow::anyhow!("failed to create wasmtime engine: {e}"))?;
    Ok(engine)
}

/// Load a .wasm component from a file path.
pub fn load_component(engine: &Engine, path: &std::path::Path) -> Result<Component> {
    Component::from_file(engine, path)
        .map_err(|e| anyhow::anyhow!("failed to load component from {}: {e}", path.display()))
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
        crate::runtime::fs_policy::PolicyFilesystem,
    >(&mut linker, |t| t.policy_fs_view())
    .map_err(|e| anyhow::anyhow!("failed to add policy wasi:filesystem/types: {e}"))?;
    wasmtime_wasi::p2::bindings::filesystem::preopens::add_to_linker::<
        HostState,
        crate::runtime::fs_policy::PolicyFilesystem,
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
        crate::runtime::fs_policy::PolicyFilesystem,
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
/// `info` is used to compute the effective policy: user's `fs`/`http` configs are
/// intersected with the component's declared capabilities before building the store.
/// Undeclared capability classes and empty allow arrays hard-deny regardless of the
/// user's grant.
#[allow(clippy::too_many_arguments)]
pub async fn create_store(
    engine: &Engine,
    preopens: &[crate::runtime::fs_policy::Preopen],
    http: &crate::config::HttpConfig,
    fs: &crate::config::FsConfig,
    sockets: &crate::config::SocketsConfig,
    info: &ComponentInfo,
    max_memory: Option<usize>,
    prompter: std::sync::Arc<dyn crate::runtime::consent::ConsentPrompter>,
    cache: std::sync::Arc<crate::runtime::consent::DecisionCache>,
) -> Result<Store<HostState>> {
    // Intersect user policy with the component's declared capabilities.
    let effective_fs = crate::runtime::effective::effective_fs(fs, &info.std.capabilities).config;
    let effective_http =
        crate::runtime::effective::effective_http(http, &info.std.capabilities).config;
    let effective_sockets =
        crate::runtime::effective::effective_sockets(sockets, &info.std.capabilities).config;

    let socket_policy =
        crate::runtime::sockets_policy::SocketsPolicy::build(effective_sockets).await?;

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

    socket_policy.install(&mut builder, prompter.clone(), cache.clone());

    let wasi = builder.build();
    let matcher = crate::runtime::fs_matcher::FsMatcher::compile(&effective_fs)?;
    let http_client = std::sync::Arc::new(crate::runtime::http_client::ActHttpClient::new(
        effective_http.clone(),
    )?);
    let state = HostState {
        wasi,
        table: ResourceTable::new(),
        http_p2: WasiHttpCtx::new(),
        http_p3: WasiHttpCtx::new(),
        http_hooks: crate::runtime::http_policy::PolicyHttpHooks::new(
            effective_http.clone(),
            http_client.clone(),
            prompter.clone(),
            cache.clone(),
        ),
        http_client,
        fs_matcher: matcher,
        fs_mode: effective_fs.mode,
        fd_paths: crate::runtime::fs_policy::FdPathMap {
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

impl From<&exports::act::tools::tool_provider::LocalizedString>
    for act_types::types::LocalizedString
{
    fn from(ls: &exports::act::tools::tool_provider::LocalizedString) -> Self {
        match ls {
            exports::act::tools::tool_provider::LocalizedString::Plain(s) => Self::Plain(s.clone()),
            exports::act::tools::tool_provider::LocalizedString::Localized(pairs) => {
                Self::from(pairs.clone())
            }
        }
    }
}

// ── Actor types ──

/// Errors from component calls.
pub enum ComponentError {
    /// Structured tool error from the component (has kind, message, metadata).
    Tool(exports::act::tools::tool_provider::Error),
    /// Infrastructure error (wasmtime, actor channel, etc.).
    Internal(anyhow::Error),
}

pub use act_types::Metadata;

/// Requests that can be sent to the component actor.
pub enum ComponentRequest {
    ListTools {
        metadata: Metadata,
        reply: oneshot::Sender<
            Result<exports::act::tools::tool_provider::ListToolsResponse, ComponentError>,
        >,
    },
    CallTool {
        name: String,
        arguments: Vec<u8>,
        metadata: Vec<(String, Vec<u8>)>,
        reply: oneshot::Sender<Result<CallToolResult, ComponentError>>,
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
    pub events: Vec<exports::act::tools::tool_provider::ToolEvent>,
}

/// Events sent through the SSE channel. Wraps stream events plus a terminal Done signal.
pub enum SseEvent {
    Stream(exports::act::tools::tool_provider::ToolEvent),
    Done,
    Error(ComponentError),
}

/// Handle to send requests to the component actor.
pub type ComponentHandle = mpsc::Sender<ComponentRequest>;

/// Instantiate the component. Returns the ActWorld, an optional
/// SessionProvider (present iff the component exports
/// `act:sessions/session-provider`), and the store.
///
/// Component info is read from custom sections (no instantiation needed
/// for that).
#[allow(clippy::too_many_arguments)]
pub async fn instantiate_component(
    engine: &Engine,
    component: &Component,
    linker: &Linker<HostState>,
    preopens: &[crate::runtime::fs_policy::Preopen],
    http: &crate::config::HttpConfig,
    fs: &crate::config::FsConfig,
    sockets: &crate::config::SocketsConfig,
    info: &ComponentInfo,
    max_memory: Option<usize>,
    prompter: std::sync::Arc<dyn crate::runtime::consent::ConsentPrompter>,
    cache: std::sync::Arc<crate::runtime::consent::DecisionCache>,
) -> Result<(
    ActWorld,
    Option<sessions::SessionProvider>,
    Store<HostState>,
)> {
    let mut store = create_store(
        engine, preopens, http, fs, sockets, info, max_memory, prompter, cache,
    )
    .await?;

    // Manual instantiation flow (replicates ActWorld::instantiate_async)
    // so we keep access to the raw `Instance` for session-provider lookup.
    let pre = linker
        .instantiate_pre(component)
        .map_err(|e| anyhow::anyhow!("failed to pre-instantiate component: {e}"))?;
    let indices =
        ActWorldIndices::new(&pre).map_err(|e| anyhow::anyhow!("ActWorld indices: {e}"))?;
    let instance = pre
        .instantiate_async(&mut store)
        .await
        .map_err(|e| anyhow::anyhow!("failed to instantiate component: {e}"))?;
    let act_world = indices
        .load(&mut store, &instance)
        .map_err(|e| anyhow::anyhow!("failed to load ActWorld: {e}"))?;

    let session_provider = sessions::SessionProvider::lookup(&instance, store.as_context_mut())?;

    Ok((act_world, session_provider, store))
}

/// Spawn the component actor task. Owns the Store, ActWorld, and the
/// optional SessionProvider (present iff the component supports
/// `act:sessions/session-provider`).
///
/// Returns a handle for sending requests.
pub fn spawn_component_actor(
    instance: ActWorld,
    session_provider: Option<sessions::SessionProvider>,
    mut store: Store<HostState>,
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
                    let provider = instance.act_tools_tool_provider().clone();
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
                } => {
                    let provider = instance.act_tools_tool_provider().clone();

                    let collected: std::sync::Arc<
                        std::sync::Mutex<Vec<exports::act::tools::tool_provider::ToolEvent>>,
                    > = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
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
                    let _ = reply.send(response);
                }
                ComponentRequest::CallToolStreaming {
                    name,
                    arguments,
                    metadata,
                    event_tx,
                } => {
                    let provider = instance.act_tools_tool_provider().clone();
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
                                    let consumer = ForwardingConsumer {
                                        event_tx: event_tx.clone(),
                                        done_tx: Some(done_tx),
                                    };
                                    let _ = stream.pipe(access, consumer);
                                }
                                exports::act::tools::tool_provider::ToolResult::Immediate(
                                    events,
                                ) => {
                                    for event in events {
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
                        .await;

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
                } => {
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
    raw: wasmtime::Result<
        wasmtime::Result<(Result<R, exports::act::tools::tool_provider::Error>,)>,
    >,
    extract: F,
) -> Result<R, ComponentError>
where
    F: FnOnce(
        (Result<R, exports::act::tools::tool_provider::Error>,),
    ) -> Result<R, exports::act::tools::tool_provider::Error>,
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
    collected: std::sync::Arc<std::sync::Mutex<Vec<exports::act::tools::tool_provider::ToolEvent>>>,
    done_tx: Option<oneshot::Sender<()>>,
}

impl StreamConsumer<HostState> for CollectingConsumer {
    type Item = exports::act::tools::tool_provider::ToolEvent;

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
}

impl StreamConsumer<HostState> for ForwardingConsumer {
    type Item = exports::act::tools::tool_provider::ToolEvent;

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
