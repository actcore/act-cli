// wasmtime component instantiation and actor pattern

use anyhow::Result;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::{mpsc, oneshot};
use wasmtime::component::{Component, Linker, ResourceTable, Source, StreamConsumer, StreamResult};
use wasmtime::{Config, Engine, Store, StoreContextMut};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};
use wasmtime_wasi_http::WasiHttpCtx;
use wasmtime_wasi_http::p3::WasiHttpCtxView;

pub mod fs_matcher;
pub mod fs_policy;
pub mod http_client;
pub mod http_policy;
pub mod network;

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
    fd_paths: crate::runtime::fs_policy::FdPathMap,
}

impl HostState {
    /// Build a policy-aware filesystem view.
    fn policy_fs_view(&mut self) -> crate::runtime::fs_policy::PolicyFilesystemCtxView<'_> {
        crate::runtime::fs_policy::PolicyFilesystemCtxView {
            ctx: self.wasi.filesystem(),
            table: &mut self.table,
            matcher: &self.fs_matcher,
            fd_paths: &mut self.fd_paths,
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
    // Add WASI HTTP bindings (P2 for wasm32-wasip2 components, P3 for async)
    wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)
        .map_err(|e| anyhow::anyhow!("failed to add WASI HTTP P2 to linker: {e}"))?;
    wasmtime_wasi_http::p3::add_to_linker(&mut linker)
        .map_err(|e| anyhow::anyhow!("failed to add WASI HTTP P3 to linker: {e}"))?;
    Ok(linker)
}

/// Create a new store with WASI context, preopening directories from resolved mounts.
pub fn create_store(
    engine: &Engine,
    preopens: &[crate::runtime::fs_policy::Preopen],
    http: &crate::config::HttpConfig,
    fs: &crate::config::FsConfig,
) -> Result<Store<HostState>> {
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

    let wasi = builder.build();
    let matcher = crate::runtime::fs_matcher::FsMatcher::compile(fs)?;
    let http_client = std::sync::Arc::new(crate::runtime::http_client::ActHttpClient::new(
        http.clone(),
    )?);
    let state = HostState {
        wasi,
        table: ResourceTable::new(),
        http_p2: WasiHttpCtx::new(),
        http_p3: WasiHttpCtx::new(),
        http_hooks: crate::runtime::http_policy::PolicyHttpHooks::new(
            http.clone(),
            http_client.clone(),
        ),
        http_client,
        fs_matcher: matcher,
        fd_paths: crate::runtime::fs_policy::FdPathMap {
            preopens: preopen_pairs,
            by_rep: Default::default(),
        },
    };
    Ok(Store::new(engine, state))
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
    Tool(act::core::types::ToolError),
    /// Infrastructure error (wasmtime, actor channel, etc.).
    Internal(anyhow::Error),
}

pub use act_types::Metadata;

/// Requests that can be sent to the component actor.
pub enum ComponentRequest {
    GetMetadataSchema {
        metadata: Metadata,
        reply: oneshot::Sender<Result<Option<String>, ComponentError>>,
    },
    ListTools {
        metadata: Metadata,
        reply: oneshot::Sender<Result<act::core::types::ListToolsResponse, ComponentError>>,
    },
    CallTool {
        call: act::core::types::ToolCall,
        reply: oneshot::Sender<Result<CallToolResult, ComponentError>>,
    },
    CallToolStreaming {
        call: act::core::types::ToolCall,
        event_tx: mpsc::Sender<SseEvent>,
    },
}

/// Collected result from call-tool (stream already consumed).
pub struct CallToolResult {
    pub events: Vec<act::core::types::ToolEvent>,
}

/// Events sent through the SSE channel. Wraps stream events plus a terminal Done signal.
pub enum SseEvent {
    Stream(act::core::types::ToolEvent),
    Done,
    Error(ComponentError),
}

/// Handle to send requests to the component actor.
pub type ComponentHandle = mpsc::Sender<ComponentRequest>;

/// Instantiate the component. Returns the ActWorld and the store.
/// Component info is read from custom sections (no instantiation needed for that).
pub async fn instantiate_component(
    engine: &Engine,
    component: &Component,
    linker: &Linker<HostState>,
    preopens: &[crate::runtime::fs_policy::Preopen],
    http: &crate::config::HttpConfig,
    fs: &crate::config::FsConfig,
) -> Result<(ActWorld, Store<HostState>)> {
    let mut store = create_store(engine, preopens, http, fs)?;
    let instance = ActWorld::instantiate_async(&mut store, component, linker)
        .await
        .map_err(|e| anyhow::anyhow!("failed to instantiate component: {e}"))?;

    Ok((instance, store))
}

/// Warn when a component declares a capability class but the host policy
/// denies everything. The component will load and trap on first op; emit a
/// heads-up so the user can decide whether the policy needs widening.
pub fn warn_missing_capabilities(
    info: &ComponentInfo,
    fs: &crate::config::FsConfig,
    http: &crate::config::HttpConfig,
) {
    use crate::config::PolicyMode;

    let fs_declared = info
        .std
        .capabilities
        .has(act_types::constants::CAP_FILESYSTEM);
    if fs_declared && fs.mode == PolicyMode::Deny {
        tracing::warn!(
            component = %info.std.name,
            "component declares wasi:filesystem but policy denies all filesystem access"
        );
    }

    let http_declared = info.std.capabilities.has(act_types::constants::CAP_HTTP);
    if http_declared && http.mode == PolicyMode::Deny {
        tracing::warn!(
            component = %info.std.name,
            "component declares wasi:http but policy denies all HTTP access"
        );
    }
}

/// Spawn the component actor task. Owns the Store and ActWorld.
/// Returns a handle for sending requests.
pub fn spawn_component_actor(instance: ActWorld, mut store: Store<HostState>) -> ComponentHandle {
    let (tx, mut rx) = mpsc::channel::<ComponentRequest>(32);

    tokio::spawn(async move {
        while let Some(request) = rx.recv().await {
            match request {
                ComponentRequest::GetMetadataSchema { metadata, reply } => {
                    let provider = instance.act_core_tool_provider().clone();
                    let result = store
                        .run_concurrent(async |accessor| {
                            provider
                                .call_get_metadata_schema(accessor, metadata.clone().into())
                                .await
                        })
                        .await;
                    let response = match result {
                        Ok(Ok(schema)) => Ok(schema),
                        Ok(Err(e)) => Err(ComponentError::Internal(anyhow::anyhow!(
                            "get-metadata-schema failed: {e}"
                        ))),
                        Err(e) => Err(ComponentError::Internal(anyhow::anyhow!(
                            "run_concurrent failed: {e}"
                        ))),
                    };
                    let _ = reply.send(response);
                }
                ComponentRequest::ListTools { metadata, reply } => {
                    let provider = instance.act_core_tool_provider().clone();
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
                ComponentRequest::CallTool { call, reply } => {
                    let provider = instance.act_core_tool_provider().clone();

                    let collected: std::sync::Arc<
                        std::sync::Mutex<Vec<act::core::types::ToolEvent>>,
                    > = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
                    let collected2 = collected.clone();
                    let (done_tx, done_rx) = oneshot::channel::<()>();

                    let result = store
                        .run_concurrent(async |accessor| {
                            let tool_result = provider.call_call_tool(accessor, call).await?;

                            accessor.with(|access| match tool_result {
                                act::core::types::ToolResult::Streaming(stream) => {
                                    let consumer = CollectingConsumer {
                                        collected,
                                        done_tx: Some(done_tx),
                                    };
                                    let _ = stream.pipe(access, consumer);
                                }
                                act::core::types::ToolResult::Immediate(events) => {
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
                ComponentRequest::CallToolStreaming { call, event_tx } => {
                    let provider = instance.act_core_tool_provider().clone();
                    let (done_tx, done_rx) = oneshot::channel::<()>();

                    let result = store
                        .run_concurrent(async |accessor| {
                            let tool_result = provider.call_call_tool(accessor, call).await?;

                            accessor.with(|access| match tool_result {
                                act::core::types::ToolResult::Streaming(stream) => {
                                    let consumer = ForwardingConsumer {
                                        event_tx: event_tx.clone(),
                                        done_tx: Some(done_tx),
                                    };
                                    let _ = stream.pipe(access, consumer);
                                }
                                act::core::types::ToolResult::Immediate(events) => {
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
            }
        }
    });

    tx
}

/// A StreamConsumer that collects all items into a Vec and signals completion.
struct CollectingConsumer {
    collected: std::sync::Arc<std::sync::Mutex<Vec<act::core::types::ToolEvent>>>,
    done_tx: Option<oneshot::Sender<()>>,
}

impl StreamConsumer<HostState> for CollectingConsumer {
    type Item = act::core::types::ToolEvent;

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
    type Item = act::core::types::ToolEvent;

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
