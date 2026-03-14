// wasmtime component instantiation and actor pattern

use anyhow::Result;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::{mpsc, oneshot};
use wasmtime::component::{Component, Linker, ResourceTable, Source, StreamConsumer, StreamResult};
use wasmtime::{Config, Engine, Store, StoreContextMut};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};
use wasmtime_wasi_http::WasiHttpCtx;
use wasmtime_wasi_http::p3::{DefaultWasiHttpCtx, WasiHttpCtxView};

// Generated bindings from WIT — fully auto-generated, no manual patching.
#[path = "bindings/mod.rs"]
#[allow(unused_mut, unused_variables, dead_code)]
mod bindings;
pub use bindings::*;

/// Host state passed into the wasmtime store.
pub struct HostState {
    wasi: WasiCtx,
    table: ResourceTable,
    http_p2: WasiHttpCtx,
    http_p3: DefaultWasiHttpCtx,
}

impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl wasmtime_wasi_http::WasiHttpView for HostState {
    fn ctx(&mut self) -> &mut WasiHttpCtx {
        &mut self.http_p2
    }
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
}

impl wasmtime_wasi_http::p3::WasiHttpView for HostState {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView {
            ctx: &mut self.http_p3,
            table: &mut self.table,
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
    // Add P3 bindings on top
    wasmtime_wasi::p3::add_to_linker(&mut linker)
        .map_err(|e| anyhow::anyhow!("failed to add WASI P3 to linker: {e}"))?;
    // Add WASI HTTP bindings (P2 for wasm32-wasip2 components, P3 for async)
    wasmtime_wasi_http::add_only_http_to_linker_async(&mut linker)
        .map_err(|e| anyhow::anyhow!("failed to add WASI HTTP P2 to linker: {e}"))?;
    wasmtime_wasi_http::p3::add_to_linker(&mut linker)
        .map_err(|e| anyhow::anyhow!("failed to add WASI HTTP P3 to linker: {e}"))?;
    Ok(linker)
}

/// Create a new store with WASI context.
pub fn create_store(engine: &Engine) -> Store<HostState> {
    let wasi = WasiCtxBuilder::new().build();
    let state = HostState {
        wasi,
        table: ResourceTable::new(),
        http_p2: WasiHttpCtx::new(),
        http_p3: DefaultWasiHttpCtx,
    };
    Store::new(engine, state)
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

/// Requests that can be sent to the component actor.
pub enum ComponentRequest {
    ListTools {
        config: Option<Vec<u8>>,
        reply: oneshot::Sender<Result<act::core::types::ListToolsResponse, ComponentError>>,
    },
    CallTool {
        config: Option<Vec<u8>>,
        call: act::core::types::ToolCall,
        reply: oneshot::Sender<Result<CallToolResult, ComponentError>>,
    },
    CallToolStreaming {
        config: Option<Vec<u8>>,
        call: act::core::types::ToolCall,
        event_tx: mpsc::Sender<SseEvent>,
    },
}

/// Collected result from call-tool (stream already consumed).
pub struct CallToolResult {
    pub events: Vec<act::core::types::StreamEvent>,
}

/// Events sent through the SSE channel. Wraps stream events plus a terminal Done signal.
pub enum SseEvent {
    Stream(act::core::types::StreamEvent),
    Done,
    Error(ComponentError),
}

/// Handle to send requests to the component actor.
pub type ComponentHandle = mpsc::Sender<ComponentRequest>;

/// Instantiate the component and call sync methods (get_info, get_config_schema).
/// Returns the ActWorld, cached info, cached config schema, and the store.
pub async fn instantiate_component(
    engine: &Engine,
    component: &Component,
    linker: &Linker<HostState>,
) -> Result<(
    ActWorld,
    act::core::types::ComponentInfo,
    Option<String>,
    Store<HostState>,
)> {
    let mut store = create_store(engine);
    let instance = ActWorld::instantiate_async(&mut store, component, linker)
        .await
        .map_err(|e| anyhow::anyhow!("failed to instantiate component: {e}"))?;

    // get_info and get_config_schema are sync WIT functions, but the store has
    // component_model_async enabled so TypedFunc::call() panics. We bypass the
    // generated Guest methods and call TypedFunc::call_async() directly.
    let iface_idx = component
        .get_export_index(None, "act:core/tool-provider@0.1.6")
        .ok_or_else(|| anyhow::anyhow!("no exported instance act:core/tool-provider@0.1.6"))?;

    let get_info_idx = component
        .get_export_index(Some(&iface_idx), "get-info")
        .ok_or_else(|| anyhow::anyhow!("no get-info export"))?;
    let pre = linker.instantiate_pre(component)?;
    let raw_instance = pre
        .instantiate_async(&mut store)
        .await
        .map_err(|e| anyhow::anyhow!("failed to instantiate (raw): {e}"))?;
    let get_info_func = raw_instance
        .get_typed_func::<(), (act::core::types::ComponentInfo,)>(&mut store, &get_info_idx)
        .map_err(|e| anyhow::anyhow!("get-info type check failed: {e}"))?;
    let (info,) = get_info_func
        .call_async(&mut store, ())
        .await
        .map_err(|e| anyhow::anyhow!("get-info failed: {e}"))?;

    let get_config_idx = component
        .get_export_index(Some(&iface_idx), "get-config-schema")
        .ok_or_else(|| anyhow::anyhow!("no get-config-schema export"))?;
    let get_config_func = raw_instance
        .get_typed_func::<(), (Option<String>,)>(&mut store, &get_config_idx)
        .map_err(|e| anyhow::anyhow!("get-config-schema type check failed: {e}"))?;
    let (config_schema,) = get_config_func
        .call_async(&mut store, ())
        .await
        .map_err(|e| anyhow::anyhow!("get-config-schema failed: {e}"))?;

    Ok((instance, info, config_schema, store))
}

/// Spawn the component actor task. Owns the Store and ActWorld.
/// Returns a handle for sending requests.
pub fn spawn_component_actor(instance: ActWorld, mut store: Store<HostState>) -> ComponentHandle {
    let (tx, mut rx) = mpsc::channel::<ComponentRequest>(32);

    tokio::spawn(async move {
        while let Some(request) = rx.recv().await {
            match request {
                ComponentRequest::ListTools { config, reply } => {
                    let provider = instance.act_core_tool_provider().clone();
                    let result = store
                        .run_concurrent(async |accessor| {
                            provider.call_list_tools(accessor, config).await
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
                    config,
                    call,
                    reply,
                } => {
                    let provider = instance.act_core_tool_provider().clone();

                    let collected = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
                    let collected2 = collected.clone();
                    let (done_tx, done_rx) = oneshot::channel::<()>();

                    // call_call_tool now returns StreamReader<StreamEvent> directly
                    let result = store
                        .run_concurrent(async |accessor| {
                            let stream = provider.call_call_tool(accessor, config, call).await?;

                            accessor.with(|access| {
                                let consumer = CollectingConsumer {
                                    collected,
                                    done_tx: Some(done_tx),
                                };
                                stream.pipe(access, consumer);
                            });

                            if tokio::time::timeout(std::time::Duration::from_secs(30), done_rx)
                                .await
                                .is_err()
                            {
                                tracing::warn!("stream consumption timed out after 30s");
                            }

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
                    config,
                    call,
                    event_tx,
                } => {
                    let provider = instance.act_core_tool_provider().clone();
                    let (done_tx, done_rx) = oneshot::channel::<()>();

                    let result = store
                        .run_concurrent(async |accessor| {
                            let stream = provider.call_call_tool(accessor, config, call).await?;

                            accessor.with(|access| {
                                let consumer = ForwardingConsumer {
                                    event_tx: event_tx.clone(),
                                    done_tx: Some(done_tx),
                                };
                                stream.pipe(access, consumer);
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
    collected: std::sync::Arc<std::sync::Mutex<Vec<act::core::types::StreamEvent>>>,
    done_tx: Option<oneshot::Sender<()>>,
}

impl StreamConsumer<HostState> for CollectingConsumer {
    type Item = act::core::types::StreamEvent;

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
    type Item = act::core::types::StreamEvent;

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
