# SSE Streaming Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add Server-Sent Events streaming to `POST /tools/{name}` so clients receive tool results incrementally when requesting `Accept: text/event-stream`.

**Architecture:** The `call_tool` handler checks the `Accept` header. For SSE, a new `CallToolStreaming` actor request uses a `ForwardingConsumer` that sends events via mpsc channel to an axum `Sse` response. A host-side `SseEvent` enum wraps stream events and a `Done` sentinel — the actor sends `Done` after the stream completes, so the SSE response knows when to close. Client disconnect drops the channel receiver, causing sends to fail, which triggers stream cancellation. Only one new dependency: `tokio-stream`.

**Tech Stack:** Rust, axum (Sse), tokio (mpsc), tokio-stream (ReceiverStream), wasmtime StreamConsumer

---

### Task 1: Add tokio-stream dependency

**Files:**
- Modify: `Cargo.toml`

**Step 1: Add dependency**

Add `tokio-stream = "0.1"` to `[dependencies]` in `Cargo.toml` (after `tokio`).

**Step 2: Verify it compiles**

Run: `cargo check`
Expected: success

**Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: add tokio-stream dependency for SSE support"
```

---

### Task 2: Add ForwardingConsumer and SseEvent to runtime

**Files:**
- Modify: `src/runtime.rs`

**Step 1: Add `SseEvent` enum and `CallToolStreaming` variant**

After `CallToolResult` (line 98), add the `SseEvent` enum:

```rust
/// Events sent through the SSE channel. Wraps stream events plus a terminal Done signal.
pub enum SseEvent {
    Stream(act::core::types::StreamEvent),
    Done,
    Error(ComponentError),
}
```

After the existing `CallTool` variant in `ComponentRequest` (line 87-91), add:

```rust
CallToolStreaming {
    config: Option<Vec<u8>>,
    call: act::core::types::ToolCall,
    event_tx: mpsc::Sender<SseEvent>,
},
```

Note: no `reply` oneshot needed — the actor sends `SseEvent::Done` or `SseEvent::Error` through the same channel.

**Step 2: Add `ForwardingConsumer` struct**

After the `CollectingConsumer` impl (after line 261), add:

```rust
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
                // Client disconnected — cancel the stream.
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
```

**Step 3: Handle `CallToolStreaming` in the actor loop**

After the `CallTool` match arm's closing `}` (around line 219), add a new match arm:

```rust
ComponentRequest::CallToolStreaming {
    config,
    call,
    event_tx,
} => {
    let provider = instance.act_core_tool_provider().clone();
    let (done_tx, done_rx) = oneshot::channel::<()>();

    let result = store
        .run_concurrent(async |accessor| {
            let call_response =
                provider.call_call_tool(accessor, config, call).await?;

            accessor.with(|access| {
                let consumer = ForwardingConsumer {
                    event_tx: event_tx.clone(),
                    done_tx: Some(done_tx),
                };
                call_response.body.pipe(access, consumer);
            });

            // Wait for stream completion or client disconnect.
            let _ = done_rx.await;

            Ok::<_, wasmtime::Error>(())
        })
        .await;

    // Send terminal event through the same channel.
    let terminal = match result {
        Ok(Ok(())) => SseEvent::Done,
        Ok(Err(e)) => SseEvent::Error(ComponentError::Internal(
            anyhow::anyhow!("call-tool failed: {e}"),
        )),
        Err(e) => SseEvent::Error(ComponentError::Internal(
            anyhow::anyhow!("run_concurrent failed: {e}"),
        )),
    };
    let _ = event_tx.send(terminal).await;
}
```

**Step 4: Verify it compiles**

Run: `cargo check`
Expected: success (warning about unused `CallToolStreaming` is OK)

**Step 5: Commit**

```bash
git add src/runtime.rs
git commit -m "feat: add ForwardingConsumer and CallToolStreaming for SSE"
```

---

### Task 3: Add SSE response path to call_tool handler

**Files:**
- Modify: `src/http.rs`

**Step 1: Add imports**

Update the axum import block (lines 1-7) to add `HeaderMap` and SSE types:

```rust
use axum::{
    extract::{Path, Request, State},
    http::{Method, StatusCode, HeaderMap},
    response::{IntoResponse, sse::{Event, Sse}},
    routing::get,
    Json, Router,
};
```

Add after `use std::sync::Arc;`:

```rust
use tokio_stream::wrappers::ReceiverStream;
```

**Step 2: Add SSE event formatting helper**

After the `encode_config` function (line 154), add:

```rust
/// Format an SseEvent as an axum SSE Event. Returns None for terminal events
/// that should not be sent (errors are formatted, Done becomes the done event).
fn sse_event_to_axum(event: runtime::SseEvent) -> Option<Event> {
    match event {
        runtime::SseEvent::Stream(stream_event) => match stream_event {
            runtime::act::core::types::StreamEvent::Content(part) => {
                let data = cbor::cbor_to_json(&part.data).unwrap_or_else(|_| {
                    use base64::Engine as _;
                    serde_json::Value::String(
                        base64::engine::general_purpose::STANDARD.encode(&part.data),
                    )
                });
                let json = serde_json::json!({
                    "data": data,
                    "mime_type": part.mime_type,
                });
                Some(Event::default().event("content").json_data(json).unwrap())
            }
            runtime::act::core::types::StreamEvent::Error(err) => {
                let message = localized_to_string(&err.message);
                tracing::warn!(kind = %err.kind, %message, "Stream error (SSE)");
                let json = serde_json::json!({
                    "kind": err.kind,
                    "message": message,
                });
                Some(Event::default().event("error").json_data(json).unwrap())
            }
        },
        runtime::SseEvent::Done => {
            Some(Event::default().event("done").json_data(serde_json::json!({})).unwrap())
        }
        runtime::SseEvent::Error(e) => {
            let (kind, message) = match e {
                runtime::ComponentError::Tool(ref te) => {
                    (te.kind.clone(), localized_to_string(&te.message))
                }
                runtime::ComponentError::Internal(ref e) => {
                    ("std:internal".to_string(), e.to_string())
                }
            };
            Some(Event::default().event("error").json_data(serde_json::json!({"kind": kind, "message": message})).unwrap())
        }
    }
}
```

**Step 3: Refactor call_tool to branch on Accept header**

Replace the entire `call_tool` function (lines 233-329) with:

```rust
async fn call_tool(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CallToolRequest>,
) -> axum::response::Response {
    let wants_sse = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("text/event-stream"));

    let cbor_config = match encode_config(&body.config) {
        Ok(c) => c,
        Err(status) => return status.into_response(),
    };

    let cbor_args = match cbor::json_to_cbor(&body.arguments) {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let tool_call = runtime::act::core::types::ToolCall {
        id: body.id.clone(),
        name,
        arguments: cbor_args,
        metadata: Vec::new(),
    };

    if wants_sse {
        call_tool_sse(state, tool_call, cbor_config).await
    } else {
        call_tool_buffered(state, body.id, tool_call, cbor_config).await
    }
}
```

**Step 4: Extract buffered path into `call_tool_buffered`**

Add after `call_tool`. This is the existing buffered logic moved to a separate function:

```rust
async fn call_tool_buffered(
    state: Arc<AppState>,
    id: String,
    tool_call: runtime::act::core::types::ToolCall,
    cbor_config: Option<Vec<u8>>,
) -> axum::response::Response {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::CallTool {
        config: cbor_config,
        call: tool_call,
        reply: reply_tx,
    };

    if state.component.send(request).await.is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                kind: "std:internal".to_string(),
                message: "component actor unavailable".to_string(),
            }),
        )
            .into_response();
    }

    match reply_rx.await {
        Ok(Ok(result)) => {
            let content: Vec<ContentPart> = result
                .events
                .iter()
                .filter_map(|event| match event {
                    runtime::act::core::types::StreamEvent::Content(part) => {
                        let data = cbor::cbor_to_json(&part.data).unwrap_or_else(|_| {
                            use base64::Engine as _;
                            serde_json::Value::String(
                                base64::engine::general_purpose::STANDARD.encode(&part.data),
                            )
                        });
                        Some(ContentPart {
                            data,
                            mime_type: part.mime_type.clone(),
                        })
                    }
                    runtime::act::core::types::StreamEvent::Error(_) => None,
                })
                .collect();

            let stream_error = result.events.iter().find_map(|event| match event {
                runtime::act::core::types::StreamEvent::Error(e) => Some(e),
                _ => None,
            });

            if let Some(err) = stream_error {
                let message = localized_to_string(&err.message);
                tracing::warn!(kind = %err.kind, %message, "Stream error");
                return (
                    error_kind_to_status(&err.kind),
                    Json(ErrorResponse {
                        kind: err.kind.clone(),
                        message: localized_to_string(&err.message),
                    }),
                )
                    .into_response();
            }

            Json(CallToolResponse {
                id,
                content,
                metadata: metadata_to_json(&result.metadata),
            })
            .into_response()
        }
        Ok(Err(e)) => component_error_response(e),
        Err(_) => component_error_response(runtime::ComponentError::Internal(
            anyhow::anyhow!("component actor dropped reply"),
        )),
    }
}
```

**Step 5: Add SSE path as `call_tool_sse`**

Add after `call_tool_buffered`:

```rust
async fn call_tool_sse(
    state: Arc<AppState>,
    tool_call: runtime::act::core::types::ToolCall,
    cbor_config: Option<Vec<u8>>,
) -> axum::response::Response {
    tracing::debug!(tool = %tool_call.name, "SSE streaming requested");

    let (event_tx, event_rx) = tokio::sync::mpsc::channel(32);

    let request = runtime::ComponentRequest::CallToolStreaming {
        config: cbor_config,
        call: tool_call,
        event_tx,
    };

    if state.component.send(request).await.is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                kind: "std:internal".to_string(),
                message: "component actor unavailable".to_string(),
            }),
        )
            .into_response();
    }

    let stream = ReceiverStream::new(event_rx);
    let sse_stream = tokio_stream::StreamExt::filter_map(stream, |event| {
        sse_event_to_axum(event).map(|e| Ok::<_, std::convert::Infallible>(e))
    });

    Sse::new(sse_stream).into_response()
}
```

**Step 6: Verify it compiles**

Run: `cargo check`
Expected: success

**Step 7: Commit**

```bash
git add src/http.rs
git commit -m "feat: SSE streaming response for call_tool endpoint"
```

---

### Task 4: Test SSE with hello-world

**Step 1: Build hello-world component** (if not already built)

```bash
cd examples/hello-world && cargo build --target wasm32-wasip2 --release && cd ../..
```

**Step 2: Start the server**

```bash
cargo run -- serve examples/hello-world/target/wasm32-wasip2/release/hello_world.wasm --port 3010
```

**Step 3: Test buffered (existing behavior still works)**

```bash
curl -s -X POST http://127.0.0.1:3010/tools/greet \
  -H 'Content-Type: application/json' \
  -d '{"id":"t1","arguments":{"name":"Alice"}}'
```

Expected: `{"id":"t1","content":[{"data":"Hello, Alice!","mime_type":"text/plain"}]}`

**Step 4: Test SSE**

```bash
curl -s -N -X POST http://127.0.0.1:3010/tools/greet \
  -H 'Content-Type: application/json' \
  -H 'Accept: text/event-stream' \
  -d '{"id":"t1","arguments":{"name":"Alice"}}'
```

Expected output (SSE format):
```
event: content
data: {"data":"Hello, Alice!","mime_type":"text/plain"}

event: done
data: {}
```

**Step 5: Test SSE error case**

```bash
curl -s -N -X POST http://127.0.0.1:3010/tools/nonexistent \
  -H 'Content-Type: application/json' \
  -H 'Accept: text/event-stream' \
  -d '{"id":"t2","arguments":{}}'
```

Expected: `event: error` with `std:not-found` kind, then stream closes.

**Step 6: Stop server and commit any fixes if needed**

---

### Task 5: Create counter example component

**Files:**
- Create: `examples/counter/Cargo.toml`
- Create: `examples/counter/src/lib.rs`
- Create: `examples/counter/rust-toolchain.toml`
- Copy: `examples/counter/wit/` (from hello-world)

**Step 1: Create project structure**

```bash
mkdir -p examples/counter/src
cp -r examples/hello-world/wit examples/counter/wit
cp examples/hello-world/rust-toolchain.toml examples/counter/rust-toolchain.toml
```

**Step 2: Create `examples/counter/Cargo.toml`**

```toml
[package]
name = "counter"
version = "0.1.0"
edition = "2024"

[dependencies]
wit-bindgen = { version = "0.53", features = ["async-spawn"] }
ciborium = "0.2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"

[lib]
crate-type = ["cdylib"]
```

**Step 3: Create `examples/counter/src/lib.rs`**

```rust
wit_bindgen::generate!({
    path: "wit",
    world: "act-world",
});

use exports::act::core::tool_provider::Guest;
use act::core::types::*;

fn respond(events: Vec<StreamEvent>) -> wit_bindgen::rt::async_support::StreamReader<StreamEvent> {
    let (mut writer, reader) = wit_stream::new::<StreamEvent>();
    wit_bindgen::spawn(async move {
        writer.write_all(events).await;
    });
    reader
}

fn to_cbor(value: &serde_json::Value) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).unwrap();
    buf
}

fn from_cbor(bytes: &[u8]) -> serde_json::Value {
    ciborium::from_reader(bytes).unwrap_or_default()
}

struct Counter;

export!(Counter);

impl Guest for Counter {
    fn get_info() -> ComponentInfo {
        ComponentInfo {
            name: "counter".to_string(),
            version: "0.1.0".to_string(),
            default_language: "en".to_string(),
            description: vec![("en".to_string(), "A streaming counter ACT component".to_string())],
            capabilities: vec![],
            metadata: vec![],
        }
    }

    fn get_config_schema() -> Option<String> {
        None
    }

    async fn list_tools(
        _config: Option<Vec<u8>>,
    ) -> Result<ListToolsResponse, ToolError> {
        Ok(ListToolsResponse {
            metadata: vec![],
            tools: vec![ToolDefinition {
                name: "count".to_string(),
                description: vec![("en".to_string(), "Count from 1 to N, emitting each number as a separate event".to_string())],
                parameters_schema: r#"{"type":"object","properties":{"n":{"type":"integer","description":"Number to count to (default 5)"}}}"#.to_string(),
                metadata: vec![
                    ("std:streaming".to_string(), to_cbor(&serde_json::Value::Bool(true))),
                ],
            }],
        })
    }

    async fn call_tool(
        _config: Option<Vec<u8>>,
        call: ToolCall,
    ) -> CallResponse {
        let events = match call.name.as_str() {
            "count" => {
                let args = from_cbor(&call.arguments);
                let n = args.get("n").and_then(|v| v.as_u64()).unwrap_or(5) as usize;

                (1..=n)
                    .map(|i| {
                        StreamEvent::Content(ContentPart {
                            data: to_cbor(&serde_json::Value::String(format!("Count: {i}"))),
                            mime_type: Some("text/plain".to_string()),
                            metadata: vec![
                                ("std:progress".to_string(), to_cbor(&serde_json::json!(i))),
                                ("std:progress-total".to_string(), to_cbor(&serde_json::json!(n))),
                            ],
                        })
                    })
                    .collect()
            }
            other => vec![StreamEvent::Error(ToolError {
                kind: "std:not-found".to_string(),
                message: vec![("en".to_string(), format!("Tool '{other}' not found"))],
                metadata: vec![],
            })],
        };

        CallResponse {
            metadata: vec![],
            body: respond(events),
        }
    }
}
```

**Step 4: Build the counter component**

```bash
cd examples/counter && cargo build --target wasm32-wasip2 --release && cd ../..
```

Expected: success

**Step 5: Commit**

```bash
git add examples/counter/
git commit -m "feat: counter example component with streaming support"
```

---

### Task 6: End-to-end SSE test with counter

**Step 1: Start server with counter component**

```bash
cargo run -- serve examples/counter/target/wasm32-wasip2/release/counter.wasm --port 3011
```

**Step 2: Test buffered mode**

```bash
curl -s -X POST http://127.0.0.1:3011/tools/count \
  -H 'Content-Type: application/json' \
  -d '{"id":"t1","arguments":{"n":3}}'
```

Expected: JSON response with 3 content parts.

**Step 3: Test SSE streaming**

```bash
curl -s -N -X POST http://127.0.0.1:3011/tools/count \
  -H 'Content-Type: application/json' \
  -H 'Accept: text/event-stream' \
  -d '{"id":"t1","arguments":{"n":3}}'
```

Expected: 3 `event: content` lines followed by `event: done`.

**Step 4: Test list-tools shows streaming metadata**

```bash
curl -s http://127.0.0.1:3011/tools
```

Expected: tool `count` has `metadata` with `std:streaming: true`.

**Step 5: Test cancellation** (client disconnect)

```bash
timeout 1 curl -s -N -X POST http://127.0.0.1:3011/tools/count \
  -H 'Content-Type: application/json' \
  -H 'Accept: text/event-stream' \
  -d '{"id":"t1","arguments":{"n":1000}}'
```

Expected: partial output, server log should not show errors.

**Step 6: Stop server, commit any fixes**

```bash
git add -A && git commit -m "fix: SSE streaming adjustments from integration testing"
```
