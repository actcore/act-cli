# MCP stdio Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add MCP stdio transport to `act-host` so ACT components work as MCP servers.

**Architecture:** New `src/mcp.rs` module reads JSON-RPC 2.0 from stdin, dispatches to existing `runtime.rs` actor, writes responses to stdout. New `Mcp` CLI subcommand reuses engine/linker/component loading from `serve`.

**Tech Stack:** Rust, serde_json (JSON-RPC), tokio BufReader (stdin), existing runtime actor

---

### Task 1: Add Mcp CLI subcommand

**Files:**
- Modify: `src/main.rs`

**Step 1: Add Mcp variant to Cli enum**

```rust
/// Load a .wasm component and serve it as an MCP server over stdio
Mcp {
    /// Path to the .wasm component file
    component: PathBuf,

    /// JSON config to pass to the component
    #[arg(long)]
    config: Option<String>,

    /// Path to a JSON config file
    #[arg(long)]
    config_file: Option<PathBuf>,
},
```

**Step 2: Add match arm in main**

```rust
Cli::Mcp {
    component,
    config,
    config_file,
} => mcp_serve(component, config, config_file).await,
```

**Step 3: Add stub mcp_serve function**

```rust
async fn mcp_serve(
    component_path: PathBuf,
    config: Option<String>,
    config_file: Option<PathBuf>,
) -> Result<()> {
    // Resolve config
    let config_json: Option<serde_json::Value> = match (config, config_file) {
        (Some(json_str), _) => Some(serde_json::from_str(&json_str).context("invalid --config JSON")?),
        (_, Some(path)) => {
            let contents = std::fs::read_to_string(&path).context("reading config file")?;
            Some(serde_json::from_str(&contents).context("invalid config file JSON")?)
        }
        (None, None) => None,
    };
    let cbor_config = config_json
        .map(|v| cbor::json_to_cbor(&v))
        .transpose()
        .context("encoding config as CBOR")?;

    // Load component (same as serve)
    let engine = runtime::create_engine()?;
    let component = runtime::load_component(&engine, &component_path)?;
    let linker = runtime::create_linker(&engine)?;
    let (instance, component_info, _config_schema, store) =
        runtime::instantiate_component(&engine, &component, &linker).await?;

    tracing::info!(
        name = %component_info.name,
        version = %component_info.version,
        "Loaded component (MCP stdio)"
    );

    let component_handle = runtime::spawn_component_actor(instance, store);

    mcp::run_stdio(component_info, component_handle, cbor_config).await
}
```

**Step 4: Add `mod mcp;` to main.rs and create empty `src/mcp.rs`**

Create `src/mcp.rs` with a stub:

```rust
use crate::runtime;
use anyhow::Result;

pub async fn run_stdio(
    _info: runtime::act::core::types::ComponentInfo,
    _handle: runtime::ComponentHandle,
    _config: Option<Vec<u8>>,
) -> Result<()> {
    todo!("MCP stdio loop")
}
```

**Step 5: Verify it compiles**

Run: `cargo check`

**Step 6: Commit**

```bash
git add src/main.rs src/mcp.rs
git commit -m "feat: add Mcp CLI subcommand and mcp module stub"
```

---

### Task 2: JSON-RPC types and parsing

**Files:**
- Modify: `src/mcp.rs`

**Step 1: Add JSON-RPC request/response types**

```rust
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

#[derive(Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcResponse {
    fn success(id: Value, result: Value) -> Self {
        Self { jsonrpc: "2.0".to_string(), id, result: Some(result), error: None }
    }
    fn error(id: Value, code: i32, message: String) -> Self {
        Self { jsonrpc: "2.0".to_string(), id, result: None, error: Some(JsonRpcError { code, message, data: None }) }
    }
}
```

**Step 2: Verify it compiles**

Run: `cargo check`

**Step 3: Commit**

```bash
git add src/mcp.rs
git commit -m "feat: JSON-RPC types for MCP stdio"
```

---

### Task 3: MCP stdio loop with initialize

**Files:**
- Modify: `src/mcp.rs`

**Step 1: Implement run_stdio with initialize handling**

Replace the `run_stdio` stub:

```rust
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub async fn run_stdio(
    info: runtime::act::core::types::ComponentInfo,
    handle: runtime::ComponentHandle,
    config: Option<Vec<u8>>,
) -> Result<()> {
    let stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();
    let mut lines = stdin.lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = JsonRpcResponse::error(
                    Value::Null,
                    -32700,
                    format!("Parse error: {e}"),
                );
                write_response(&mut stdout, &resp).await?;
                continue;
            }
        };

        let response = handle_request(&request, &info, &handle, &config).await;
        if let Some(resp) = response {
            write_response(&mut stdout, &resp).await?;
        }
    }

    Ok(())
}

async fn write_response(
    stdout: &mut tokio::io::Stdout,
    resp: &JsonRpcResponse,
) -> Result<()> {
    let json = serde_json::to_string(resp)?;
    stdout.write_all(json.as_bytes()).await?;
    stdout.write_all(b"\n").await?;
    stdout.flush().await?;
    Ok(())
}

async fn handle_request(
    req: &JsonRpcRequest,
    info: &runtime::act::core::types::ComponentInfo,
    handle: &runtime::ComponentHandle,
    config: &Option<Vec<u8>>,
) -> Option<JsonRpcResponse> {
    let id = req.id.clone().unwrap_or(Value::Null);

    match req.method.as_str() {
        "initialize" => Some(handle_initialize(id, info)),
        "notifications/initialized" => None, // no response for notifications
        "ping" => Some(JsonRpcResponse::success(id, serde_json::json!({}))),
        "tools/list" => Some(handle_tools_list(id, handle, config).await),
        "tools/call" => Some(handle_tools_call(id, req, handle, config).await),
        _ => {
            if req.method.starts_with("notifications/") {
                None // ignore unknown notifications
            } else {
                Some(JsonRpcResponse::error(id, -32601, format!("Method not found: {}", req.method)))
            }
        }
    }
}

fn handle_initialize(
    id: Value,
    info: &runtime::act::core::types::ComponentInfo,
) -> JsonRpcResponse {
    let result = serde_json::json!({
        "protocolVersion": "2025-11-25",
        "serverInfo": {
            "name": info.name,
            "version": info.version,
        },
        "capabilities": {
            "tools": {},
        },
    });
    JsonRpcResponse::success(id, result)
}
```

Add stubs for tools/list and tools/call:

```rust
async fn handle_tools_list(
    id: Value,
    _handle: &runtime::ComponentHandle,
    _config: &Option<Vec<u8>>,
) -> JsonRpcResponse {
    JsonRpcResponse::error(id, -32603, "not implemented".to_string())
}

async fn handle_tools_call(
    id: Value,
    _req: &JsonRpcRequest,
    _handle: &runtime::ComponentHandle,
    _config: &Option<Vec<u8>>,
) -> JsonRpcResponse {
    JsonRpcResponse::error(id, -32603, "not implemented".to_string())
}
```

**Step 2: Verify it compiles**

Run: `cargo check`

**Step 3: Commit**

```bash
git add src/mcp.rs
git commit -m "feat: MCP stdio loop with initialize and ping"
```

---

### Task 4: Implement tools/list

**Files:**
- Modify: `src/mcp.rs`

**Step 1: Implement handle_tools_list**

Replace the stub:

```rust
use crate::cbor;

async fn handle_tools_list(
    id: Value,
    handle: &runtime::ComponentHandle,
    config: &Option<Vec<u8>>,
) -> JsonRpcResponse {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::ListTools {
        config: config.clone(),
        reply: reply_tx,
    };

    if handle.send(request).await.is_err() {
        return JsonRpcResponse::error(id, -32603, "component actor unavailable".to_string());
    }

    match reply_rx.await {
        Ok(Ok(list_response)) => {
            let tools: Vec<Value> = list_response.tools.iter().map(|td| {
                let description = td.description.first()
                    .map(|(_, text)| text.clone())
                    .unwrap_or_default();
                let input_schema: Value = serde_json::from_str(&td.parameters_schema)
                    .unwrap_or(serde_json::json!({"type": "object"}));

                let mut tool = serde_json::json!({
                    "name": td.name,
                    "description": description,
                    "inputSchema": input_schema,
                });

                // Map annotation metadata
                let annotations = build_annotations(&td.metadata);
                if !annotations.is_empty() {
                    tool.as_object_mut().unwrap().insert(
                        "annotations".to_string(),
                        serde_json::json!(annotations),
                    );
                }

                tool
            }).collect();

            JsonRpcResponse::success(id, serde_json::json!({ "tools": tools }))
        }
        Ok(Err(e)) => component_error_to_jsonrpc(id, e),
        Err(_) => JsonRpcResponse::error(id, -32603, "component actor dropped reply".to_string()),
    }
}

fn build_annotations(metadata: &[(String, Vec<u8>)]) -> serde_json::Map<String, Value> {
    let mut annotations = serde_json::Map::new();
    for (key, cbor_bytes) in metadata {
        let value = cbor::cbor_to_json(cbor_bytes).ok();
        match key.as_str() {
            "std:read-only" => {
                if let Some(v) = value { annotations.insert("readOnlyHint".to_string(), v); }
            }
            "std:idempotent" => {
                if let Some(v) = value { annotations.insert("idempotentHint".to_string(), v); }
            }
            "std:destructive" => {
                if let Some(v) = value { annotations.insert("destructiveHint".to_string(), v); }
            }
            _ => {}
        }
    }
    annotations
}

fn error_kind_to_jsonrpc_code(kind: &str) -> i32 {
    match kind {
        "std:not-found" => -32601,
        "std:invalid-args" => -32602,
        "std:internal" => -32603,
        _ => -32000,
    }
}

fn component_error_to_jsonrpc(id: Value, err: runtime::ComponentError) -> JsonRpcResponse {
    match err {
        runtime::ComponentError::Tool(te) => {
            let message = te.message.first().map(|(_, t)| t.clone()).unwrap_or_default();
            JsonRpcResponse::error(id, error_kind_to_jsonrpc_code(&te.kind), message)
        }
        runtime::ComponentError::Internal(e) => {
            JsonRpcResponse::error(id, -32603, e.to_string())
        }
    }
}
```

**Step 2: Verify it compiles**

Run: `cargo check`

**Step 3: Commit**

```bash
git add src/mcp.rs
git commit -m "feat: MCP tools/list with annotation mapping"
```

---

### Task 5: Implement tools/call

**Files:**
- Modify: `src/mcp.rs`

**Step 1: Implement handle_tools_call**

Replace the stub. This collects all stream events (buffered), maps content per ACT-MCP.md §2.2:

```rust
async fn handle_tools_call(
    id: Value,
    req: &JsonRpcRequest,
    handle: &runtime::ComponentHandle,
    config: &Option<Vec<u8>>,
) -> JsonRpcResponse {
    let params = req.params.as_ref();
    let tool_name = params
        .and_then(|p| p.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let arguments = params
        .and_then(|p| p.get("arguments"))
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let cbor_args = match cbor::json_to_cbor(&arguments) {
        Ok(bytes) => bytes,
        Err(_) => return JsonRpcResponse::error(id, -32602, "invalid arguments".to_string()),
    };

    let tool_call = runtime::act::core::types::ToolCall {
        id: id.to_string(),
        name: tool_name.to_string(),
        arguments: cbor_args,
        metadata: Vec::new(),
    };

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::CallTool {
        config: config.clone(),
        call: tool_call,
        reply: reply_tx,
    };

    if handle.send(request).await.is_err() {
        return JsonRpcResponse::error(id, -32603, "component actor unavailable".to_string());
    }

    match reply_rx.await {
        Ok(Ok(result)) => {
            let mut content = Vec::new();
            let mut is_error = false;

            for event in &result.events {
                match event {
                    runtime::act::core::types::StreamEvent::Content(part) => {
                        content.push(map_content_part(part));
                    }
                    runtime::act::core::types::StreamEvent::Error(err) => {
                        is_error = true;
                        let message = err.message.first()
                            .map(|(_, t)| t.clone())
                            .unwrap_or_default();
                        content.push(serde_json::json!({
                            "type": "text",
                            "text": message,
                        }));
                    }
                }
            }

            let mut result = serde_json::json!({ "content": content });
            if is_error {
                result.as_object_mut().unwrap().insert("isError".to_string(), Value::Bool(true));
            }
            JsonRpcResponse::success(id, result)
        }
        Ok(Err(e)) => component_error_to_jsonrpc(id, e),
        Err(_) => JsonRpcResponse::error(id, -32603, "component actor dropped reply".to_string()),
    }
}

fn map_content_part(part: &runtime::act::core::types::ContentPart) -> Value {
    let mime = part.mime_type.as_deref().unwrap_or("");

    if mime.starts_with("text/") {
        // text/* → {"type":"text","text":"<data as UTF-8>"}
        let text = match cbor::cbor_to_json(&part.data) {
            Ok(Value::String(s)) => s,
            Ok(v) => v.to_string(),
            Err(_) => String::from_utf8_lossy(&part.data).to_string(),
        };
        serde_json::json!({ "type": "text", "text": text })
    } else if mime.starts_with("image/") {
        // image/* → {"type":"image","data":"<base64>","mimeType":"<mime>"}
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&part.data);
        serde_json::json!({ "type": "image", "data": b64, "mimeType": mime })
    } else {
        // absent or other → decode CBOR to JSON, serialize as text
        let text = match cbor::cbor_to_json(&part.data) {
            Ok(Value::String(s)) => s,
            Ok(v) => serde_json::to_string(&v).unwrap_or_default(),
            Err(_) => {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode(&part.data)
            }
        };
        serde_json::json!({ "type": "text", "text": text })
    }
}
```

**Step 2: Verify it compiles**

Run: `cargo check`

**Step 3: Commit**

```bash
git add src/mcp.rs
git commit -m "feat: MCP tools/call with content mapping"
```

---

### Task 6: End-to-end test with hello-world

**Step 1: Build host**

```bash
cargo build --release
```

**Step 2: Test initialize + tools/list + tools/call via stdio**

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"greet","arguments":{"name":"World"}}}
{"jsonrpc":"2.0","id":4,"method":"ping"}' | cargo run --release -- mcp examples/hello-world/target/wasm32-wasip2/release/hello_world.wasm
```

Expected output (one JSON line per response, no response for notifications/initialized):
```
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","serverInfo":{"name":"hello-world","version":"0.1.0"},"capabilities":{"tools":{}}}}
{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"greet","description":"Say hello to someone","inputSchema":{"type":"object","properties":{"name":{"type":"string","description":"Name to greet"}},"required":["name"]}}]}}
{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"Hello, World!"}]}}
{"jsonrpc":"2.0","id":4,"result":{}}
```

**Step 3: Test error case**

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nonexistent","arguments":{}}}' | cargo run --release -- mcp examples/hello-world/target/wasm32-wasip2/release/hello_world.wasm
```

Expected: tools/call returns `{"content":[{"type":"text","text":"Tool 'nonexistent' not found"}],"isError":true}`.

**Step 4: Test with counter (streaming collected)**

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"count","arguments":{"n":3}}}' | cargo run --release -- mcp examples/counter/target/wasm32-wasip2/release/counter.wasm
```

Expected: 3 content parts in the response.

**Step 5: Commit any fixes**
