# ACT Reference Host Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Rust binary that loads a single `.wasm` ACT component and exposes it as an ACT-HTTP server with JSON endpoints.

**Architecture:** Cargo workspace with host binary (`src/`) and calculator example component (`examples/calculator/`). HTTP request → axum handler → JSON→dCBOR → wasmtime component call → dCBOR→JSON → HTTP response. wasmtime with `component-model-async` for WASI P3 async/stream support.

**Tech Stack:** Rust, wasmtime (component-model-async), axum, ciborium, serde/serde_json, clap, tokio, cargo-component

---

### Task 1: Project Scaffold — Cargo.toml and Module Stubs

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs`
- Create: `src/runtime.rs`
- Create: `src/http.rs`
- Create: `src/cbor.rs`

**Step 1: Create Cargo.toml**

```toml
[package]
name = "act-host"
version = "0.1.0"
edition = "2024"

[dependencies]
anyhow = "1"
axum = "0.8"
ciborium = "0.2"
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["full"] }
wasmtime = { version = "33", features = ["component-model", "component-model-async"] }
wasmtime-wasi = { version = "33" }
```

Note: wasmtime version may need adjustment based on what's available with `component-model-async` support. Start with 33, adjust if needed.

**Step 2: Create module stubs**

`src/main.rs`:
```rust
mod cbor;
mod http;
mod runtime;

fn main() {
    println!("act-host stub");
}
```

`src/cbor.rs`:
```rust
// JSON ↔ dCBOR conversion utilities
```

`src/http.rs`:
```rust
// axum HTTP handlers
```

`src/runtime.rs`:
```rust
// wasmtime component instantiation
```

**Step 3: Verify it compiles**

Run: `cd /mnt/devenv/workspace/act/act-host && cargo build`
Expected: Compiles successfully (may take a while for wasmtime download)

**Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock src/
git commit -m "feat: project scaffold with dependencies and module stubs"
```

---

### Task 2: CBOR Utilities — JSON↔dCBOR Conversion

**Files:**
- Modify: `src/cbor.rs`

**Step 1: Write failing test**

Add to `src/cbor.rs`:
```rust
use anyhow::Result;

/// Convert a JSON value to deterministically encoded CBOR bytes.
pub fn json_to_cbor(value: &serde_json::Value) -> Result<Vec<u8>> {
    todo!()
}

/// Convert CBOR bytes to a JSON value.
pub fn cbor_to_json(bytes: &[u8]) -> Result<serde_json::Value> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn roundtrip_object() {
        let input = json!({"a": 2, "b": 3});
        let cbor = json_to_cbor(&input).unwrap();
        let output = cbor_to_json(&cbor).unwrap();
        assert_eq!(input, output);
    }

    #[test]
    fn roundtrip_nested() {
        let input = json!({"config": {"api_key": "abc123"}, "values": [1, 2, 3]});
        let cbor = json_to_cbor(&input).unwrap();
        let output = cbor_to_json(&cbor).unwrap();
        assert_eq!(input, output);
    }

    #[test]
    fn roundtrip_null() {
        let input = json!(null);
        let cbor = json_to_cbor(&input).unwrap();
        let output = cbor_to_json(&cbor).unwrap();
        assert_eq!(input, output);
    }

    #[test]
    fn empty_bytes_is_error() {
        assert!(cbor_to_json(&[]).is_err());
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test cbor`
Expected: FAIL — `todo!()` panics

**Step 3: Implement conversion functions**

Replace the `todo!()` bodies:

```rust
use anyhow::{Context, Result};

/// Convert a JSON value to deterministically encoded CBOR bytes.
pub fn json_to_cbor(value: &serde_json::Value) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).context("failed to encode JSON value as CBOR")?;
    Ok(buf)
}

/// Convert CBOR bytes to a JSON value.
pub fn cbor_to_json(bytes: &[u8]) -> Result<serde_json::Value> {
    ciborium::from_reader(bytes).context("failed to decode CBOR bytes as JSON value")
}
```

Note: `ciborium` serializes `serde_json::Value` to CBOR and back. For true dCBOR (deterministic), ciborium's default encoding is sufficient for our reference implementation — keys are serialized in insertion order. Full dCBOR canonicalization (sorted keys) can be added later if needed.

**Step 4: Run tests to verify they pass**

Run: `cargo test cbor`
Expected: All 4 tests PASS

**Step 5: Commit**

```bash
git add src/cbor.rs
git commit -m "feat: JSON↔CBOR conversion utilities"
```

---

### Task 3: Wasmtime Runtime — Component Loading

This task sets up the wasmtime engine and component instantiation. Since we can't test against a real `.wasm` component yet (calculator is Task 7), we build the infrastructure and test it structurally.

**Files:**
- Modify: `src/runtime.rs`

**Step 1: Implement the runtime module**

```rust
use anyhow::{Context, Result};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{IoView, WasiCtx, WasiCtxBuilder, WasiView};

/// Host state passed into the wasmtime store.
pub struct HostState {
    wasi: WasiCtx,
    table: wasmtime::component::ResourceTable,
}

impl IoView for HostState {
    fn table(&mut self) -> &mut wasmtime::component::ResourceTable {
        &mut self.table
    }
}

impl WasiView for HostState {
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi
    }
}

/// Create a wasmtime engine with component-model-async enabled.
pub fn create_engine() -> Result<Engine> {
    let mut config = Config::new();
    config.async_support(true);
    config.wasm_component_model(true);
    config.wasm_component_model_async(true);
    Engine::new(&config).context("failed to create wasmtime engine")
}

/// Load a .wasm component from a file path.
pub fn load_component(engine: &Engine, path: &std::path::Path) -> Result<Component> {
    Component::from_file(engine, path)
        .with_context(|| format!("failed to load component from {}", path.display()))
}

/// Create a linker with WASI bindings.
pub fn create_linker(engine: &Engine) -> Result<Linker<HostState>> {
    let mut linker = Linker::new(engine);
    wasmtime_wasi::add_to_linker_async(&mut linker)
        .context("failed to add WASI to linker")?;
    Ok(linker)
}

/// Create a new store with WASI context.
pub fn create_store(engine: &Engine) -> Store<HostState> {
    let wasi = WasiCtxBuilder::new().build();
    let state = HostState {
        wasi,
        table: wasmtime::component::ResourceTable::new(),
    };
    Store::new(engine, state)
}
```

**Step 2: Verify it compiles**

Run: `cargo build`
Expected: Compiles. If wasmtime API has changed, adjust method names per compiler errors.

Note: The wasmtime component-model-async API is experimental and evolving rapidly. The exact API surface (method names, trait requirements) may differ from what's shown here. Use compiler errors to guide adjustments. Key things that may need adjustment:
- `Config::wasm_component_model_async` may not exist yet or may be named differently
- `IoView` and `WasiView` trait requirements may differ
- `add_to_linker_async` signature may vary
- `ResourceTable` may be in a different module path

If `component-model-async` is not available in the wasmtime version, fall back to synchronous component model and use `tokio::task::spawn_blocking` for component calls.

**Step 3: Commit**

```bash
git add src/runtime.rs
git commit -m "feat: wasmtime runtime with component-model-async"
```

---

### Task 4: HTTP Handlers — Axum Routes

**Files:**
- Modify: `src/http.rs`
- Modify: `src/main.rs` (import types)

**Step 1: Define shared app state and JSON types**

`src/http.rs`:
```rust
use axum::{
    extract::{Path, State},
    http::{Method, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ── JSON request/response types (matching ACT-HTTP spec) ──

#[derive(Serialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub default_language: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters_schema: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct ListToolsResponse {
    pub tools: Vec<ToolDefinition>,
}

#[derive(Deserialize)]
pub struct CallToolRequest {
    pub id: String,
    pub arguments: serde_json::Value,
    #[serde(default)]
    pub config: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct ContentPart {
    pub data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

#[derive(Serialize)]
pub struct CallToolResponse {
    pub id: String,
    pub content: Vec<ContentPart>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub kind: String,
    pub message: String,
}

#[derive(Deserialize)]
pub struct QueryToolsRequest {
    #[serde(default)]
    pub config: Option<serde_json::Value>,
}

// ── App state (will hold component handle) ──

pub struct AppState {
    pub info: ServerInfo,
    pub config_schema: Option<String>,
    // Component handle will be added in Task 6
}

// ── Handlers ──

async fn get_info(State(state): State<Arc<AppState>>) -> Json<ServerInfo> {
    // Clone the cached info
    Json(ServerInfo {
        name: state.info.name.clone(),
        version: state.info.version.clone(),
        description: state.info.description.clone(),
        default_language: state.info.default_language.clone(),
        metadata: state.info.metadata.clone(),
    })
}

async fn get_config_schema(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match &state.config_schema {
        Some(schema) => (
            StatusCode::OK,
            [("content-type", "application/json")],
            schema.clone(),
        )
            .into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

async fn get_tools(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
    // TODO: call component list-tools with config from X-ACT-Config header
    StatusCode::NOT_IMPLEMENTED.into_response()
}

async fn query_tools(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<QueryToolsRequest>,
) -> impl IntoResponse {
    // TODO: call component list-tools with config from body
    StatusCode::NOT_IMPLEMENTED.into_response()
}

async fn call_tool(
    State(_state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(_body): Json<CallToolRequest>,
) -> impl IntoResponse {
    // TODO: call component call-tool
    let _ = name;
    StatusCode::NOT_IMPLEMENTED.into_response()
}

// ── QUERY method support ──

fn query_method() -> Method {
    Method::from_bytes(b"QUERY").expect("QUERY is a valid method")
}

// ── Router ──

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/info", get(get_info))
        .route("/config-schema", get(get_config_schema))
        .route(
            "/tools",
            get(get_tools).on(axum::routing::MethodFilter::try_from(query_method()).unwrap_or(axum::routing::MethodFilter::all()), query_tools),
        )
        .route("/tools/{name}", axum::routing::post(call_tool))
        .with_state(state)
}
```

Note: The QUERY method routing in axum may need a different approach. `MethodFilter::try_from(Method)` may not accept custom methods. Alternative approaches:
- Use `axum::routing::on` with a custom `MethodFilter`
- Use a middleware that rewrites QUERY to POST for a specific path
- Use `any()` handler that checks the method manually

Adjust based on compiler feedback.

**Step 2: Verify it compiles**

Run: `cargo build`
Expected: Compiles. Fix any axum API issues (especially QUERY method routing).

**Step 3: Commit**

```bash
git add src/http.rs
git commit -m "feat: axum HTTP handlers with JSON types"
```

---

### Task 5: CLI with Clap

**Files:**
- Modify: `src/main.rs`

**Step 1: Implement CLI and server startup**

```rust
mod cbor;
mod http;
mod runtime;

use anyhow::{Context, Result};
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "act-host", about = "ACT Reference Host")]
enum Cli {
    /// Load a .wasm component and serve it as an ACT-HTTP server
    Serve {
        /// Path to the .wasm component file
        component: PathBuf,

        /// Host address to bind to
        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        /// Port to listen on
        #[arg(long, default_value_t = 3000)]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli {
        Cli::Serve {
            component,
            host,
            port,
        } => serve(component, &host, port).await,
    }
}

async fn serve(component_path: PathBuf, host: &str, port: u16) -> Result<()> {
    // 1. Create engine and load component
    let engine = runtime::create_engine()?;
    let component = runtime::load_component(&engine, &component_path)?;
    let linker = runtime::create_linker(&engine)?;
    let mut store = runtime::create_store(&engine);

    // 2. Instantiate and call get-info (cached)
    // TODO: Actually instantiate and call component — placeholder for now
    let _ = (&component, &linker, &mut store);

    let info = http::ServerInfo {
        name: "placeholder".to_string(),
        version: "0.0.0".to_string(),
        description: "Component loaded but not yet wired".to_string(),
        default_language: "en".to_string(),
        metadata: None,
    };

    let state = Arc::new(http::AppState {
        info,
        config_schema: None,
    });

    // 3. Start HTTP server
    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .context("invalid host:port")?;

    eprintln!("ACT host listening on http://{addr}");
    eprintln!("Component: {}", component_path.display());

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, http::create_router(state))
        .await
        .context("server error")?;

    Ok(())
}
```

**Step 2: Verify it compiles**

Run: `cargo build`
Expected: Compiles successfully

**Step 3: Test CLI help**

Run: `cargo run -- --help`
Expected: Shows usage with `serve` subcommand

Run: `cargo run -- serve --help`
Expected: Shows `component`, `--host`, `--port` options

**Step 4: Commit**

```bash
git add src/main.rs
git commit -m "feat: CLI with clap serve subcommand"
```

---

### Task 6: Wire Component Calls to HTTP Handlers

This is the integration task — connecting wasmtime component calls to the axum handlers. This requires WIT bindgen for the host side.

**Files:**
- Modify: `src/runtime.rs`
- Modify: `src/http.rs`
- Modify: `src/main.rs`
- Modify: `Cargo.toml`

**Step 1: Add WIT files to the project**

Copy the ACT WIT files into the project so wasmtime bindgen can use them:

```bash
mkdir -p /mnt/devenv/workspace/act/act-host/wit/deps
cp /mnt/devenv/workspace/act/act-spec/wit/act-core.wit /mnt/devenv/workspace/act/act-host/wit/
```

**Step 2: Generate host-side bindings**

Add to `src/runtime.rs`:

```rust
// Generate host-side bindings from the WIT
wasmtime::component::bindgen!({
    path: "wit",
    world: "act-world",
    async: true,
});
```

Note: The `bindgen!` macro generates types and an `ActWorld` struct with methods corresponding to the exported interfaces. The exact generated API depends on the wasmtime version. Common patterns:
- `ActWorld::instantiate_async(&mut store, &component, &linker)` — instantiate
- `act_world.tool_provider().call_get_info(&mut store)` — call get-info
- `act_world.tool_provider().call_list_tools(&mut store, config)` — call list-tools
- `act_world.tool_provider().call_call_tool(&mut store, config, call)` — call call-tool

Adjust based on what the macro actually generates. Use `cargo doc --document-private-items` or compiler errors to discover the generated API.

**Step 3: Update AppState to hold component handles**

The component instance, store, and linker need to be accessible from handlers. Since wasmtime `Store` is `!Send` in some configurations, we may need `tokio::task::spawn_blocking` or a dedicated task with a channel.

Recommended approach: wrap the component in an actor pattern — a dedicated tokio task holds the `Store` and receives requests via an `mpsc` channel.

```rust
// In runtime.rs — add a ComponentActor

use tokio::sync::{mpsc, oneshot};

pub enum ComponentRequest {
    GetInfo {
        reply: oneshot::Sender<anyhow::Result</* generated type */>>,
    },
    GetConfigSchema {
        reply: oneshot::Sender<anyhow::Result<Option<String>>>,
    },
    ListTools {
        config: Option<Vec<u8>>,
        reply: oneshot::Sender<anyhow::Result</* generated type */>>,
    },
    CallTool {
        config: Option<Vec<u8>>,
        call: /* generated tool-call type */,
        reply: oneshot::Sender<anyhow::Result</* generated call-response type */>>,
    },
}

pub type ComponentHandle = mpsc::Sender<ComponentRequest>;
```

The exact types depend on what `bindgen!` generates. This task requires iterative development — write code, compile, fix based on generated types.

**Step 4: Wire handlers to use ComponentHandle**

Update `AppState`:
```rust
pub struct AppState {
    pub info: ServerInfo,
    pub config_schema: Option<String>,
    pub component: ComponentHandle,
}
```

Update each handler to send requests through the channel and await responses.

**Step 5: Verify it compiles**

Run: `cargo build`
Expected: Compiles (WIT files must be valid, generated types must match)

**Step 6: Commit**

```bash
git add wit/ src/
git commit -m "feat: wire component calls to HTTP handlers via actor pattern"
```

---

### Task 7: Calculator Example Component

**Files:**
- Create: `examples/calculator/Cargo.toml`
- Create: `examples/calculator/src/lib.rs`
- Create: `examples/calculator/wit/` (symlink or copy of ACT WIT)

**Step 1: Set up cargo-component project**

Ensure `cargo-component` is installed:
```bash
cargo install cargo-component
```

Create `examples/calculator/Cargo.toml`:
```toml
[package]
name = "calculator"
version = "0.1.0"
edition = "2024"

[dependencies]
wit-bindgen = "0.41"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
ciborium = "0.2"

[lib]
crate-type = ["cdylib"]

[package.metadata.component]
package = "act:calculator"

[package.metadata.component.dependencies]
```

Note: The exact `cargo-component` configuration format may have changed. Adjust `[package.metadata.component]` section based on current cargo-component docs. The component needs to target `wasm32-wasip2` (or `wasm32-wasip1` adapted).

**Step 2: Copy/symlink WIT files**

```bash
mkdir -p examples/calculator/wit
cp wit/act-core.wit examples/calculator/wit/
```

**Step 3: Implement calculator component**

`examples/calculator/src/lib.rs`:
```rust
use wit_bindgen::generate;

generate!({
    path: "wit",
    world: "act-world",
});

struct Calculator;

impl Guest for Calculator {
    // Implement tool-provider interface
}

export!(Calculator);
```

The exact trait names and method signatures depend on what `wit_bindgen::generate!` produces. The implementation should:

1. `get_info()` → return component-info with name "calculator", version "0.1.0", default-language "en"
2. `get_config_schema()` → return `None` (no config needed)
3. `list_tools(config)` → return two tools:
   - `add`: parameters `{"type":"object","properties":{"a":{"type":"number"},"b":{"type":"number"}},"required":["a","b"]}`
   - `multiply`: same schema
4. `call_tool(config, call)` → decode CBOR arguments, compute result, return as CBOR content-part in stream

For `call_tool`, the calculator:
- Decodes `arguments` (CBOR bytes) into `{a: f64, b: f64}`
- Computes `a + b` or `a * b` based on `call.name`
- Encodes result as CBOR
- Returns a stream with one `content` event containing the CBOR result
- Returns `stream-event::error` with `std:not-found` for unknown tool names

**Step 4: Build the component**

```bash
cd examples/calculator && cargo component build --release
```

Expected: Produces `target/wasm32-wasip1/release/calculator.wasm` (or similar path)

**Step 5: Commit**

```bash
git add examples/calculator/
git commit -m "feat: calculator example component"
```

---

### Task 8: Integration — End-to-End Test

**Files:**
- Modify: `src/main.rs` (if needed for fixes)
- Modify: `src/http.rs` (if needed for fixes)
- Modify: `src/runtime.rs` (if needed for fixes)

**Step 1: Build calculator component**

```bash
cd examples/calculator && cargo component build --release
```

**Step 2: Start the host**

```bash
cargo run -- serve examples/calculator/target/wasm32-wasip1/release/calculator.wasm --port 8080
```

Expected: "ACT host listening on http://127.0.0.1:8080"

**Step 3: Test GET /info**

```bash
curl -s http://localhost:8080/info | jq .
```

Expected:
```json
{
  "name": "calculator",
  "version": "0.1.0",
  "description": "A simple calculator component",
  "default_language": "en"
}
```

**Step 4: Test GET /config-schema**

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/config-schema
```

Expected: `204`

**Step 5: Test GET /tools**

```bash
curl -s http://localhost:8080/tools | jq .
```

Expected:
```json
{
  "tools": [
    {
      "name": "add",
      "description": "Add two numbers",
      "parameters_schema": {
        "type": "object",
        "properties": {
          "a": { "type": "number" },
          "b": { "type": "number" }
        },
        "required": ["a", "b"]
      }
    },
    {
      "name": "multiply",
      "description": "Multiply two numbers",
      "parameters_schema": { "..." }
    }
  ]
}
```

**Step 6: Test POST /tools/add**

```bash
curl -s -X POST http://localhost:8080/tools/add \
  -H "Content-Type: application/json" \
  -d '{"id":"1","arguments":{"a":2,"b":3}}' | jq .
```

Expected:
```json
{
  "id": "1",
  "content": [
    { "data": "5", "mime_type": "application/json" }
  ]
}
```

**Step 7: Test POST /tools/multiply**

```bash
curl -s -X POST http://localhost:8080/tools/multiply \
  -H "Content-Type: application/json" \
  -d '{"id":"2","arguments":{"a":4,"b":5}}' | jq .
```

Expected: result `20`

**Step 8: Test POST /tools/unknown → 404**

```bash
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8080/tools/unknown \
  -H "Content-Type: application/json" \
  -d '{"id":"3","arguments":{}}'
```

Expected: `404`

**Step 9: Test QUERY /tools**

```bash
curl -s -X QUERY http://localhost:8080/tools \
  -H "Content-Type: application/json" \
  -d '{}' | jq .
```

Expected: Same response as GET /tools

**Step 10: Fix any issues found during testing**

If any endpoint returns unexpected results, fix the relevant handler or component code.

**Step 11: Commit fixes**

```bash
git add src/ examples/
git commit -m "fix: integration test fixes"
```

---

### Task 9: Error Handling Polish

**Files:**
- Modify: `src/http.rs`

**Step 1: Implement error kind to HTTP status mapping**

Add to `src/http.rs`:
```rust
fn error_kind_to_status(kind: &str) -> StatusCode {
    match kind {
        "std:not-found" => StatusCode::NOT_FOUND,
        "std:invalid-args" => StatusCode::UNPROCESSABLE_ENTITY,
        "std:timeout" => StatusCode::GATEWAY_TIMEOUT,
        "std:capability-denied" => StatusCode::FORBIDDEN,
        "std:internal" | _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
```

**Step 2: Update call_tool handler to return proper error responses**

The handler should catch `stream-event::error` from the component stream and return the appropriate HTTP status with `ErrorResponse` body.

**Step 3: Test error handling**

```bash
# Invalid arguments
curl -s -w "\n%{http_code}" -X POST http://localhost:8080/tools/add \
  -H "Content-Type: application/json" \
  -d '{"id":"1","arguments":{"a":"not a number"}}'
```

Expected: `422` with error body

**Step 4: Commit**

```bash
git add src/http.rs
git commit -m "feat: error kind to HTTP status mapping"
```

---

### Task 10: README and Final Cleanup

**Files:**
- Create: `README.md`

**Step 1: Write minimal README**

```markdown
# act-host

ACT Reference Host — loads a single `.wasm` ACT component and serves it as an ACT-HTTP server.

## Build

```bash
cargo build
```

## Build calculator example

```bash
cd examples/calculator
cargo component build --release
```

## Run

```bash
cargo run -- serve path/to/component.wasm
cargo run -- serve path/to/component.wasm --port 8080 --host 0.0.0.0
```

## Endpoints

- `GET /info` — component metadata
- `GET /config-schema` — config JSON Schema (or 204)
- `GET /tools` — list tools
- `QUERY /tools` — list tools (config in body)
- `POST /tools/{name}` — invoke a tool
```

**Step 2: Commit**

```bash
git add README.md
git commit -m "docs: README with build and usage instructions"
```
