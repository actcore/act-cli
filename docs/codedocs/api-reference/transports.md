---
title: "API Reference: transports"
description: "Public Rust items in act-cli/src/http.rs and act-cli/src/mcp.rs that adapt the runtime actor to ACT-HTTP and MCP."
---

Source files: `act-cli/src/http.rs` and `act-cli/src/mcp.rs`

These modules are transport adapters. They do not instantiate components themselves; they take the prepared runtime state and expose it through HTTP or JSON-RPC over stdio.

## ACT-HTTP

```rust
pub struct AppState {
    pub info: act_types::ComponentInfo,
    pub component: runtime::ComponentHandle,
    pub metadata: Metadata,
}
```

### `create_router`

```rust
pub fn create_router(state: Arc<AppState>) -> Router
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `state` | `Arc<AppState>` | — | Shared component info, actor handle, and default metadata. |

Returns an Axum router with four routes:

| Method | Path | Behavior |
|--------|------|----------|
| `GET` | `/info` | Returns `ComponentInfo`. |
| `POST` | `/metadata-schema` | Returns metadata schema or `204 No Content`. |
| `POST` or `QUERY` | `/tools` | Lists tools with optional metadata override. |
| `POST` or `QUERY` | `/tools/{name}` | Calls a tool and optionally streams SSE when `Accept: text/event-stream` is present. |

Example:

```rust
let state = std::sync::Arc::new(crate::http::AppState {
    info,
    component: handle,
    metadata,
});
let router = crate::http::create_router(state);
```

## MCP

### `run_stdio`

```rust
pub async fn run_stdio(
    info: runtime::ComponentInfo,
    handle: runtime::ComponentHandle,
    metadata: runtime::Metadata,
) -> Result<()>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `info` | `runtime::ComponentInfo` | — | Component info used for `initialize` responses. |
| `handle` | `runtime::ComponentHandle` | — | Actor handle used for metadata schema, list-tools, and call-tool requests. |
| `metadata` | `runtime::Metadata` | — | Default metadata merged into each request. |

Runs a line-oriented JSON-RPC server over stdin and stdout. Supported methods are:

| Method | Behavior |
|--------|----------|
| `initialize` | Returns protocol version, server info, and tool capability declaration. |
| `notifications/initialized` | Ignored. |
| `ping` | Returns an empty success object. |
| `tools/list` | Lists tools and injects `_metadata` into the input schema when metadata schema is available. |
| `tools/call` | Executes a tool and maps ACT content parts into MCP content items. |

Example request and response:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}
```

```json
{"jsonrpc":"2.0","id":1,"result":{"tools":[...]}}
```

## Practical Notes

- Both adapters convert runtime errors into transport-native error shapes rather than exposing `ComponentError` directly.
- ACT-HTTP exposes streaming through SSE, while MCP currently returns buffered tool results.
- `mcp.rs` injects `_metadata` into tool schemas so MCP clients can pass per-call metadata overrides even though the ACT tool schema does not natively include that property.

Related pages: [Component Host Lifecycle](/docs/component-host-lifecycle) and [Guides: Serving Components](/docs/guides/serving-components).
