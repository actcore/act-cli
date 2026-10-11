---
title: "API Reference: runtime core"
description: "Public Rust items in act-cli/src/runtime/mod.rs that create the Wasmtime engine, instantiate the component, and expose the actor API."
---

Source file: `act-cli/src/runtime/mod.rs`

This module is the runtime spine of `act-cli`. It exports the Wasmtime host state, the actor request types, and the helper functions that bootstrap a component instance.

## Re-exports

```rust
pub use bindings::*;
pub use act_types::ComponentInfo;
pub use act_types::Metadata;
```

`bindings::*` comes from the generated Wasmtime component bindings in `runtime/bindings/mod.rs`, built from `wit/world.wit`. The most important generated item for this module is `ActWorld`.

## Types

```rust
pub struct HostState { /* wasi, table, http, fs policy state */ }
```

```rust
pub enum ComponentError {
    Tool(act::core::types::ToolError),
    Internal(anyhow::Error),
}
```

```rust
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
```

```rust
pub struct CallToolResult {
    pub events: Vec<act::core::types::ToolEvent>,
}
```

```rust
pub enum SseEvent {
    Stream(act::core::types::ToolEvent),
    Done,
    Error(ComponentError),
}
```

```rust
pub type ComponentHandle = mpsc::Sender<ComponentRequest>;
```

## Functions

### `create_engine`

```rust
pub fn create_engine() -> Result<Engine>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| — | — | — | Creates a Wasmtime engine with component-model and async support enabled. |

### `load_component`

```rust
pub fn load_component(engine: &Engine, path: &std::path::Path) -> Result<Component>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `engine` | `&Engine` | — | The Wasmtime engine created by `create_engine`. |
| `path` | `&std::path::Path` | — | Path to the `.wasm` component on disk. |

### `create_linker`

```rust
pub fn create_linker(engine: &Engine) -> Result<Linker<HostState>>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `engine` | `&Engine` | — | Engine used to construct the linker. |

Builds a linker with WASI P2, WASI P3, policy-aware filesystem bindings, and WASI HTTP bindings.

### `create_store`

```rust
pub fn create_store(
    engine: &Engine,
    preopens: &[crate::runtime::fs_policy::Preopen],
    http: &crate::config::HttpConfig,
    fs: &crate::config::FsConfig,
    info: &ComponentInfo,
) -> Result<Store<HostState>>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `engine` | `&Engine` | — | Wasmtime engine. |
| `preopens` | `&[crate::runtime::fs_policy::Preopen]` | — | Guest-to-host mount roots derived from filesystem policy. |
| `http` | `&crate::config::HttpConfig` | — | User-resolved HTTP policy before capability intersection. |
| `fs` | `&crate::config::FsConfig` | — | User-resolved filesystem policy before capability intersection. |
| `info` | `&ComponentInfo` | — | Component metadata that provides declared capabilities. |

Returns a policy-aware store whose `HostState` embeds filesystem and HTTP policy machinery.

### `read_component_info`

```rust
pub fn read_component_info(component_bytes: &[u8]) -> Result<ComponentInfo>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `component_bytes` | `&[u8]` | — | Raw component bytes. |

Reads the `act:component` custom section and falls back to `version` and `description` custom sections when present.

### `instantiate_component`

```rust
pub async fn instantiate_component(
    engine: &Engine,
    component: &Component,
    linker: &Linker<HostState>,
    preopens: &[crate::runtime::fs_policy::Preopen],
    http: &crate::config::HttpConfig,
    fs: &crate::config::FsConfig,
    info: &ComponentInfo,
) -> Result<(ActWorld, Store<HostState>)>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `engine` | `&Engine` | — | Wasmtime engine. |
| `component` | `&Component` | — | Loaded component. |
| `linker` | `&Linker<HostState>` | — | Linker with policy-aware bindings. |
| `preopens` | `&[crate::runtime::fs_policy::Preopen]` | — | Preopened directories. |
| `http` | `&crate::config::HttpConfig` | — | User-resolved HTTP policy. |
| `fs` | `&crate::config::FsConfig` | — | User-resolved filesystem policy. |
| `info` | `&ComponentInfo` | — | Metadata for effective-policy calculation. |

Instantiates the generated `ActWorld` export asynchronously and returns the instance plus store.

### `spawn_component_actor`

```rust
pub fn spawn_component_actor(instance: ActWorld, mut store: Store<HostState>) -> ComponentHandle
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `instance` | `ActWorld` | — | Generated binding to the component's exported world. |
| `store` | `Store<HostState>` | — | Policy-aware store owned by the actor loop. |

Starts a Tokio task that receives `ComponentRequest` values and returns a channel sender handle.

## Example

```rust
let engine = crate::runtime::create_engine()?;
let component = crate::runtime::load_component(&engine, wasm_path)?;
let linker = crate::runtime::create_linker(&engine)?;
let (instance, store) = crate::runtime::instantiate_component(
    &engine,
    &component,
    &linker,
    &preopens,
    &http,
    &fs,
    &info,
).await?;
let handle = crate::runtime::spawn_component_actor(instance, store);
```

Related pages: [Component Host Lifecycle](/docs/component-host-lifecycle), [API Reference: filesystem policy](/docs/api-reference/filesystem-policy), and [API Reference: transports](/docs/api-reference/transports).
