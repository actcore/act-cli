---
title: "Component Host Lifecycle"
description: "Follow a component from bytes on disk into a Wasmtime store, actor loop, and the HTTP or MCP transport adapters."
---

The host lifecycle is the path from `ComponentRef` to a running ACT tool provider. It matters because most user-visible behavior in `act` is a thin wrapper over the same runtime actor: direct CLI calls, ACT-HTTP requests, and MCP JSON-RPC messages all converge on `ComponentRequest`.

## What the Concept Is

The runtime layer in `act-cli/src/runtime/mod.rs` is responsible for:

- Creating a Wasmtime engine with component-model and async support.
- Loading the `.wasm` component from disk.
- Building a linker that wires both WASI and policy-aware overrides.
- Creating a store whose `HostState` contains filesystem and HTTP policy state.
- Instantiating the `ActWorld` binding generated from `wit/world.wit`.
- Spawning a Tokio actor that serializes requests into the component instance.

## How It Relates to Other Concepts

- It consumes [Component References](/docs/component-references) because it only accepts a local file path.
- It embeds [Runtime Policies](/docs/runtime-policies) in `HostState` before any guest code runs.
- It is exposed externally by the ACT-HTTP and MCP transports covered in the API reference and guides.

## Internal Logic

`prepare_component` in `act-cli/src/main.rs` is the orchestration point:

1. Resolve CLI and config options into `ResolvedOpts`.
2. Resolve the component reference to a local path.
3. Read raw bytes and parse `ComponentInfo` from `act:component`.
4. Derive preopens with `fs_policy::derive_preopens`, then optionally remap them with `apply_mount_root`.
5. Create `Metadata` from merged JSON metadata.
6. Call `create_engine`, `load_component`, `create_linker`, and `instantiate_component`.
7. Create a `ComponentHandle` with `spawn_component_actor`.

The actor loop is central. It accepts four message variants:

```rust
pub enum ComponentRequest {
    GetMetadataSchema { ... },
    ListTools { ... },
    CallTool { ... },
    CallToolStreaming { ... },
}
```

`CallTool` collects tool events into a `Vec`, while `CallToolStreaming` forwards them through an `mpsc::Sender<SseEvent>`. The same ACT tool provider call powers both.

```mermaid
sequenceDiagram
  participant Main as prepare_component
  participant Runtime as runtime/mod.rs
  participant Store as Store<HostState>
  participant Actor as spawn_component_actor
  participant Client as CLI/HTTP/MCP

  Main->>Runtime: create_engine()
  Main->>Runtime: load_component(engine, path)
  Main->>Runtime: create_linker(engine)
  Main->>Runtime: instantiate_component(...)
  Runtime-->>Main: (ActWorld, Store)
  Main->>Actor: spawn_component_actor(instance, store)
  Client->>Actor: ComponentRequest
  Actor->>Store: run_concurrent(...)
  Store-->>Actor: Tool result or schema
  Actor-->>Client: buffered result or stream events
```

## Basic Usage

Start the ACT-HTTP server:

```bash
act run --http --listen 3000 ./component.wasm
```

Internally, `cmd_run` parses the port as `[::1]:3000`, prepares the component, wraps `AppState` in `Arc`, and serves an Axum router from `http::create_router`.

Call a tool directly:

```bash
act call ./component.wasm summarize --args '{"text":"hello"}'
```

`cmd_call` converts the JSON arguments to CBOR with `act_types::cbor::json_to_cbor`, sends `ComponentRequest::CallTool`, and then prints each returned content part.

## Advanced and Edge-case Usage

Run the same component as an MCP server:

```bash
act run --mcp ./component.wasm
```

`cmd_run` uses the same `prepare_component` path, but instead of creating an HTTP router it passes `ComponentInfo`, `ComponentHandle`, and `Metadata` to `mcp::run_stdio`. That loop reads line-delimited JSON-RPC messages, handles `initialize`, `tools/list`, and `tools/call`, and writes one JSON line per response.

Inspect a component without instantiating it:

```bash
act info ./component.wasm
```

If `--tools` is omitted, `cmd_info` never calls `prepare_component`. It only reads the custom section with `read_component_info`, which is significantly lighter and is useful when the runtime environment for the component is unavailable.

<Callout type="warn">`act run` requires an explicit transport choice. In `cmd_run`, `--mcp` and `--http` are mutually exclusive, and if neither `--http` nor `--listen` is provided, the command errors instead of guessing a default transport.</Callout>

<Accordions>
<Accordion title="Why use one actor per instantiated component?">

`spawn_component_actor` keeps ownership of `Store<HostState>` inside one Tokio task. That makes the runtime easier to reason about because every guest call crosses one channel boundary and one `run_concurrent` call.

The trade-off is that extremely high request concurrency is serialized at the actor boundary, so the host favors correctness and consistent state over maximal throughput.

For CLI, local automation, and tool-serving workloads, that trade-off is sensible because predictability matters more than squeezing parallelism out of one Wasmtime store.

</Accordion>
<Accordion title="Buffered calls vs. streaming calls">

The runtime offers both `CallTool` and `CallToolStreaming` because some consumers need a completed result, while ACT-HTTP with `text/event-stream` wants progressive output. The buffered path is simpler and easier to map to stdout or JSON.

The streaming path reduces latency for long-running tools but adds more coordination: the actor must forward `SseEvent::Stream` items and send a terminal `Done` or `Error`.

The source keeps both paths in the same actor so they share tool invocation logic even though the delivery strategy differs.

</Accordion>
</Accordions>

For transport-specific adapters, continue to [API Reference: transports](/docs/api-reference/transports).
