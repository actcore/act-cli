# act-cli

CLI and reference host for [ACT](../act-spec/) — loads `.wasm` ACT components and serves them over HTTP or MCP (stdio).

## Usage

```
act serve <component.wasm> [-l [::1]:3000]
act call <component.wasm> <tool-name> [--args '{}'] [-c '{}']
act mcp <component.wasm> [-c '{}'] [--config-file config.json]
act info <component.wasm>
act tools <component.wasm> [-c '{}']
```

Set `RUST_LOG=act_cli=debug` for verbose output.

## Commands

| Command | Description |
|---------|-------------|
| `serve` | Start ACT-HTTP server for a component |
| `call`  | Call a tool directly, print result to stdout |
| `mcp`   | Serve component as MCP server over stdio |
| `info`  | Show component name, version, description, capabilities |
| `tools` | List tools exposed by a component |

## HTTP Endpoints (`serve`)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/info` | Component metadata |
| `GET` | `/config-schema` | JSON Schema for config (204 if none) |
| `GET` | `/tools` | List tools |
| `POST` | `/tools/{name}` | Call a tool |

## Building

```
cargo build --release
```

## Architecture

```
main.rs     CLI (clap) → subcommands (serve, call, mcp, info, tools)
runtime.rs  wasmtime engine, component instantiation, actor pattern
http.rs     axum routes, ACT-HTTP request/response handling
mcp.rs      MCP JSON-RPC over stdio
```

The host uses an actor pattern: a single tokio task owns the wasmtime `Store` and component instance, receiving requests over an mpsc channel. This ensures single-threaded access to the Wasm component while allowing concurrent HTTP handling.
