# act-host

Reference implementation of an [ACT](../act-spec/) host — loads a single `.wasm` ACT component and serves it over HTTP.

## Usage

```
act-host serve <component.wasm> [--host 127.0.0.1] [--port 3000]
```

Set `RUST_LOG=act_host=debug` for verbose output.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/info` | Component metadata |
| `GET` | `/config-schema` | JSON Schema for config (204 if none) |
| `GET` | `/tools` | List tools |
| `QUERY` | `/tools` | List tools with config in body |
| `POST` | `/tools/{name}` | Call a tool |

### Call tool request

```json
{
  "id": "call-1",
  "arguments": { "name": "world" },
  "config": null
}
```

### Call tool response

```json
{
  "id": "call-1",
  "content": [
    { "data": "Hello, world!", "mime_type": "text/plain" }
  ]
}
```

## Building

```
cargo build --release
```

### Building the hello-world example component

```
cd examples/hello-world
cargo build --target wasm32-wasip2 --release
```

Then serve it:

```
cargo run --release -- serve examples/hello-world/target/wasm32-wasip2/release/hello_world.wasm
```

## Architecture

```
main.rs     CLI (clap) → load component → start server
runtime.rs  wasmtime engine, component instantiation, actor pattern
http.rs     axum routes, JSON request/response types
cbor.rs     JSON ↔ CBOR conversion
```

The host uses an actor pattern: a single tokio task owns the wasmtime `Store` and `ActWorld` instance, receiving requests over an mpsc channel. This ensures single-threaded access to the component while allowing concurrent HTTP handling.
