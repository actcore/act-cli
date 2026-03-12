# ACT Reference Host — Design

## Goal

Rust binary that loads a single `.wasm` ACT component and exposes it as an ACT-HTTP server. Proves the spec works end-to-end.

## Scope (v0.1)

- Load one `.wasm` component via wasmtime with `component-model-async`
- Expose ACT-HTTP endpoints (info, config-schema, tools, call)
- JSON only (no CBOR content negotiation)
- No SSE streaming (collect stream, return JSON)
- No events, no resources
- Example calculator component

## Architecture

```
act-host/
├── Cargo.toml
├── src/
│   ├── main.rs          — CLI entry, load component, start server
│   ├── runtime.rs       — wasmtime component instantiation
│   ├── http.rs          — axum routes (info, tools, call)
│   └── cbor.rs          — JSON↔dCBOR conversion
└── examples/
    └── calculator/      — example component (cargo-component)
        ├── Cargo.toml
        └── src/lib.rs
```

**Flow:** HTTP request → axum handler → JSON→dCBOR → wasmtime call → dCBOR→JSON → HTTP response.

## HTTP Endpoints

| Endpoint | Handler | Component call |
|---|---|---|
| `GET /info` | Return cached `component-info` as JSON | `tool-provider.get-info()` |
| `GET /config-schema` | Return config schema or 204 | `tool-provider.get-config-schema()` |
| `GET /tools` | List tools (config via `X-ACT-Config` header) | `tool-provider.list-tools(config)` |
| `QUERY /tools` | List tools (config in request body) | `tool-provider.list-tools(config)` |
| `POST /tools/{name}` | Invoke tool, collect stream, return JSON | `tool-provider.call-tool(config, call)` |

Note: axum needs custom method extractor for QUERY.

## Calculator Example Component

- Tools: `add(a: f64, b: f64) -> f64`, `multiply(a: f64, b: f64) -> f64`
- No config required
- Default language: "en"
- Built with `cargo-component`, produces `calculator.wasm`

## Error Handling

| Error | Kind | HTTP Status |
|---|---|---|
| Tool not found | `std:not-found` | 404 |
| Invalid arguments | `std:invalid-args` | 422 |
| Component trap | `std:internal` | 500 |
| Stream error | Collected, returned as JSON | Mapped by kind |

## CLI Interface

```bash
act-host serve calculator.wasm
act-host serve calculator.wasm --port 8080 --host 127.0.0.1
```

## Dependencies

### Host
| Crate | Purpose |
|---|---|
| `wasmtime` + `wasmtime-wasi` | Component runtime, WASI P3 |
| `tokio` | Async runtime |
| `axum` | HTTP server |
| `ciborium` | CBOR encode/decode |
| `serde` + `serde_json` | JSON serialization |
| `clap` | CLI argument parsing |

### Calculator component
- `cargo-component` (build tool)
- `wit-bindgen` (WIT bindings generation)

## Success Criteria

1. `cargo build` builds host
2. `cargo component build` builds calculator.wasm
3. `act-host serve calculator.wasm` starts HTTP server
4. `GET /info` returns component metadata
5. `GET /tools` returns two tool definitions (add, multiply)
6. `POST /tools/add {"id":"1","arguments":{"a":2,"b":3}}` returns result with `5`
7. `POST /tools/unknown` returns 404

## Out of Scope

- SSE streaming (`Accept: text/event-stream`)
- Events (`GET /events`)
- Resources (`GET /resources`)
- CBOR content negotiation
- Multi-component hosting
- MCP adapter
- TLS/HTTPS
