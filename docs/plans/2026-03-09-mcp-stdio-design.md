# MCP stdio Design

**Goal:** Add MCP stdio transport to `act-host` so ACT components can be used as MCP servers from Claude Desktop, Cursor, VS Code, etc.

## Architecture

New `src/mcp.rs` module handles JSON-RPC 2.0 over stdin/stdout. New `mcp` CLI subcommand: `act-host mcp <component.wasm>`. Reuses existing `runtime.rs` actor pattern — same engine, linker, component instantiation, and `ComponentHandle`.

## MCP Methods

| MCP method | ACT mapping |
|---|---|
| `initialize` | Return server info from cached `ComponentInfo` |
| `notifications/initialized` | No-op acknowledgment |
| `tools/list` | `list-tools(config)` via actor |
| `tools/call` | `call-tool(config, call)` via actor, collect stream |
| `ping` | Return `{}` |

## Data Flow

```
stdin (line-delimited JSON-RPC) → parse → match method
  → initialize: return serverInfo + capabilities {tools: {}}
  → tools/list: actor ListTools → map tool-definition[] to MCP Tool[]
  → tools/call: actor CallTool → collect stream → map to MCP CallToolResult
← stdout (JSON-RPC response, one line per message)
```

## Config

Passed via CLI: `--config '{"key":"value"}'` or `--config-file path.json`. Encoded to CBOR once at startup, cached for process lifetime (per ACT-MCP.md — stateless, config-as-context).

## Content Mapping (ACT-MCP.md §2.2)

- `text/*` mime → `{"type":"text","text":"<decoded string>"}`
- `image/*` mime → `{"type":"image","data":"<base64>","mimeType":"<mime>"}`
- absent/other → `{"type":"text","text":"<json-encoded data>"}`

## Error Mapping (ACT-MCP.md §2.3)

- `std:not-found` → JSON-RPC -32601 (Method not found)
- `std:invalid-args` → JSON-RPC -32602 (Invalid params)
- `std:internal` → JSON-RPC -32603 (Internal error)
- other → JSON-RPC -32000 (Server error)

## Components

**`src/mcp.rs`:** JSON-RPC parsing, MCP request/response types, method dispatch, content/error mapping, stdin/stdout loop.

**`src/main.rs`:** New `Mcp` CLI subcommand with `component`, `--config`, `--config-file`, `--host`, `--port` args.

**`Cargo.toml`:** No new dependencies — serde_json handles JSON-RPC.

## Out of Scope

- MCP streamable HTTP transport (ACT-HTTP covers remote access)
- `notifications/cancelled` (future enhancement)
- `resources/*` and `prompts/*` (no ACT interfaces yet)
- Progress notifications for streaming
