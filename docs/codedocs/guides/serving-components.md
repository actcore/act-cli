---
title: "Serving Components"
description: "Host one ACT component over HTTP or MCP and understand the request path from client input to the runtime actor."
---

This guide shows the two serving modes exposed by `act run`: ACT-HTTP over a socket and MCP over stdio. Both are thin wrappers around the same prepared component and `ComponentHandle`, so the practical choice is about client compatibility, not about runtime capability.

<Steps>
<Step>
### Inspect the component first

Use `info --tools` before you expose a component. It tells you whether the component has a metadata schema, what tool names exist, and whether the transport choice needs extra policy grants.

```bash
act info --tools ./target/wasm32-wasip2/release/my_component.wasm
```

If the output lists tools but no metadata schema, the server can often start without `--metadata`. If the component declares filesystem or HTTP capabilities, decide those policy flags before you move on.
</Step>
<Step>
### Serve over ACT-HTTP

Start the server on a predictable local port:

```bash
act run \
  --http \
  --listen 3000 \
  --fs-policy allowlist \
  --fs-allow '/workspace/data/**' \
  ./target/wasm32-wasip2/release/my_component.wasm
```

Then call it from another terminal:

```bash
curl -s http://[::1]:3000/info
curl -s -X POST http://[::1]:3000/tools/summarize \
  -H 'content-type: application/json' \
  -d '{"arguments":{"text":"ACT keeps one actor per component"}}'
```

The first request maps to `get_info` in `act-cli/src/http.rs`. The second becomes a `ComponentRequest::CallTool` and returns buffered JSON unless the client asks for `text/event-stream`.
</Step>
<Step>
### Serve over MCP stdio

Use MCP when the client expects JSON-RPC over stdin and stdout:

```bash
act run --mcp ./target/wasm32-wasip2/release/my_component.wasm
```

A minimal `initialize` request looks like this:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
```

`mcp::run_stdio` in `act-cli/src/mcp.rs` reads one line at a time, dispatches `initialize`, `tools/list`, and `tools/call`, and emits one JSON line per response. Unknown `notifications/*` methods are ignored, which matches MCP expectations.
</Step>
<Step>
### Enable streaming when the tool emits incremental events

For ACT-HTTP, request SSE explicitly:

```bash
curl -N -X POST http://[::1]:3000/tools/generate \
  -H 'accept: text/event-stream' \
  -H 'content-type: application/json' \
  -d '{"arguments":{"prompt":"Write a release note"}}'
```

The HTTP layer switches to `call_tool_sse`, which creates a `ComponentRequest::CallToolStreaming`. The runtime forwards `ToolEvent::Content` items as SSE `content` events and finishes with `done`.
</Step>
</Steps>

```mermaid
sequenceDiagram
  participant Client
  participant HTTP as http.rs or mcp.rs
  participant Actor as ComponentHandle
  participant Guest as ACT component

  Client->>HTTP: request or JSON-RPC message
  HTTP->>Actor: ComponentRequest
  Actor->>Guest: call_list_tools / call_call_tool
  Guest-->>Actor: events
  Actor-->>HTTP: buffered result or stream items
  HTTP-->>Client: JSON, SSE, or JSON-RPC response
```

Problem solved: one component can serve web clients and agent clients without duplicating runtime setup. The important operational detail is that both transports still depend on the same policy model. If a served tool needs outbound HTTP or filesystem access, set the policy flags when starting `act run`, not later at request time.

For deeper details, see [Component Host Lifecycle](/docs/component-host-lifecycle) and [API Reference: transports](/docs/api-reference/transports).
