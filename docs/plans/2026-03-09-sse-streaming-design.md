# SSE Streaming Design

**Goal:** Add Server-Sent Events streaming to `POST /tools/{name}` so clients can receive tool results incrementally.

## Architecture

The `call_tool` handler checks the `Accept` header. If `text/event-stream`, it returns an axum `Sse` streaming response instead of buffered JSON. A new `ForwardingConsumer` sends each stream event through an mpsc channel to the SSE response as it arrives, instead of collecting all events first.

A new `ComponentRequest::CallToolStreaming` variant carries an `mpsc::Sender<StreamEvent>` instead of a `oneshot::Sender<CallToolResult>`. When the client disconnects, the channel closes, the actor detects this and drops the stream reader — triggering wasmtime cancellation.

## Data Flow

**Buffered (existing, `Accept: application/json`):**
```
POST /tools/{name} → call_tool → actor CallTool → pipe+collect → JSON response
```

**Streaming (new, `Accept: text/event-stream`):**
```
POST /tools/{name} → call_tool → actor CallToolStreaming
  → ForwardingConsumer sends events via mpsc → Sse response emits SSE events
  → client disconnects → mpsc dropped → drop stream → cancel
```

## SSE Event Mapping

- `StreamEvent::Content(part)` → `event: content\ndata: {"data": ..., "mime_type": ...}\n\n`
- `StreamEvent::Error(err)` → `event: error\ndata: {"kind": ..., "message": ...}\n\n` (terminal)
- Stream closed normally → `event: done\ndata: {}\n\n` (terminal)

## Streaming Hint

Tools may declare `std:streaming` (boolean) in metadata. When a client requests SSE for a tool without this hint, the host logs a warning but proceeds (hint is advisory per spec).

## Components

**`src/http.rs`:** Parse Accept header, branch SSE vs JSON, SSE event formatting, streaming hint warning.

**`src/runtime.rs`:** `CallToolStreaming` request variant, `ForwardingConsumer` that sends via mpsc, cancellation on channel close.

**`examples/counter/`:** New component with `count` tool — emits N content events with `std:streaming: true` metadata.

**`Cargo.toml`:** Add `tokio-stream` dependency.

## Error Handling

- Single-event tools over SSE: emit one `event: content`, then `event: done`.
- Mid-stream error: forward as `event: error`, close stream. HTTP 200 already sent.
- Client disconnect: mpsc close → drop stream reader → wasmtime cancellation.
- Actor unavailable: HTTP 500 JSON (before SSE headers sent).
- No SSE timeout — streaming is intentionally long-lived.

## Out of Scope

- `GET /events` push notifications (separate feature)
- Multi-component routing
