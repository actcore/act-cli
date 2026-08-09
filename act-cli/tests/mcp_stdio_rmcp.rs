//! Fixture `tests/fixtures/time.wasm` is a prebuilt `components/time` component
//! (built via `cd components/time && just build && just pack`). Rebuild when the
//! component source or its pack metadata changes.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use rmcp::{
    ServiceExt,
    model::CallToolRequestParams,
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Mutex as AsyncMutex;

fn time_component_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/time.wasm")
}

fn act_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_act"))
}

/// Spawn `act run <component> --mcp` with stderr piped instead of inherited,
/// and start a background task draining it into a shared buffer. Audit
/// output (including the rollup line each `tools/call` produces) lands on
/// stderr, separate from the JSON-RPC traffic on stdin/stdout that `serve`
/// takes ownership of.
fn spawn_time_with_captured_stderr() -> (TokioChildProcess, Arc<AsyncMutex<String>>) {
    let (transport, stderr) = TokioChildProcess::builder(
        tokio::process::Command::new(act_binary_path()).configure(|cmd| {
            cmd.arg("run").arg(time_component_path()).arg("--mcp");
        }),
    )
    .stderr(Stdio::piped())
    .spawn()
    .expect("spawn act --mcp with piped stderr");

    let captured = Arc::new(AsyncMutex::new(String::new()));
    let sink = captured.clone();
    let mut lines = BufReader::new(stderr.expect("stderr was piped")).lines();
    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            let mut buf = sink.lock().await;
            buf.push_str(&line);
            buf.push('\n');
        }
    });

    (transport, captured)
}

/// Poll the captured-stderr buffer until it contains `needle` or `timeout`
/// elapses. The audit line for a call is flushed to stderr before the
/// JSON-RPC reply is sent (`finish_tool_call` runs before `reply.send` in
/// the actor loop), but reaching *this* process's buffer still crosses a
/// pipe and an async read, hence the poll rather than a bare `contains`.
async fn wait_for_stderr(
    captured: &Arc<AsyncMutex<String>>,
    needle: &str,
    timeout: Duration,
) -> bool {
    let start = std::time::Instant::now();
    loop {
        if captured.lock().await.contains(needle) {
            return true;
        }
        if start.elapsed() > timeout {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn initialize_and_list_tools_round_trip() {
    let transport = TokioChildProcess::new(
        tokio::process::Command::new(act_binary_path()).configure(|cmd| {
            cmd.arg("run").arg(time_component_path()).arg("--mcp");
        }),
    )
    .expect("spawn act --mcp");

    let client = ().serve(transport).await.expect("rmcp client handshake with act --mcp");

    let tools = client.list_all_tools().await.expect("list_all_tools");

    assert!(
        !tools.is_empty(),
        "time component must expose at least one tool"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn call_tool_now_returns_text_content() {
    let transport = TokioChildProcess::new(
        tokio::process::Command::new(act_binary_path()).configure(|cmd| {
            cmd.arg("run").arg(time_component_path()).arg("--mcp");
        }),
    )
    .expect("spawn act --mcp");

    let client = ().serve(transport).await.expect("handshake");

    // Find a tool name from the list — the time component exposes a single tool
    // (`get_current_time` or similar). Iterate the list to find it rather than
    // hardcoding, so the test survives a rename.
    let tools = client.list_all_tools().await.expect("list_all_tools");
    let tool_name = tools.first().expect("at least one tool").name.to_string();

    let result = client
        .call_tool(CallToolRequestParams::new(tool_name))
        .await
        .expect("call_tool");

    assert_ne!(
        result.is_error,
        Some(true),
        "call should succeed, got: {:?}",
        result
    );
    assert!(
        !result.content.is_empty(),
        "must return at least one content item"
    );

    client.cancel().await.ok();
}

fn sessions_canary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sessions-canary.wasm")
}

/// An unknown session id must reach the client as a *named* ACT error kind,
/// not as an anonymous -32603. This is the whole point of the projection.
#[tokio::test]
async fn error_kind_reaches_the_client() {
    let transport = TokioChildProcess::new(
        tokio::process::Command::new(act_binary_path()).configure(|cmd| {
            cmd.arg("run").arg(sessions_canary_path()).arg("--mcp");
        }),
    )
    .expect("spawn act --mcp");

    let client = ().serve(transport).await.expect("rmcp handshake");

    // No --session-args here, so the rogue id is not overridden and actually
    // reaches the component. Same argument-_meta shape as session_of_1_mcp.rs.
    let arguments = serde_json::json!({"_meta": {"std:session-id": "sid-does-not-exist"}})
        .as_object()
        .unwrap()
        .clone();
    let params = CallToolRequestParams::new("read").with_arguments(arguments);

    // The kind may arrive on either path: as a JSON-RPC error response
    // (ErrorData.data) or as an isError result (_meta). Both must carry it.
    let kind = match client.call_tool(params).await {
        Err(rmcp::ServiceError::McpError(e)) => e
            .data
            .as_ref()
            .and_then(|d| d.get("dev.actcore/error-kind"))
            .and_then(|v| v.as_str())
            .map(str::to_string),
        Ok(result) => {
            assert_eq!(
                result.is_error,
                Some(true),
                "an unknown session id must fail: {result:?}"
            );
            result
                .meta
                .as_ref()
                .and_then(|m| m.0.get("dev.actcore/error-kind"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        }
        Err(other) => panic!("unexpected transport failure: {other:?}"),
    };

    assert_eq!(
        kind.as_deref(),
        Some("std:session-not-found"),
        "the ACT kind must reach the client, keeping its `std:` spelling as a value"
    );

    client.cancel().await.ok();
}

/// Whatever the projection puts on the wire, every `_meta` key it emits must
/// be a legal MCP key name — no colons.
#[tokio::test]
async fn emitted_meta_keys_are_conformant() {
    let transport = TokioChildProcess::new(
        tokio::process::Command::new(act_binary_path()).configure(|cmd| {
            cmd.arg("run").arg(time_component_path()).arg("--mcp");
        }),
    )
    .expect("spawn act --mcp");

    let client = ().serve(transport).await.expect("handshake");

    let tools = client.list_all_tools().await.expect("list_all_tools");
    let tool_name = tools.first().expect("at least one tool").name.to_string();

    let result = client
        .call_tool(CallToolRequestParams::new(tool_name))
        .await
        .expect("call_tool");

    if let Some(meta) = result.meta.as_ref() {
        for key in meta.0.keys() {
            assert!(
                !key.contains(':'),
                "result _meta key `{key}` contains a colon"
            );
        }
    }

    // Positive assertion, not just an absence check: the first block's _meta
    // must actually carry the mime-type key the projection is supposed to
    // emit, with the value the component actually produced. `time`'s
    // get_current_time returns a plain String, which act_sdk's
    // `String::into_tool_response` tags as MIME_TEXT ("text/plain").
    let first_block = result
        .content
        .first()
        .expect("must return at least one content item");
    let rmcp::model::ContentBlock::Text(text) = first_block else {
        panic!("expected the first content block to be Text, got: {first_block:?}");
    };
    let meta = text
        .meta
        .as_ref()
        .expect("first text block must carry _meta with dev.actcore/mime-type");
    assert_eq!(
        meta.0.get("dev.actcore/mime-type").and_then(|v| v.as_str()),
        Some("text/plain"),
        "first text block's dev.actcore/mime-type must match the mime the component emitted"
    );

    for block in &result.content {
        if let rmcp::model::ContentBlock::Text(t) = block {
            if let Some(meta) = t.meta.as_ref() {
                for key in meta.0.keys() {
                    assert!(
                        !key.contains(':'),
                        "block _meta key `{key}` contains a colon"
                    );
                }
            }
        }
    }

    client.cancel().await.ok();
}

/// ACT-CONSTANTS §5 / ACT-MCP §3.2.1: a client-supplied `std:request-id` in
/// transport `_meta` reaches the audit trail — the propagation this task
/// adds (`trace_metadata_from_meta` in `rmcp_bridge.rs`).
///
/// `std:traceparent` / `std:agent-id` propagate the same way but, unlike
/// `std:request-id`, are never rendered into the human audit line by design
/// (act-audit's `SpanVisitor`: "captured onto the span but stay unrendered
/// — only REQUEST_ID reaches a line"; they exist for a future OTLP
/// exporter). This test is the black-box half of the verification the
/// request id gets; the trace-context mapping itself is proven at the unit
/// level by `rmcp_bridge::tests::mcp_meta_trace_keys_reach_call_metadata`.
#[tokio::test]
async fn mcp_transport_request_id_reaches_the_audit_line() {
    let (transport, captured) = spawn_time_with_captured_stderr();
    let client = ().serve(transport).await.expect("rmcp handshake");

    let tools = client.list_all_tools().await.expect("list_all_tools");
    let tool_name = tools.first().expect("at least one tool").name.to_string();

    let mut params = CallToolRequestParams::new(tool_name);
    params.meta = Some(rmcp::model::RequestMetaObject(rmcp::model::MetaObject(
        serde_json::json!({
            "std:request-id": "e2e-request-id",
            "std:traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            "std:agent-id": "test-agent",
        })
        .as_object()
        .unwrap()
        .clone(),
    )));

    let result = client.call_tool(params).await.expect("call_tool");
    assert_ne!(result.is_error, Some(true), "call should succeed");

    // `render_rollup` truncates the request id to its first 6 bytes before
    // printing it.
    let found = wait_for_stderr(&captured, "req:e2e-re", Duration::from_secs(5)).await;
    assert!(
        found,
        "expected the client-supplied std:request-id (truncated) in the audit \
         line, captured stderr so far:\n{}",
        captured.lock().await
    );

    client.cancel().await.ok();
}

/// The no-`_meta` case: correlation must never depend on the caller opting
/// in. Before this task, a call with no metadata at all fell back to
/// `runtime::new_request_id()` at the actor — always `{6 hex digits}-{hex
/// counter}`, i.e. always containing a `-`. After this task, an MCP call
/// carries the JSON-RPC request id (a small decimal integer, rmcp assigns
/// them sequentially) into `std:request-id` before the actor ever sees an
/// absence to fall back on — so the visible id changes shape. Asserting
/// "some req: value is present" alone would pass whether or not this task's
/// code runs at all (the actor-level fallback already existed), so this
/// pins the more specific, load-bearing shape instead.
#[tokio::test]
async fn mcp_call_without_meta_carries_the_jsonrpc_id_not_a_host_generated_one() {
    let (transport, captured) = spawn_time_with_captured_stderr();
    let client = ().serve(transport).await.expect("rmcp handshake");

    let tools = client.list_all_tools().await.expect("list_all_tools");
    let tool_name = tools.first().expect("at least one tool").name.to_string();

    let result = client
        .call_tool(CallToolRequestParams::new(tool_name))
        .await
        .expect("call_tool");
    assert_ne!(result.is_error, Some(true), "call should succeed");

    assert!(
        wait_for_stderr(&captured, "req:", Duration::from_secs(5)).await,
        "expected a req: field in the audit line at all"
    );

    let line = captured.lock().await.clone();
    let req_value = line
        .lines()
        .find_map(|l| l.split("req:").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .expect("a rollup line with a req: field");

    assert!(
        req_value.chars().all(|c| c.is_ascii_digit()),
        "expected the JSON-RPC request id (digits only) with no `_meta` sent, \
         got req:{req_value} in:\n{line}"
    );

    client.cancel().await.ok();
}
