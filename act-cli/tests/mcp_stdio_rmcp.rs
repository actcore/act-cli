//! Fixture `tests/fixtures/time.wasm` is a prebuilt `components/time` component
//! (built via `cd components/time && just build && just pack`). Rebuild when the
//! component source or its pack metadata changes.

use std::path::PathBuf;

use rmcp::{
    ServiceExt,
    model::CallToolRequestParams,
    transport::{ConfigureCommandExt, TokioChildProcess},
};

fn time_component_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/time.wasm")
}

fn act_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_act"))
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
