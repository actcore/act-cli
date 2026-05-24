//! Session-of-1 (`act run --mcp --session-args`) end-to-end over MCP stdio.
//! Uses the prebuilt `tests/fixtures/sessions-canary.wasm` session-provider
//! (tools `read`/`increment`, requires `std:session-id`; `open-session`
//! accepts `start: u64`).

use std::path::PathBuf;

use rmcp::{
    ServiceExt,
    model::{CallToolRequestParams, RawContent},
    transport::{ConfigureCommandExt, TokioChildProcess},
};

fn canary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sessions-canary.wasm")
}

fn act_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_act"))
}

#[tokio::test]
async fn session_of_1_hides_virtual_tools_and_uses_default_session() {
    let transport = TokioChildProcess::new(
        tokio::process::Command::new(act_binary_path()).configure(|cmd| {
            cmd.arg("run")
                .arg(canary_path())
                .arg("--mcp")
                .arg("--session-args")
                .arg(r#"{"start":7}"#);
        }),
    )
    .expect("spawn act --mcp --session-args");

    let client = ().serve(transport).await.expect("rmcp handshake");

    // Hidden: only the component's own tools, no open_session/close_session.
    let tools = client.list_all_tools().await.expect("list_all_tools");
    let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    assert!(
        !names
            .iter()
            .any(|n| n == "open_session" || n == "close_session"),
        "session-of-1 must hide virtual session tools; got {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "read"),
        "component tools must remain; got {names:?}"
    );

    // Hidden: the `read` tool schema must NOT carry the injected `_meta`
    // arg-hint in session-of-1 mode (the host forces std:session-id).
    // input_schema is Arc<serde_json::Map<String, Value>>, deref to access .get()
    let read_tool = tools.iter().find(|t| t.name == "read").expect("read tool");
    let has_meta = read_tool
        .input_schema
        .get("properties")
        .and_then(|p| p.as_object())
        .map(|props| props.contains_key("_meta"))
        .unwrap_or(false);
    assert!(
        !has_meta,
        "session-of-1 must not inject the _meta arg-hint; read schema: {:?}",
        read_tool.input_schema
    );

    // Force: `read` with NO _meta still hits the pre-opened session (start=7).
    let result = client
        .call_tool(CallToolRequestParams::new("read"))
        .await
        .expect("call_tool read");
    assert_ne!(
        result.is_error,
        Some(true),
        "read should succeed: {result:?}"
    );
    let text = result
        .content
        .iter()
        .find_map(|c| match &c.raw {
            RawContent::Text(t) => Some(t.text.clone()),
            _ => None,
        })
        .unwrap_or_default();
    assert!(
        text.contains('7'),
        "read must return the default session's value 7; got {text:?}"
    );

    client.cancel().await.ok();
}

/// A non-session component (`time.wasm`) with `--session-args` must bail with
/// the missing-session-provider error before serving.
#[test]
fn session_args_on_non_session_component_bails() {
    let time = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/time.wasm");
    let output = std::process::Command::new(act_binary_path())
        .arg("run")
        .arg(&time)
        .arg("--mcp")
        .arg("--session-args")
        .arg("{}")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("spawn act");
    assert!(
        !output.status.success(),
        "must fail for a component without session-provider"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not export"),
        "stderr should explain the missing session-provider; got: {stderr}"
    );
}

#[tokio::test]
async fn without_session_args_virtual_tools_are_present() {
    let transport = TokioChildProcess::new(
        tokio::process::Command::new(act_binary_path()).configure(|cmd| {
            cmd.arg("run").arg(canary_path()).arg("--mcp");
        }),
    )
    .expect("spawn act --mcp");

    let client = ().serve(transport).await.expect("rmcp handshake");
    let tools = client.list_all_tools().await.expect("list_all_tools");
    let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    assert!(
        names.iter().any(|n| n == "open_session"),
        "without --session-args, open_session must be exposed; got {names:?}"
    );

    client.cancel().await.ok();
}
