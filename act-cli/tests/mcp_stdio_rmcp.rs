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
