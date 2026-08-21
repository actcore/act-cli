//! Drives the facade against `act-cli/tests/fixtures/time.wasm`, the prebuilt
//! `components/time` component the CLI suites already use.
//!
//! `time` needs no filesystem, network or credentials, so a default
//! `RuntimeConfig` — ask-mode grants — paired with a denying prompter still
//! loads and answers. That pairing is the headless default, and a component
//! that needs nothing must not be blocked by it.

use std::path::PathBuf;

fn time_component() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../act-cli/tests/fixtures/time.wasm")
}

#[tokio::test]
async fn a_loaded_component_lists_its_tools_through_the_facade() {
    let reference = act_runtime::ComponentRef::Local(time_component());
    let rt = act_runtime::ComponentRuntime::new().expect("engine");
    let running = rt
        .load(
            &reference,
            &act_runtime::RuntimeConfig::default(),
            act_runtime::ConsentConfig::deny(),
        )
        .await
        .expect("load");

    assert_eq!(running.info().std.name, "time");
    assert!(
        !running.has_sessions(),
        "time is stateless: it exports no session-provider"
    );

    // The tool name is deliberately not pinned — `mcp_stdio_rmcp.rs` takes
    // `tools.first()` for the same reason. The fixture is rebuilt from
    // `components/time`, and hardcoding its names here would turn an unrelated
    // rename into a failure of the facade.
    let tools = running
        .handle()
        .list_tools(&act_runtime::Metadata::default())
        .await
        .expect("list-tools");
    assert!(!tools.tools.is_empty(), "time exports at least one tool");
}

#[tokio::test]
async fn a_stateless_component_fails_session_calls_as_a_host_error() {
    // The session surface exists on every handle; whether it answers is the
    // component's business. A stateless one must say so rather than hang or
    // panic — this is the path a bridge takes before it knows what it has.
    let reference = act_runtime::ComponentRef::Local(time_component());
    let rt = act_runtime::ComponentRuntime::new().expect("engine");
    let running = rt
        .load(
            &reference,
            &act_runtime::RuntimeConfig::default(),
            act_runtime::ConsentConfig::deny(),
        )
        .await
        .expect("load");

    let err = running
        .handle()
        .open_session_args_schema(Vec::new())
        .await
        .expect_err("a stateless component has no session args schema");
    // Internal, not a `std:not-found` tool error: the component never ran.
    // Nothing declined the call — there was no export to call.
    match err {
        act_runtime::ComponentError::Internal(e) => assert_eq!(
            e.to_string(),
            "component does not export act:sessions/session-provider"
        ),
        act_runtime::ComponentError::Tool(e) => {
            panic!(
                "nothing ran, so nothing could answer: got tool error {}",
                e.kind
            )
        }
    }
}
