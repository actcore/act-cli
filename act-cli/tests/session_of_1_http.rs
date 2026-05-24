//! Session-of-1 (`act run --http --session-args`) end-to-end over ACT-HTTP.
//! Spawns the host against `tests/fixtures/sessions-canary.wasm`, waits for it
//! to listen, then asserts `/sessions` is suppressed and a no-metadata tool
//! call hits the pre-opened session.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

fn canary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sessions-canary.wasm")
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .unwrap()
        .port()
}

/// POST JSON bytes (no reqwest `json` feature needed).
fn json_body(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("serialize JSON")
}

/// Spawn `act run --http` and poll `/info` until it answers.
async fn spawn_server(extra_args: &[&str], port: u16) -> Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_act"));
    cmd.arg("run")
        .arg(canary_path())
        .arg("--http")
        .arg("-l")
        .arg(format!("127.0.0.1:{port}"))
        .args(extra_args);
    let child = cmd.spawn().expect("spawn act --http");

    let client = reqwest::Client::new();
    let info_url = format!("http://127.0.0.1:{port}/info");
    for _ in 0..100 {
        if client
            .get(&info_url)
            .send()
            .await
            .ok()
            .map(|r| r.status().is_success())
            == Some(true)
        {
            return child;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("act --http did not start listening on port {port}");
}

#[tokio::test]
async fn session_of_1_suppresses_sessions_and_forces_default() {
    let port = free_port();
    let mut child = spawn_server(&["--session-args", r#"{"start":5}"#], port).await;
    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{port}");

    // /sessions is unregistered → 404.
    let sessions = client
        .post(format!("{base}/sessions"))
        .header("content-type", "application/json")
        .body(json_body(&serde_json::json!({"arguments": {}})))
        .send()
        .await
        .expect("POST /sessions");
    assert_eq!(
        sessions.status().as_u16(),
        404,
        "session-of-1 must suppress /sessions"
    );

    // read with NO metadata hits the pre-opened session (start=5).
    let resp = client
        .post(format!("{base}/tools/read"))
        .header("content-type", "application/json")
        .body(json_body(&serde_json::json!({"arguments": {}})))
        .send()
        .await
        .expect("POST /tools/read");
    assert!(
        resp.status().is_success(),
        "read should succeed: {:?}",
        resp.status()
    );
    let text = resp.text().await.expect("response text");
    let body: serde_json::Value = serde_json::from_str(&text).expect("json body");
    assert_eq!(
        body["content"][0]["data"]["value"], 5,
        "read must return the default session's value; got {body}"
    );

    child.kill().ok();
}

/// Sending a rogue `std:session-id` in the top-level `metadata` of a tool call
/// must NOT override the host-forced default.  The canary returns
/// `std:session-not-found` for unknown ids, so a regression from "force" to
/// "default" would cause the rogue id to reach the component and produce an
/// error response instead of the expected value.
#[tokio::test]
async fn session_of_1_overrides_client_supplied_session_id() {
    let port = free_port();
    let mut child = spawn_server(&["--session-args", r#"{"start":5}"#], port).await;
    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{port}");

    // Supply a rogue session-id in the top-level metadata field.
    let resp = client
        .post(format!("{base}/tools/read"))
        .header("content-type", "application/json")
        .body(json_body(
            &serde_json::json!({"arguments": {}, "metadata": {"std:session-id": "rogue-does-not-exist"}}),
        ))
        .send()
        .await
        .expect("POST /tools/read with rogue session-id");
    assert!(
        resp.status().is_success(),
        "forced default must override rogue session-id, call should succeed: {:?}",
        resp.status()
    );
    let text = resp.text().await.expect("response text");
    let body: serde_json::Value = serde_json::from_str(&text).expect("json body");
    assert_eq!(
        body["content"][0]["data"]["value"], 5,
        "must return the default session value 5 (rogue id overridden); got {body}"
    );

    child.kill().ok();
}

#[tokio::test]
async fn without_session_args_sessions_endpoint_is_present() {
    let port = free_port();
    let mut child = spawn_server(&[], port).await;
    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{port}");

    // /sessions is registered → opening succeeds (201 Created).
    let sessions = client
        .post(format!("{base}/sessions"))
        .header("content-type", "application/json")
        .body(json_body(&serde_json::json!({"arguments": {"start": 0}})))
        .send()
        .await
        .expect("POST /sessions");
    assert_eq!(
        sessions.status().as_u16(),
        201,
        "without --session-args, /sessions must open a session"
    );

    child.kill().ok();
}
