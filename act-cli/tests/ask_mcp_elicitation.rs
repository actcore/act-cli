//! `ask`-mode consent over MCP, end to end.
//!
//! Drives the real `act` binary under `--mcp` with raw JSON-RPC on stdio and
//! answers the elicitation the host sends, so the whole path is exercised:
//! capability gate → consent sink → request handler → `elicitation/create` →
//! client's answer → allow or deny.
//!
//! The fixture (`ask-canary.wasm`) declares `wasi:http` and its single tool
//! makes one request. With no grant the host resolves `wasi:http` to `ask`, so
//! every call trips the gate. Nothing listens on the target port, which makes
//! the two outcomes distinguishable without standing up a server:
//!
//! * consent refused → the host blocks the request → `HttpRequestDenied`
//! * consent granted → the request goes out and fails later → `ConnectionRefused`
//!
//! ## Why this is worth a subprocess test
//!
//! Protocol revision `2026-07-28` forbids a server→client request that is not
//! associated with an in-flight client request (SEP-2260), and rmcp tracks the
//! association with a task-local it installs around the handler future. ACT runs
//! guests on the component actor task, so a gate firing there is outside that
//! scope and the elicitation is rejected — turning every `ask` into a silent
//! deny. Nothing below the process boundary catches that: the unit tests in
//! `runtime::elicit` cover the channel, but only a real client negotiating a
//! real protocol version proves the association holds.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/ask-canary.wasm"
);
/// Nothing listens here, so an allowed request fails at connect.
const TARGET: &str = "http://127.0.0.1:1/";
const CASE_TIMEOUT: Duration = Duration::from_secs(60);

struct Outcome {
    /// Whether the host asked the client for consent.
    elicited: bool,
    /// The tool call's reported text.
    text: String,
}

/// Run one `tools/call` against the canary.
///
/// `answer` is the elicitation action to reply with; `None` means the client
/// declares no elicitation capability at all (the fail-safe path).
fn run_case(protocol_version: &str, answer: Option<&str>) -> Outcome {
    let mut child = Command::new(env!("CARGO_BIN_EXE_act"))
        .args(["run", FIXTURE, "--mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn act --mcp");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));

    let capabilities = match answer {
        Some(_) => serde_json::json!({ "elicitation": {} }),
        None => serde_json::json!({}),
    };
    let answer = answer.map(str::to_owned);
    let protocol_version = protocol_version.to_owned();

    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut send = |value: serde_json::Value| {
            let _ = writeln!(stdin, "{value}");
            let _ = stdin.flush();
        };

        send(serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": protocol_version,
                "capabilities": capabilities,
                "clientInfo": { "name": "ask-mcp-elicitation-test", "version": "0" },
            }
        }));

        let mut elicited = false;
        for line in stdout.lines() {
            let Ok(line) = line else { break };
            let Ok(message) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };

            // The consent question, as a server-to-client request.
            if message.get("method").and_then(|m| m.as_str()) == Some("elicitation/create") {
                elicited = true;
                send(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": { "action": answer.as_deref().unwrap_or("decline") },
                }));
                continue;
            }

            match message.get("id").and_then(|id| id.as_u64()) {
                Some(1) => {
                    send(serde_json::json!({
                        "jsonrpc": "2.0", "method": "notifications/initialized"
                    }));
                    send(serde_json::json!({
                        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                        "params": { "name": "fetch", "arguments": { "url": TARGET } }
                    }));
                }
                Some(2) => {
                    let _ = tx.send(Outcome {
                        elicited,
                        text: message.to_string(),
                    });
                    return;
                }
                _ => {}
            }
        }
        let _ = tx.send(Outcome {
            elicited,
            text: "<no response>".to_string(),
        });
    });

    let outcome = rx.recv_timeout(CASE_TIMEOUT);
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();
    outcome.expect("tools/call must produce a response before the timeout")
}

/// The regression this guards: under `2026-07-28` the host must still be able
/// to ask, and an approval must actually open the capability.
#[test]
fn consent_granted_allows_the_request_on_2026_07_28() {
    let outcome = run_case("2026-07-28", Some("accept"));
    assert!(
        outcome.elicited,
        "host must ask the client for consent, got: {}",
        outcome.text
    );
    assert!(
        outcome.text.contains("ConnectionRefused"),
        "granted consent must let the request out (expected a connect failure), got: {}",
        outcome.text
    );
}

#[test]
fn consent_refused_denies_the_request_on_2026_07_28() {
    let outcome = run_case("2026-07-28", Some("decline"));
    assert!(outcome.elicited, "host must ask: {}", outcome.text);
    assert!(
        outcome.text.contains("HttpRequestDenied"),
        "refused consent must block the request, got: {}",
        outcome.text
    );
}

/// The legacy revision must keep working unchanged.
#[test]
fn consent_still_works_on_2025_11_25() {
    let granted = run_case("2025-11-25", Some("accept"));
    assert!(granted.elicited, "host must ask: {}", granted.text);
    assert!(
        granted.text.contains("ConnectionRefused"),
        "granted consent must let the request out, got: {}",
        granted.text
    );

    let refused = run_case("2025-11-25", Some("decline"));
    assert!(
        refused.text.contains("HttpRequestDenied"),
        "refused consent must block the request, got: {}",
        refused.text
    );
}

/// A client that cannot be asked must not be asked — and must not be trusted.
#[test]
fn client_without_elicitation_support_degrades_to_deny() {
    let outcome = run_case("2026-07-28", None);
    assert!(
        !outcome.elicited,
        "must not elicit from a client that did not declare support: {}",
        outcome.text
    );
    assert!(
        outcome.text.contains("HttpRequestDenied"),
        "unaskable client must deny (fail-safe), got: {}",
        outcome.text
    );
}
