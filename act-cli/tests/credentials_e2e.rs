//! End-to-end proof of the property the whole credentials phase exists for:
//! a component receives a credential, and the value never appears anywhere
//! the agent can see.
//!
//! Everything here runs against real artifacts and the real binary — the
//! `act` under test, invoked as a subprocess; a prebuilt component that
//! actually imports `act:credentials/store`; and a credential provisioned by
//! running `act secret set`, not by writing store files from the test. The
//! only thing simulated is the agent, which is an rmcp client speaking MCP
//! stdio.
//!
//! ## The two artifacts
//!
//! `credentials-canary.wasm` and `credentials-canary-undeclared.wasm` are the
//! **same compiled bytes**, packed twice: once against an `act.toml` carrying
//! `[std.capabilities."act:credentials"]` and once against one without it.
//! That is what makes the negative test mean something — the two runs differ
//! in exactly one bit, what the artifact claims to need, and nothing else.
//! There is deliberately no flag that un-declares a capability: an undeclared
//! class is denied and no grant can widen it (design §4), so the only way to
//! exercise that path is a second artifact.
//!
//! See `tests/fixtures-src/README.md` for how both are built.

use std::io::Write;
use std::path::{Path, PathBuf};
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

/// The credential value provisioned into the store. Distinctive enough that
/// a substring search for it cannot collide with anything the host or the
/// component legitimately emits, and long enough that its length is a
/// meaningful check on its own.
const SECRET: &str = "sekrit-canary-value";

/// The key both canaries ask for — see `PROBE_KEY` in the fixture source.
const PROBE_KEY: &str = "probe";

fn act_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_act"))
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Write a credential into `component`'s profile by running `act secret set`,
/// exactly as a user would.
///
/// Deliberately not a direct `CredentialStore::put`: the profile namespace is
/// derived by `resolve::profile_key` on both sides, and a test that wrote the
/// store itself would pass even if the writer and the reader disagreed about
/// which profile a component owns — which is the one mistake that would make
/// every real provisioning silently invisible to the run.
fn provision(backend: &str, component: &Path, key: &str, kind: &str, fields_json: &str) {
    let mut child = std::process::Command::new(act_binary_path())
        .arg("secret")
        .arg("set")
        .arg(component)
        .args(["--key", key, "--kind", kind])
        .args(["--credentials-backend", backend])
        .arg("--fields-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn act secret set");
    child
        .stdin
        .as_mut()
        .expect("stdin was piped")
        .write_all(fields_json.as_bytes())
        .expect("write field map to act secret set");
    let out = child.wait_with_output().expect("act secret set");
    assert!(
        out.status.success(),
        "act secret set failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Everything one `tools/call` produced, split by who can see it.
struct Outcome {
    /// The whole MCP reply, serialized — content blocks, `structuredContent`,
    /// `isError`, every `_meta`. This is the agent's entire view, and it is
    /// what a leak search has to run against: asserting only on the text of
    /// the first block would miss a value smuggled through a metadata field.
    transport: String,
    /// Everything the host wrote to stderr, audit trail included. Not
    /// agent-visible, but the design forbids values here too.
    stderr: String,
}

impl Outcome {
    /// The concatenated text of every text block, parsed as JSON — what the
    /// canary actually returned.
    fn payload(&self) -> serde_json::Value {
        let reply: serde_json::Value =
            serde_json::from_str(&self.transport).expect("the reply is JSON");
        let text = reply
            .get("content")
            .and_then(|c| c.as_array())
            .map(|blocks| {
                blocks
                    .iter()
                    .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_default();
        serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("canary payload is not JSON ({e}): {text:?}"))
    }
}

/// Run one tool call against `component` over MCP stdio and collect both
/// sides of what it produced.
///
/// `--session-args '{}'` puts the run in session-of-1: the host opens one
/// session at startup and forces its id onto every call, which is what makes
/// `get-secret` reachable at all (it requires a live session, and a session
/// is live only after `open-session` has returned — design §8.3).
async fn call_over_mcp(component: &Path, extra_args: &[&str], tool: &str) -> Outcome {
    let component = component.to_path_buf();
    let extra: Vec<String> = extra_args.iter().map(|s| s.to_string()).collect();
    let (transport, stderr) = TokioChildProcess::builder(
        tokio::process::Command::new(act_binary_path()).configure(|cmd| {
            cmd.arg("run")
                .arg(&component)
                .arg("--mcp")
                .arg("--session-args")
                .arg("{}")
                .args(&extra);
        }),
    )
    .stderr(Stdio::piped())
    .spawn()
    .expect("spawn act run --mcp with piped stderr");

    let captured = Arc::new(AsyncMutex::new(String::new()));
    let sink = captured.clone();
    let mut lines = BufReader::new(stderr.expect("stderr was piped")).lines();
    let drain = tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            let mut buf = sink.lock().await;
            buf.push_str(&line);
            buf.push('\n');
        }
    });

    let client = ().serve(transport).await.expect("rmcp handshake");

    // A tool error can arrive either as a JSON-RPC error or as an `isError`
    // result; both are the agent's view, so both are serialized the same way
    // and searched the same way.
    let reply = match client
        .call_tool(CallToolRequestParams::new(tool.to_string()))
        .await
    {
        Ok(result) => serde_json::to_string(&result).expect("serialize CallToolResult"),
        Err(rmcp::ServiceError::McpError(e)) => {
            serde_json::to_string(&e).expect("serialize ErrorData")
        }
        Err(other) => panic!("unexpected transport failure: {other:?}"),
    };

    client.cancel().await.ok();
    // The child is gone, so the pipe closes and the drain task ends; joining
    // it is what guarantees every audit line the run emitted is in the buffer
    // before an assertion reads it.
    let _ = tokio::time::timeout(Duration::from_secs(5), drain).await;

    let stderr = captured.lock().await.clone();
    Outcome {
        transport: reply,
        stderr,
    }
}

/// The positive case, and the whole point of the phase.
///
/// Three things have to hold at once, and each is asserted separately because
/// each fails differently: the component saw the credential's *kind*, the
/// field map arrived carrying the *real* material (all 19 bytes of it — an
/// empty shell with the right kind on it would satisfy a laxer test), and
/// the value itself appears nowhere in the agent's view.
#[tokio::test]
async fn a_component_gets_its_credential_and_the_value_never_leaves_the_host() {
    let dir = tempfile::tempdir().unwrap();
    let backend = format!("file:{}", dir.path().display());
    let canary = fixture("credentials-canary.wasm");

    provision(
        &backend,
        &canary,
        PROBE_KEY,
        "std:opaque",
        &format!(r#"{{"std:value":"{SECRET}"}}"#),
    );

    let out = call_over_mcp(
        &canary,
        &[
            "--credentials-backend",
            &backend,
            "--allow",
            "act:credentials",
        ],
        "whoami",
    )
    .await;

    let payload = out.payload();
    assert_eq!(
        payload.get("kind").and_then(|v| v.as_str()),
        Some("std:opaque"),
        "the component saw the kind: {}",
        out.transport
    );
    assert_eq!(
        payload.get("has_fields").and_then(|v| v.as_bool()),
        Some(true),
        "and the fields: {}",
        out.transport
    );
    assert_eq!(
        payload.get("value_len").and_then(|v| v.as_u64()),
        Some(SECRET.len() as u64),
        "and the material itself, whole — not an empty field map wearing the \
         right kind: {}",
        out.transport
    );

    assert!(
        !out.transport.contains(SECRET),
        "but the value never reached the transport: {}",
        out.transport
    );
    assert!(!out.stderr.contains(SECRET), "nor the logs: {}", out.stderr);

    // The audit trail records that material crossed, and what it was —
    // component, session, key, kind, and nothing that could be a value.
    assert!(
        out.stderr.contains("credential") && out.stderr.contains("kind=std:opaque"),
        "the issue is audited: {}",
        out.stderr
    );
    assert!(
        out.stderr.contains(&format!("credential  {PROBE_KEY}")),
        "the audited issue names the key: {}",
        out.stderr
    );
}

/// The negative case: an artifact that does not declare `act:credentials` is
/// refused, and `--allow act:credentials` does not save it.
///
/// The grant is passed on purpose. An undeclared class is denied and no grant
/// can widen it (design §4), so a run without the flag would prove only that
/// ungranted is denied — the far weaker claim. The credential is provisioned
/// for this component too, so `denied` cannot be a miss wearing a denial's
/// name: the key is there, and the answer is still no.
#[tokio::test]
async fn an_undeclared_component_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    let backend = format!("file:{}", dir.path().display());
    let canary = fixture("credentials-canary-undeclared.wasm");

    provision(
        &backend,
        &canary,
        PROBE_KEY,
        "std:opaque",
        &format!(r#"{{"std:value":"{SECRET}"}}"#),
    );

    let out = call_over_mcp(
        &canary,
        &[
            "--credentials-backend",
            &backend,
            "--allow",
            "act:credentials",
        ],
        "whoami",
    )
    .await;

    assert!(
        out.transport.contains("denied"),
        "undeclared means denied (design §4): {}",
        out.transport
    );
    assert!(
        !out.transport.contains(SECRET),
        "and nothing crossed: {}",
        out.transport
    );
    assert!(!out.stderr.contains(SECRET), "nor the logs: {}", out.stderr);

    // The denial is the *ceiling's*, not the grant's — the distinction the
    // second artifact exists to make. `--allow act:credentials` was passed,
    // so a grant-shaped denial here would mean the declaration was never
    // consulted.
    assert!(
        out.stderr.contains("outside ceiling"),
        "denied by the ceiling, despite the grant: {}",
        out.stderr
    );
    // No credential-issue record: nothing was handed over, so the audit trail
    // must not claim otherwise.
    assert!(
        !out.stderr.contains("kind=std:opaque"),
        "a refused request must not produce an issue record: {}",
        out.stderr
    );
}

/// Ask-by-default, end to end: the declaring canary with no grant at all.
///
/// `act:credentials` resolves to `ask`, the run is headless (stdin is a pipe,
/// so the prompter is the denying one), and the credential is refused. The
/// companion to the test above: there, declaration was missing and the grant
/// could not help; here, the declaration is present and the *absence* of a
/// grant is what refuses.
#[tokio::test]
async fn a_declaring_component_with_no_grant_is_refused_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let backend = format!("file:{}", dir.path().display());
    let canary = fixture("credentials-canary.wasm");

    provision(
        &backend,
        &canary,
        PROBE_KEY,
        "std:opaque",
        &format!(r#"{{"std:value":"{SECRET}"}}"#),
    );

    let out = call_over_mcp(&canary, &["--credentials-backend", &backend], "whoami").await;

    assert!(
        out.transport.contains("denied"),
        "no grant means no credential, without anyone having to say deny: {}",
        out.transport
    );
    assert!(
        !out.transport.contains(SECRET),
        "and nothing crossed: {}",
        out.transport
    );
    assert!(!out.stderr.contains(SECRET), "nor the logs: {}", out.stderr);

    // Refused *as an unanswered ask*, not by the ceiling — the audit trail
    // renders the two differently (`ask-deny` here, `outside ceiling` in the
    // test above), so this is what keeps the two negative tests from being
    // the same test written twice.
    assert!(
        out.stderr.contains("ask-deny"),
        "the refusal is an ask nobody could answer, not a ceiling denial: {}",
        out.stderr
    );
    assert!(
        !out.stderr.contains("outside ceiling"),
        "the declaration was honoured; only the grant was missing: {}",
        out.stderr
    );
}
