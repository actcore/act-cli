//! End-to-end proof that `act:consent/consent-authority` reaches a real
//! guest and that the host's decision procedure — not just `ConsentGate::decide`
//! in isolation — governs it.
//!
//! `crates/act-runtime::consent::gate`'s unit tests already exercise every
//! branch of ACT-CONSENT.md §4 against `ConsentGate` directly, with no
//! engine, no linker and no guest. What they cannot see is the WIT bridge
//! itself: linking `act:consent/consent-authority` into a real component,
//! lowering a guest-constructed `consent-request` across the boundary, and
//! the audit trail an operator actually reads at the CLI. That is what these
//! tests are for.
//!
//! The fixture is `consent-canary.wasm` (see `tests/fixtures-src/README.md`):
//! its one tool, `drop_database`, asks for class `db:drop` naming the
//! database as `key`, and never touches anything regardless of the answer —
//! it is a canary, not a database client.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn act_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_act"))
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Run `act call <fixture> drop_database --args '{"database": ..}'` plus
/// whatever grant flags the case needs, with stdin closed so `ask` is
/// deterministically headless (no TTY, so `tty_or_deny_prompter` picks
/// `DenyPrompter` — same trick `audit_cli.rs`'s ask tests use).
fn call_drop(fixture_name: &str, database: &str, extra: &[&str]) -> std::process::Output {
    act_bin()
        .arg("call")
        .arg(fixture(fixture_name))
        .arg("drop_database")
        .arg("--args")
        .arg(format!(r#"{{"database":"{database}"}}"#))
        .args(extra)
        .stdin(Stdio::null())
        .output()
        .expect("ran act")
}

/// Find the one immediate exception line (`✗ deny` or `? ask-*`) in stderr,
/// or panic with the full trail for debugging.
fn find_exception<'a>(stderr: &'a str, prefix: &str) -> &'a str {
    stderr
        .lines()
        .find(|l| l.starts_with(prefix))
        .unwrap_or_else(|| panic!("no line starting with {prefix:?} in stderr: {stderr}"))
}

/// Default policy is `ask`, and this call's own stdin is `/dev/null` (see
/// `call_drop`) — there is no channel to a human, so `ask` degrades to deny
/// per ACT-CONSENT.md §5. Asserted deliberately as the deny case, not a
/// surprise: this is what every headless invocation with no grant looks like.
#[test]
fn ask_without_a_channel_denies() {
    let out = call_drop("consent-canary.wasm", "analytics", &[]);
    assert!(
        !out.status.success(),
        "headless ask with no prompt channel must deny: {out:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("std:capability-denied"),
        "the canary must report the refusal as std:capability-denied, got: {stderr}"
    );

    // `find_exception`'s prefix match already pins the decision
    // (ask-deny); these two pin the class and the key. Deliberately not
    // asserting a specific reason string here — M1 changed it from "denied
    // by user" (which lied: nobody was consulted) to "no prompt channel",
    // and pinning either exact wording in this end-to-end test would only
    // make it brittle against the next such correction. `record.rs`'s
    // `a_no_channel_degrade_is_not_attributed_to_the_user` and
    // `fs_policy.rs`'s `ask_resolution_with_no_channel_is_not_attributed_to_the_user`
    // are where that reason string is actually pinned.
    let ask_line = find_exception(&stderr, "audit: ? ask-deny");
    assert!(
        ask_line.contains("db:drop"),
        "ask-deny line must name the class, got: {ask_line}"
    );
    assert!(
        ask_line.contains("analytics"),
        "ask-deny line must name the key, got: {ask_line}"
    );
}

/// `--deny db:drop` makes the refusal explicit, rather than it falling out
/// of having no channel — the companion negative case to the default above.
#[test]
fn an_explicit_deny_refuses() {
    let out = call_drop("consent-canary.wasm", "analytics", &["--deny", "db:drop"]);
    assert!(
        !out.status.success(),
        "an explicit --deny must refuse: {out:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("std:capability-denied"), "got: {stderr}");

    let deny_line = find_exception(&stderr, "audit: \u{2717} deny");
    assert!(
        deny_line.contains("db:drop"),
        "deny line must name the class, got: {deny_line}"
    );
    assert!(
        deny_line.contains("analytics"),
        "deny line must name the key, got: {deny_line}"
    );
    // Resolved through the grant's mode (deny), not through an unmatched
    // declared constraint — but the ceiling classifier reports both the
    // same way (`statik`'s default reason), so this is the one substring
    // both share rather than a claim about *which* step produced it.
    assert!(deny_line.contains("outside ceiling"), "got: {deny_line}");
}

/// A grant narrower than the request denies; one that covers it allows.
/// Same declared class (a bare declaration — the ceiling itself imposes no
/// constraint, ACT-CONSENT.md §3.1), same call shape, only the key and the
/// grant differ — so this is squarely the operator's `--grant` doing the
/// bounding, not the manifest.
#[test]
fn an_allowlist_grant_bounds_which_databases() {
    let grant = r#"{"db:drop":{"mode":"allowlist","allow":[{"key":"test_*"}]}}"#;

    let allowed = call_drop("consent-canary.wasm", "test_scratch", &["--grant", grant]);
    assert!(
        allowed.status.success(),
        "a key inside the allowlist must be allowed: {allowed:?}"
    );
    let stdout = String::from_utf8_lossy(&allowed.stdout);
    let payload: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout is JSON ({e}): {stdout}"));
    assert_eq!(
        payload.get("dropped").and_then(|v| v.as_str()),
        Some("test_scratch"),
        "the canary reports the allowed key, having touched nothing: {stdout}"
    );
    // I2: a consent decision never folds into the rollup (it is a semantic
    // class, not a physical one) — it must appear as its own immediate
    // `✓ allow` line naming the key, not as a `db:drop:` clause folded into
    // the tool call's rollup line the way a filesystem `read` would be.
    let allowed_stderr = String::from_utf8_lossy(&allowed.stderr);
    let allow_line = find_exception(&allowed_stderr, "audit: \u{2713} allow");
    assert!(
        allow_line.contains("db:drop"),
        "allow line must name the class, got: {allow_line}"
    );
    assert!(
        allow_line.contains("test_scratch"),
        "allow line must name the allowed key, got: {allow_line}"
    );
    let rollup = allowed_stderr
        .lines()
        .find(|l| l.starts_with("audit: \u{25cf}"))
        .unwrap_or_else(|| panic!("no rollup line in stderr: {allowed_stderr}"));
    assert!(
        !rollup.contains("db:drop"),
        "the allow must not also be folded into the rollup line, got: {rollup}"
    );

    let denied = call_drop("consent-canary.wasm", "production", &["--grant", grant]);
    assert!(
        !denied.status.success(),
        "a key outside the allowlist must be denied: {denied:?}"
    );
    let denied_stderr = String::from_utf8_lossy(&denied.stderr);
    let deny_line = find_exception(&denied_stderr, "audit: \u{2717} deny");
    assert!(deny_line.contains("db:drop"), "got: {deny_line}");
    assert!(
        deny_line.contains("production"),
        "deny line must name the key it refused, got: {deny_line}"
    );
}

/// The class is declared, so `--allow` opens it to its declared ceiling.
/// `consent-canary`'s declaration is bare (no `[[allow]]` constraints), so
/// the class itself is the whole of the ceiling and `open` authorizes every
/// key.
#[test]
fn allow_opens_the_declared_class() {
    let out = call_drop("consent-canary.wasm", "anything", &["--allow", "db:drop"]);
    assert!(
        out.status.success(),
        "an opened declared class must allow: {out:?}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let payload: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout is JSON ({e}): {stdout}"));
    assert_eq!(
        payload.get("dropped").and_then(|v| v.as_str()),
        Some("anything"),
        "got: {stdout}"
    );

    // I2: before the fix, an authorized `db:drop` folded into the same
    // per-call rollup a filesystem read does, and this line would have read
    // `db:drop: 1 request` — the class, but not *which* key was authorized.
    // A consent decision must print immediately and name the key, the same
    // way a credential issue does, and must not also appear in a rollup
    // count for this class.
    let stderr = String::from_utf8_lossy(&out.stderr);
    let allow_line = find_exception(&stderr, "audit: \u{2713} allow");
    assert!(
        allow_line.contains("db:drop"),
        "allow line must name the class, got: {allow_line}"
    );
    assert!(
        allow_line.contains("anything"),
        "allow line must name the key that was authorized, got: {allow_line}"
    );
    assert!(
        !stderr.contains("db:drop: 1 request"),
        "the allow must not also be folded into a rollup count, got: {stderr}"
    );
}

/// The paired undeclared artifact: identical compiled bytes, packed against
/// a manifest that never mentions `db:drop` (see
/// `tests/fixtures-src/README.md`). `--allow db:drop` is passed on purpose —
/// ACT-CONSENT.md §4 step 1 says an undeclared class must be refused before
/// the operator is consulted, and no grant can widen it, so a run *without*
/// the flag would only prove the far weaker "ungranted is denied". The audit
/// line must say the class was never declared, not that a grant refused it
/// or that an ask went unanswered, and no ask/elicitation must have been
/// attempted at all.
#[test]
fn an_undeclared_class_is_refused_without_a_prompt() {
    let out = call_drop(
        "consent-canary-undeclared.wasm",
        "analytics",
        &["--allow", "db:drop"],
    );
    assert!(
        !out.status.success(),
        "undeclared must be refused even under --allow: {out:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("std:capability-denied"), "got: {stderr}");

    let deny_line = find_exception(&stderr, "audit: \u{2717} deny");
    assert!(deny_line.contains("db:drop"), "got: {deny_line}");
    assert!(
        deny_line.contains("class not declared in act:component"),
        "the audit line must say the class was never declared, got: {deny_line}"
    );
    assert!(
        !stderr.contains("ask-deny") && !stderr.contains("ask-allow"),
        "an undeclared class must never reach the ask path at all: {stderr}"
    );
}

// ── The DecisionCache-sharing property, proven end to end ──────────────────
//
// `ConsentGate::from_accessor` clones the run's `Arc<DecisionCache>` out of
// `HostState` on *every* call to `request` — see the module docs on
// `crates/act-runtime/src/consent/gate.rs`. If it instead built a fresh
// cache per gate, every unit test in that module would still pass (each
// calls `.decide()` twice on the *same* `ConsentGate` value, so the cache is
// trivially shared), while ACT-CONSENT.md §5's "remember for at least the
// component run" would silently die: a component asking the same question
// twice would re-prompt every time.
//
// The only way to observe this is two *separately constructed* gates
// sharing one `HostState` — which is exactly what two `tools/call`s against
// one running component give you. Driving that through a full `HostState`
// in a unit test would mean rebuilding `create_store`'s WASI/HTTP/policy
// wiring from scratch in the test (a second copy of exactly the kind of
// security-relevant construction this phase's own module docs warn drifts),
// so this is proven here instead, against the real bridge and a real MCP
// elicitation round-trip, mirroring `ask_mcp_elicitation.rs`.

use std::io::{BufRead, BufReader, Write};
use std::sync::mpsc;
use std::time::Duration;

const CASE_TIMEOUT: Duration = Duration::from_secs(60);

/// Drive one `act run --mcp` session over raw JSON-RPC: initialize with
/// elicitation support, then call `drop_database` twice in the same session
/// (same subprocess, same `Store<HostState>` — the whole point) — once for
/// `first_database`, once for `second_database`. Answers every
/// `elicitation/create` with `accept`. Returns the number of elicitations
/// actually sent and both calls' results.
fn call_twice_over_mcp(
    first_database: &str,
    second_database: &str,
) -> (usize, serde_json::Value, serde_json::Value) {
    let fixture_path = fixture("consent-canary.wasm");
    let mut child = Command::new(env!("CARGO_BIN_EXE_act"))
        .args(["run"])
        .arg(&fixture_path)
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn act run --mcp");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let first_database = first_database.to_string();
    let second_database = second_database.to_string();

    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut send = |value: serde_json::Value| {
            let _ = writeln!(stdin, "{value}");
            let _ = stdin.flush();
        };

        send(serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2026-07-28",
                "capabilities": { "elicitation": {} },
                "clientInfo": { "name": "consent-cache-sharing-test", "version": "0" },
            }
        }));

        let mut elicited = 0usize;
        let mut results: Vec<serde_json::Value> = Vec::new();
        for line in stdout.lines() {
            let Ok(line) = line else { break };
            let Ok(message) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };

            if message.get("method").and_then(|m| m.as_str()) == Some("elicitation/create") {
                elicited += 1;
                send(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": { "action": "accept" },
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
                        "params": { "name": "drop_database", "arguments": { "database": first_database } }
                    }));
                }
                Some(2) => {
                    results.push(message.clone());
                    send(serde_json::json!({
                        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                        "params": { "name": "drop_database", "arguments": { "database": second_database } }
                    }));
                }
                Some(3) => {
                    results.push(message.clone());
                    let _ = tx.send((elicited, results.clone()));
                    return;
                }
                _ => {}
            }
        }
        let _ = tx.send((elicited, results));
    });

    let (elicited, results) = rx
        .recv_timeout(CASE_TIMEOUT)
        .expect("both tools/calls must produce a response before the timeout");
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();

    assert_eq!(results.len(), 2, "expected exactly two tools/call replies");
    (elicited, results[0].clone(), results[1].clone())
}

/// The property itself: two calls asking about the *same* `(class, key)`
/// must reach the human once, not twice, because both gates share the one
/// `HostState::consent_cache`.
#[test]
fn a_repeated_question_is_asked_once_not_per_call() {
    let (elicited, first, second) = call_twice_over_mcp("test_scratch", "test_scratch");
    assert_eq!(
        elicited, 1,
        "the same (class, key) must not re-prompt across separate calls; \
         a fresh cache per gate would have asked twice: first={first} second={second}"
    );
    for (label, reply) in [("first", &first), ("second", &second)] {
        assert_eq!(
            reply
                .get("result")
                .and_then(|r| r.get("isError"))
                .and_then(|v| v.as_bool()),
            Some(false),
            "{label} call must have been allowed: {reply}"
        );
    }
}

/// The negative control for the test above: two calls asking about
/// *different* keys must each be asked. Without this, a host that ignored
/// `key` entirely — remembering "db:drop was approved" rather than
/// "db:drop for test_scratch was approved" — would also pass the test
/// above, having collapsed two distinct questions into one blanket
/// authorization. `gate.rs`'s own unit test
/// `ask_reaches_the_prompter_once_per_key_and_is_remembered` pins the same
/// property against `ConsentGate::decide` directly; this is its end-to-end
/// counterpart, through two independently constructed gates.
#[test]
fn a_different_key_is_still_asked_about() {
    let (elicited, _first, _second) = call_twice_over_mcp("test_scratch", "production");
    assert_eq!(
        elicited, 2,
        "two distinct keys must each be asked about, not folded into one answer"
    );
}
