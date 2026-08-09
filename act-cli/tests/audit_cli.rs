//! The audit trail's user-facing contract at the CLI surface.
//!
//! The layer's own behaviour is unit-tested in `act-audit`. These subprocess
//! tests assert the guarantee that cannot be tested in-crate: that the trail
//! survives every log-level knob a user can reach for.

use std::process::Command;

fn act_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_act"))
}

#[test]
fn audit_flags_are_recognised() {
    let out = act_bin()
        .args(["call", "--help"])
        .output()
        .expect("ran act");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("--no-audit"), "missing --no-audit in: {text}");
    assert!(
        text.contains("--audit-args"),
        "missing --audit-args in: {text}"
    );
}

#[test]
fn rust_log_off_does_not_disable_the_audit_layer() {
    // The trail must not be silenceable through log-level configuration.
    // A missing component fails before instantiation, so we assert on the
    // flag surface rather than on emitted records; record-level coverage
    // lives in the component-backed test below.
    let out = act_bin()
        .env("RUST_LOG", "off")
        .args(["call", "--help"])
        .output()
        .expect("ran act");
    assert!(out.status.success());
}

/// `call-tool` never returns `result<tool-result, error>` — a guest failure
/// arrives as a `tool-event::error` inside an otherwise `Ok` response (the
/// same shape `rmcp_bridge::fold_events_to_result` inspects to build an MCP
/// error response). The audit outcome has to be read off the events, not the
/// outer `Result`, or every guest failure would audit as `ok`.
#[test]
fn a_guest_tool_error_is_audited_as_tool_error_not_ok() {
    let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sessions-canary.wasm");

    // `read` looks up per-session counter state by `std:session-id`; an id
    // that was never opened makes the guest itself report a `std:not-found`
    // tool-event::error — same failure `mcp_stdio_rmcp.rs`'s
    // `error_kind_reaches_the_client` provokes over MCP, reached here
    // directly via `-m` instead of MCP's `_meta` argument mapping.
    let out = act_bin()
        .args([
            "call",
            fixture.to_str().expect("fixture path is utf-8"),
            "read",
            "--args",
            "{}",
            "-m",
            "std:session-id=sid-does-not-exist",
        ])
        .output()
        .expect("ran act");

    let stderr = String::from_utf8_lossy(&out.stderr);
    // The instantiation header (Task 10) also starts with "audit: ", now the
    // first line in this stream — match the rollup marker specifically, same
    // as every other test below that looks for the per-call summary line.
    let audit_line = stderr
        .lines()
        .find(|l| l.starts_with("audit: \u{25cf}"))
        .unwrap_or_else(|| panic!("no audit rollup line in stderr: {stderr}"));
    assert!(
        audit_line.contains("tool-error"),
        "guest failure must audit as tool-error, got: {audit_line}"
    );
    assert!(
        !audit_line.contains(" ok "),
        "guest failure must not audit as ok: {audit_line}"
    );
}

/// `fs_policy.rs` emits a `CapDecisionRecord` at each of the two points a
/// filesystem decision actually resolves: the static ceiling classification
/// (`check_path_sync`) and the deferred `ask` resolution (`resolve_ask`).
/// Everything else covering that wiring (`fs_policy.rs`'s own `mod tests`,
/// `act-audit`'s `record.rs`/`render.rs`) exercises the record types and
/// the renderer directly, never the two call sites themselves — so this is
/// the only test that would notice if `check_path_sync` or `resolve_ask`
/// stopped calling `emit_cap_decision` at all. Runs the real `fs-canary`
/// fixture (declares `wasi:filesystem` with an unbounded ceiling, so a
/// `--grant` is what actually narrows it) through both outcomes in one
/// process: a granted read and an out-of-ceiling read.
#[test]
fn fs_decisions_reach_the_audit_trail() {
    let fixture =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fs-canary.wasm");

    let dir = tempfile::TempDir::new().expect("tempdir");
    let allowed = dir.path().join("ok.txt");
    std::fs::write(&allowed, "granted content").expect("write fixture file");
    let rule = format!("{}/**", dir.path().display());
    let grant = format!(
        r#"{{"wasi:filesystem":{{"mode":"allowlist","allow":[{{"path":"{rule}","mode":"rw"}}]}}}}"#
    );

    // In-ceiling read: the rollup line must carry the `filesystem:` clause
    // naming the matched rule, proving `check_path_sync`'s `Allow` arm ran.
    let out = act_bin()
        .args([
            "call",
            fixture.to_str().expect("fixture path is utf-8"),
            "read",
            "--args",
            &format!(r#"{{"path":"{}"}}"#, allowed.display()),
            "--grant",
            &grant,
        ])
        .output()
        .expect("ran act");
    assert!(out.status.success(), "granted read must succeed: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let rollup = stderr
        .lines()
        .find(|l| l.starts_with("audit: \u{25cf}"))
        .unwrap_or_else(|| panic!("no rollup line in stderr: {stderr}"));
    assert!(
        rollup.contains("filesystem:"),
        "rollup must carry a filesystem: clause, got: {rollup}"
    );
    assert!(
        rollup.contains(&format!("under {rule}")),
        "rollup must name the matched rule, got: {rollup}"
    );

    // Out-of-ceiling read: an immediate `✗ deny` line must appear, proving
    // `check_path_sync`'s `Deny` arm ran — same grant, a path it doesn't cover.
    let outside = std::path::Path::new("/etc/passwd");
    let out = act_bin()
        .args([
            "call",
            fixture.to_str().expect("fixture path is utf-8"),
            "read",
            "--args",
            &format!(r#"{{"path":"{}"}}"#, outside.display()),
            "--grant",
            &grant,
        ])
        .output()
        .expect("ran act");
    assert!(
        !out.status.success(),
        "out-of-ceiling read must be denied: {out:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let deny_line = stderr
        .lines()
        .find(|l| l.starts_with("audit: \u{2717} deny"))
        .unwrap_or_else(|| panic!("no immediate deny line in stderr: {stderr}"));
    assert!(
        deny_line.contains("wasi:filesystem"),
        "deny line must name the capability, got: {deny_line}"
    );
    assert!(
        deny_line.contains("outside ceiling"),
        "deny line must carry the reason, got: {deny_line}"
    );
}

/// `resolve_ask`'s `emit_cap_decision` call is the third decision point and
/// the one `fs_decisions_reach_the_audit_trail` above cannot reach: that
/// test only runs under `allowlist`, and `Decision::Ask` — the only way
/// `check_path_sync` reaches the `Ask` arm and defers to `resolve_ask` — is
/// returned only in `ask` mode. Confirmed by disabling `resolve_ask`'s
/// `emit_cap_decision` call and re-running: the other test still passes.
///
/// Runs `fs-canary` under an `ask`-mode grant with stdin closed. No prompt
/// channel makes `main.rs`'s `tty_or_deny_prompter` pick `DenyPrompter`
/// deterministically (`std::io::IsTerminal::is_terminal` on a null stdin is
/// always `false`), so `ask` degrades to deny — but critically,
/// `resolve_ask` still *runs* to produce that verdict, it isn't skipped.
#[test]
fn fs_ask_resolution_reaches_the_audit_trail() {
    let fixture =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fs-canary.wasm");

    let dir = tempfile::TempDir::new().expect("tempdir");
    let target = dir.path().join("ok.txt");
    std::fs::write(&target, "content").expect("write fixture file");

    // Bare "ask" mode with no allow list: the wasi:filesystem provider
    // special-cases `ask` to inherit the component's DECLARED ceiling
    // wholesale (fs-canary declares `**`, rw) rather than intersecting
    // against an empty user allow list, so this path still lands in-ceiling
    // (`Ask`), not an immediate out-of-ceiling deny.
    let out = act_bin()
        .args([
            "call",
            fixture.to_str().expect("fixture path is utf-8"),
            "read",
            "--args",
            &format!(r#"{{"path":"{}"}}"#, target.display()),
            "--grant",
            r#"{"wasi:filesystem":"ask"}"#,
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("ran act");
    assert!(
        !out.status.success(),
        "headless ask with no prompt channel must degrade to deny: {out:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let ask_line = stderr
        .lines()
        .find(|l| l.starts_with("audit: ? ask-deny"))
        .unwrap_or_else(|| panic!("no immediate ask-deny line in stderr: {stderr}"));
    assert!(
        ask_line.contains("wasi:filesystem"),
        "ask-deny line must name the capability, got: {ask_line}"
    );
    assert!(
        ask_line.contains("denied by user"),
        "ask-deny line must carry the reason, got: {ask_line}"
    );
}

/// `http_policy.rs`'s `decide_uri` emits at the two points an HTTP decision
/// actually resolves: the static ceiling classification (inline in
/// `decide_uri`) and — for the deferred `ask` case — the point where the p2/p3
/// `send_request` hooks resolve `cache.decide_cached(..)`. Everything else
/// covering this (`http_policy.rs`'s own `mod tests`, `act-audit`'s
/// `record.rs`/`render.rs`) exercises the record types directly, never these
/// call sites — so this is the only test that would notice if `decide_uri`
/// stopped calling `emit_cap_decision` at all.
///
/// Runs the real `ask-canary` fixture (declares `wasi:http` with an
/// unbounded `host = "*"` ceiling, so a `--grant` is what actually narrows
/// it) against a dead loopback port (`127.0.0.1:1`, nothing listens there).
/// That makes an allowed-but-unreachable request (`ConnectionRefused`, blocked
/// at the transport) distinguishable from a policy-denied one
/// (`HttpRequestDenied`, blocked before the request leaves) without standing
/// up a server — same trick `tests/ask_mcp_elicitation.rs` already relies on.
#[test]
fn http_decisions_reach_the_audit_trail() {
    let fixture =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ask-canary.wasm");

    // In-ceiling allow: the rollup line must carry the `http:` clause naming
    // the matched rule, proving `decide_uri`'s `Allow` arm ran. The request
    // itself still fails (nothing listens on port 1) — that failure is
    // reported as a guest tool-error, not a policy denial, distinguishing an
    // audited allow from an audited deny.
    let out = act_bin()
        .args([
            "call",
            fixture.to_str().expect("fixture path is utf-8"),
            "fetch",
            "--args",
            r#"{"url":"http://127.0.0.1:1/"}"#,
            "--grant",
            r#"{"wasi:http":{"mode":"allowlist","allow":[{"host":"127.0.0.1"}]}}"#,
        ])
        .output()
        .expect("ran act");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ConnectionRefused"),
        "an allowed request must reach the transport, got: {stderr}"
    );
    let rollup = stderr
        .lines()
        .find(|l| l.starts_with("audit: \u{25cf}"))
        .unwrap_or_else(|| panic!("no rollup line in stderr: {stderr}"));
    assert!(
        rollup.contains("http:"),
        "rollup must carry an http: clause, got: {rollup}"
    );
    assert!(
        rollup.contains("under 127.0.0.1"),
        "rollup must name the matched rule, got: {rollup}"
    );

    // Out-of-ceiling deny: an immediate `✗ deny` line must appear, proving
    // `decide_uri`'s `Deny` arm ran — same grant shape, a host it doesn't
    // cover. The request never leaves the host, so the guest sees
    // `HttpRequestDenied` rather than a transport error.
    let out = act_bin()
        .args([
            "call",
            fixture.to_str().expect("fixture path is utf-8"),
            "fetch",
            "--args",
            r#"{"url":"http://127.0.0.1:1/"}"#,
            "--grant",
            r#"{"wasi:http":{"mode":"allowlist","allow":[{"host":"10.0.0.1"}]}}"#,
        ])
        .output()
        .expect("ran act");
    assert!(
        !out.status.success(),
        "out-of-ceiling request must be denied: {out:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("HttpRequestDenied"),
        "a denied request must be blocked before the transport, got: {stderr}"
    );
    let deny_line = stderr
        .lines()
        .find(|l| l.starts_with("audit: \u{2717} deny"))
        .unwrap_or_else(|| panic!("no immediate deny line in stderr: {stderr}"));
    assert!(
        deny_line.contains("wasi:http"),
        "deny line must name the capability, got: {deny_line}"
    );
    assert!(
        deny_line.contains("outside ceiling"),
        "deny line must carry the reason, got: {deny_line}"
    );
}

/// The `Decision::Ask` arms of `send_request` (p2/p3) are the decision point
/// `http_decisions_reach_the_audit_trail` above cannot reach: that test only
/// runs under `allowlist`, and `Decision::Ask` — the only way `decide_uri`
/// defers to the ask path — is returned only in `ask` mode. Confirmed by
/// disabling the `emit_cap_decision` call in those arms and re-running: the
/// other test still passes.
///
/// Runs `ask-canary` under an `ask`-mode grant with stdin closed. No prompt
/// channel makes `main.rs`'s `tty_or_deny_prompter` pick `DenyPrompter`
/// deterministically, so `ask` degrades to deny — but critically, the ask
/// path still *runs* to produce that verdict, it isn't skipped.
#[test]
fn http_ask_resolution_reaches_the_audit_trail() {
    let fixture =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ask-canary.wasm");

    let out = act_bin()
        .args([
            "call",
            fixture.to_str().expect("fixture path is utf-8"),
            "fetch",
            "--args",
            r#"{"url":"http://127.0.0.1:1/"}"#,
            "--grant",
            r#"{"wasi:http":"ask"}"#,
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("ran act");
    assert!(
        !out.status.success(),
        "headless ask with no prompt channel must degrade to deny: {out:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let ask_line = stderr
        .lines()
        .find(|l| l.starts_with("audit: ? ask-deny"))
        .unwrap_or_else(|| panic!("no immediate ask-deny line in stderr: {stderr}"));
    assert!(
        ask_line.contains("wasi:http"),
        "ask-deny line must name the capability, got: {ask_line}"
    );
    assert!(
        ask_line.contains("denied by user"),
        "ask-deny line must carry the reason, got: {ask_line}"
    );
}

/// The instantiation header (`instantiate_component`, Task 10): what is
/// running and under what modes, rendered from `act_audit::instantiation_span`
/// and `emit_ceiling_class` before the tool-call span for the first call even
/// opens. Reuses `fs-canary` (declares `wasi:filesystem`) under a scoped
/// grant so the header's per-class clause has a real, non-deny mode to show.
///
/// Asserted as the very first stderr line (not just "present somewhere") —
/// that is what proves it precedes the rollup line the same call also
/// produces, and precedes the tool's own stdout content, which never reaches
/// the guest until instantiation (and this header) has already completed.
#[test]
fn instantiation_header_precedes_any_tool_output() {
    let fixture =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fs-canary.wasm");

    let dir = tempfile::TempDir::new().expect("tempdir");
    let target = dir.path().join("ok.txt");
    std::fs::write(&target, "content").expect("write fixture file");
    let rule = format!("{}/**", dir.path().display());
    let grant = format!(
        r#"{{"wasi:filesystem":{{"mode":"allowlist","allow":[{{"path":"{rule}","mode":"rw"}}]}}}}"#
    );

    let out = act_bin()
        .args([
            "call",
            fixture.to_str().expect("fixture path is utf-8"),
            "read",
            "--args",
            &format!(r#"{{"path":"{}"}}"#, target.display()),
            "--grant",
            &grant,
        ])
        .output()
        .expect("ran act");
    assert!(out.status.success(), "granted read must succeed: {out:?}");

    let stderr = String::from_utf8_lossy(&out.stderr);
    let first_line = stderr
        .lines()
        .next()
        .unwrap_or_else(|| panic!("no stderr output at all: {stderr}"));
    assert!(
        first_line.starts_with("audit: ") && first_line.contains("sha256:"),
        "expected the instantiation header as the first stderr line, got: {stderr}"
    );
    assert!(
        first_line.contains("wasi:filesystem=allowlist"),
        "header must show the resolved mode for a declared class, got: {first_line}"
    );

    // The guest's own output belongs on stdout, untouched by the audit trail.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.trim_end(),
        "content",
        "tool content must land on stdout only"
    );
    assert!(
        !stdout.contains("audit: "),
        "no audit line may leak onto stdout, got: {stdout}"
    );
}

/// Complements the test above: a declared capability that resolves to `deny`
/// (here, explicitly via `--deny`, not just "never declared") must produce a
/// second stderr line — right after the header — naming it as declared but
/// not granted. `layer.rs`'s unit tests already cover the render_header /
/// warning-line logic directly; this is the one test that would notice if
/// `instantiate_component` stopped calling `emit_ceiling_class` with a real
/// `declared` value at all.
#[test]
fn instantiation_header_warns_when_a_declared_capability_is_denied() {
    let fixture =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fs-canary.wasm");

    let out = act_bin()
        .args([
            "call",
            fixture.to_str().expect("fixture path is utf-8"),
            "read",
            "--args",
            r#"{"path":"/nonexistent"}"#,
            "--deny",
            "wasi:filesystem",
        ])
        .output()
        .expect("ran act");

    let stderr = String::from_utf8_lossy(&out.stderr);
    let mut lines = stderr.lines();
    let header = lines
        .next()
        .unwrap_or_else(|| panic!("no stderr output at all: {stderr}"));
    assert!(
        header.starts_with("audit: ") && header.contains("wasi:filesystem=deny"),
        "expected the header with filesystem denied first, got: {stderr}"
    );
    let warning = lines
        .next()
        .unwrap_or_else(|| panic!("no second stderr line (warning) after header: {stderr}"));
    assert!(
        warning.starts_with("audit: ") && warning.contains("not granted"),
        "expected the declared-but-ungranted warning right after the header, got: {warning}"
    );
    assert!(
        warning.contains("wasi:filesystem"),
        "warning must name the ungranted class, got: {warning}"
    );
}

/// The scenario the two tests above sidestep with an explicit `--grant`/
/// `--deny`, and the one that matters most: a headless invocation with **no
/// grant flags at all**. The host is ask-by-default, so the header still
/// shows `wasi:filesystem=ask` (that really is the configured policy, and
/// must not change) — but headless has no prompt channel, so
/// `tty_or_deny_prompter()` picks `DenyPrompter` and every `ask` decision
/// degrades to deny before anyone is asked. Without the fix this test pins,
/// the header showed `ask` and nothing warned that the component would in
/// practice get nothing — the one signal this feature exists to deliver,
/// silent in the single most common invocation shape (CI, automation, an
/// agent driving the CLI).
#[test]
fn instantiation_header_warns_when_declared_ask_has_no_prompt_channel() {
    let fixture =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fs-canary.wasm");

    let out = act_bin()
        .args([
            "call",
            fixture.to_str().expect("fixture path is utf-8"),
            "read",
            "--args",
            r#"{"path":"/nonexistent"}"#,
        ])
        // No --grant / --allow / --deny at all: this is the default,
        // ask-by-default policy. Explicit null stdin makes the "no prompt
        // channel" condition deterministic regardless of how the test
        // harness itself was invoked (matches `fs_ask_resolution_reaches_the_audit_trail`'s
        // existing pattern for the same reason).
        .stdin(std::process::Stdio::null())
        .output()
        .expect("ran act");

    let stderr = String::from_utf8_lossy(&out.stderr);
    let mut lines = stderr.lines();
    let header = lines
        .next()
        .unwrap_or_else(|| panic!("no stderr output at all: {stderr}"));
    assert!(
        header.starts_with("audit: ") && header.contains("wasi:filesystem=ask"),
        "header must keep showing the configured mode (ask), unchanged, got: {stderr}"
    );
    let warning = lines
        .next()
        .unwrap_or_else(|| panic!("no second stderr line (warning) after header: {stderr}"));
    // Deliberately specific: a per-access "? ask-deny ... denied by user"
    // exception line (from the actual failed read) also starts with
    // "audit: ", also names wasi:filesystem, and also contains "denied" —
    // so a looser assertion here would pass even with the instantiation-time
    // warning entirely disabled, as long as an unrelated per-access denial
    // happened to land as line two. "no prompt channel" is wording only the
    // new warning uses.
    assert!(
        warning.starts_with("audit: ") && warning.contains("no prompt channel"),
        "expected the ask-but-no-prompt-channel warning right after the header, got: {warning}"
    );
    assert!(
        warning.contains("wasi:filesystem"),
        "warning must name the affected class, got: {warning}"
    );
    assert!(
        warning.contains("denied"),
        "warning must name the reason (every access will be denied), got: {warning}"
    );
}

/// Auth is carried in session args (`ACT-AUTH.md`): a component that needs a
/// token gets it through `open-session`, never through tool-call arguments.
/// The audit trail writes to stderr, which an operator watches and which
/// MCP clients capture into their server-log pane — if a token could reach
/// that stream, every ACT user's terminal scrollback and every MCP client's
/// log file would become a credential store. This must hold with
/// `--audit-args` too: that flag widens tool arguments, never session args.
/// Uses `sessions-canary` (the fixture that actually takes session args) so
/// there is a real `open-session` call in the path, not a hypothetical one.
#[test]
fn session_args_never_appear_in_the_audit_trail() {
    let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sessions-canary.wasm");
    const SECRET: &str = "sk-do-not-log-me-0123456789";
    for extra in [vec![], vec!["--audit-args"]] {
        let mut cmd = act_bin();
        cmd.args([
            "call",
            fixture.to_str().expect("fixture path is utf-8"),
            "read",
            "--args",
            "{}",
        ]);
        cmd.args(["--session-args", &format!(r#"{{"token":"{SECRET}"}}"#)]);
        cmd.args(&extra);
        let out = cmd.output().expect("ran act");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            !err.contains(SECRET),
            "session arg leaked into audit output (extra={extra:?}): {err}"
        );
    }
}

/// The default-path half of the credential-safety guarantee: without
/// `--audit-args`, a tool-call argument value must never reach stderr, only
/// its digest. `sessions-canary`'s `read` tool ignores its arguments
/// entirely and declares no capabilities, so nothing else in this call
/// (no capability resource key, no session-open args) could legitimately
/// carry the marker either — isolating this to the tool-argument path alone.
#[test]
fn tool_arguments_are_digested_by_default() {
    let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sessions-canary.wasm");
    const MARKER: &str = "zzmarkerzz";
    let out = act_bin()
        .args([
            "call",
            fixture.to_str().expect("fixture path is utf-8"),
            "read",
            "--args",
            &format!(r#"{{"name":"{MARKER}"}}"#),
        ])
        .output()
        .expect("ran act");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains(MARKER), "argument value leaked: {err}");
    assert!(err.contains("args:"), "expected an args digest: {err}");
}

/// The other half: `--audit-args` must actually widen the envelope. Without
/// this test, `tool_arguments_are_digested_by_default` above would keep
/// passing even if `--audit-args` were silently a no-op — it only proves the
/// default is safe, not that the flag does anything.
#[test]
fn audit_args_records_the_full_tool_argument_value() {
    let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sessions-canary.wasm");
    const MARKER: &str = "zzmarkerzz";
    let out = act_bin()
        .args([
            "call",
            fixture.to_str().expect("fixture path is utf-8"),
            "read",
            "--args",
            &format!(r#"{{"name":"{MARKER}"}}"#),
            "--audit-args",
        ])
        .output()
        .expect("ran act");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(MARKER),
        "expected the full argument value with --audit-args set: {err}"
    );
}

/// Mirrors `http_decisions_reach_the_audit_trail`, but for the sockets
/// classify site in `runtime/mod.rs`'s `socket_addr_check` hook. Runs the
/// `sockets-canary` fixture (declares `wasi:sockets` with an unbounded
/// `host = "*"` ceiling) against the same dead loopback port trick: an
/// allowed-but-unreachable connect surfaces `ConnectionRefused` (io error,
/// reached the transport), a policy-denied one surfaces `PermissionDenied`
/// (blocked by `socket_addr_check` before the connect syscall).
#[test]
fn sockets_decisions_reach_the_audit_trail() {
    let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sockets-canary.wasm");

    // In-ceiling allow: the rollup line must carry the `sockets:` clause,
    // proving the `Decision::Allow` arm of the sockets classify ran.
    let out = act_bin()
        .args([
            "call",
            fixture.to_str().expect("fixture path is utf-8"),
            "connect",
            "--args",
            r#"{"host":"127.0.0.1","port":1}"#,
            "--grant",
            r#"{"wasi:sockets":{"mode":"allowlist","allow":[{"host":"127.0.0.1"}]}}"#,
        ])
        .output()
        .expect("ran act");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ConnectionRefused"),
        "an allowed connect must reach the transport, got: {stderr}"
    );
    let rollup = stderr
        .lines()
        .find(|l| l.starts_with("audit: \u{25cf}"))
        .unwrap_or_else(|| panic!("no rollup line in stderr: {stderr}"));
    assert!(
        rollup.contains("sockets:"),
        "rollup must carry a sockets: clause, got: {rollup}"
    );

    // Out-of-ceiling deny: an immediate `✗ deny` line must appear, proving
    // the `Decision::Deny` arm ran — same grant shape, a host it doesn't
    // cover. `socket_addr_check` blocks the connect before it reaches the
    // OS, so the guest sees `PermissionDenied` rather than a transport error.
    let out = act_bin()
        .args([
            "call",
            fixture.to_str().expect("fixture path is utf-8"),
            "connect",
            "--args",
            r#"{"host":"127.0.0.1","port":1}"#,
            "--grant",
            r#"{"wasi:sockets":{"mode":"allowlist","allow":[{"host":"10.0.0.1"}]}}"#,
        ])
        .output()
        .expect("ran act");
    assert!(
        !out.status.success(),
        "out-of-ceiling connect must be denied: {out:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("PermissionDenied"),
        "a denied connect must be blocked before the transport, got: {stderr}"
    );
    let deny_line = stderr
        .lines()
        .find(|l| l.starts_with("audit: \u{2717} deny"))
        .unwrap_or_else(|| panic!("no immediate deny line in stderr: {stderr}"));
    assert!(
        deny_line.contains("wasi:sockets"),
        "deny line must name the capability, got: {deny_line}"
    );
    assert!(
        deny_line.contains("outside ceiling"),
        "deny line must carry the reason, got: {deny_line}"
    );
}

/// The `Decision::Ask` arm of the sockets classify in `runtime/mod.rs` is the
/// decision point `sockets_decisions_reach_the_audit_trail` above cannot
/// reach: that test only runs under `allowlist`, and `Decision::Ask` is
/// returned only in `ask` mode. Confirmed by disabling that arm's
/// `emit_cap_decision` call and re-running: the other test still passes.
///
/// Runs `sockets-canary` under an `ask`-mode grant with stdin closed, which
/// degrades to deny via `DenyPrompter` — the ask path still runs to produce
/// that verdict.
#[test]
fn sockets_ask_resolution_reaches_the_audit_trail() {
    let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sockets-canary.wasm");

    let out = act_bin()
        .args([
            "call",
            fixture.to_str().expect("fixture path is utf-8"),
            "connect",
            "--args",
            r#"{"host":"127.0.0.1","port":1}"#,
            "--grant",
            r#"{"wasi:sockets":"ask"}"#,
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("ran act");
    assert!(
        !out.status.success(),
        "headless ask with no prompt channel must degrade to deny: {out:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let ask_line = stderr
        .lines()
        .find(|l| l.starts_with("audit: ? ask-deny"))
        .unwrap_or_else(|| panic!("no immediate ask-deny line in stderr: {stderr}"));
    assert!(
        ask_line.contains("wasi:sockets"),
        "ask-deny line must name the capability, got: {ask_line}"
    );
    assert!(
        ask_line.contains("denied by user"),
        "ask-deny line must carry the reason, got: {ask_line}"
    );
}
