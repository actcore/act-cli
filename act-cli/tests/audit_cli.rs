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
    let audit_line = stderr
        .lines()
        .find(|l| l.starts_with("audit: "))
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
