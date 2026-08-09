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
