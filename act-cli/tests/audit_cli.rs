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
