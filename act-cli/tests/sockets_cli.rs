//! Integration coverage for uniform capability grant flag parsing.
//! Lives in tests/ so it picks up clap's derive surface as users see it.

use std::process::Command;

fn act_bin() -> Command {
    let bin = env!("CARGO_BIN_EXE_act");
    Command::new(bin)
}

#[test]
fn grant_allow_deny_flags_listed_in_call_help() {
    let out = act_bin()
        .args(["call", "--help"])
        .output()
        .expect("ran act");
    assert!(out.status.success(), "act call --help failed");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("--grant"), "missing --grant in help");
    assert!(text.contains("--allow"), "missing --allow in help");
    assert!(text.contains("--deny"), "missing --deny in help");
}

#[test]
fn malformed_grant_json_is_rejected_clearly() {
    let out = act_bin()
        .args([
            "call",
            "nonexistent.wasm",
            "noop",
            "--grant",
            "not json",
            "--args",
            "{}",
        ])
        .output()
        .expect("ran act");
    assert!(
        !out.status.success(),
        "expected non-zero exit for bad --grant JSON"
    );
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains("grant") || text.contains("JSON") || text.contains("json"),
        "expected error mentioning grant or JSON in stderr, got: {text}"
    );
}
