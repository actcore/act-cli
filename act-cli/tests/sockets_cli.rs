//! Integration coverage for sockets policy flag parsing.
//! Lives in tests/ so it picks up clap's derive surface as users see it.

use std::process::Command;

fn act_bin() -> Command {
    let bin = env!("CARGO_BIN_EXE_act");
    Command::new(bin)
}

#[test]
fn sockets_help_lists_flags() {
    let out = act_bin()
        .args(["call", "--help"])
        .output()
        .expect("ran act");
    assert!(out.status.success(), "act call --help failed");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("--sockets-allow"),
        "missing --sockets-allow in help"
    );
    assert!(
        text.contains("--sockets-deny"),
        "missing --sockets-deny in help"
    );
    assert!(
        text.contains("--sockets-policy"),
        "missing --sockets-policy in help"
    );
}

#[test]
fn bad_socket_spec_is_rejected_clearly() {
    let out = act_bin()
        .args([
            "call",
            "nonexistent.wasm",
            "noop",
            "--sockets-allow",
            "missing-port",
            "--args",
            "{}",
        ])
        .output()
        .expect("ran act");
    assert!(!out.status.success(), "expected non-zero exit");
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains("missing ':<port>'"),
        "expected port-missing message in stderr, got: {text}"
    );
}
