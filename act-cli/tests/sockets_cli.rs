//! Integration coverage for --allow-socket / --deny-socket flag parsing.
//! Lives in tests/ so it picks up clap's derive surface as users see it.

use std::process::Command;

fn act_bin() -> Command {
    let bin = env!("CARGO_BIN_EXE_act");
    Command::new(bin)
}

#[test]
fn allow_socket_help_lists_flags() {
    let out = act_bin()
        .args(["call", "--help"])
        .output()
        .expect("ran act");
    assert!(out.status.success(), "act call --help failed");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("--allow-socket"),
        "missing --allow-socket in help"
    );
    assert!(
        text.contains("--deny-socket"),
        "missing --deny-socket in help"
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
            "--allow-socket",
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
