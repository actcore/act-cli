//! Integration coverage for the `ask` policy mode at the CLI surface.
//!
//! The decision-point logic (matcher defer → consent cache/prompter → allow /
//! deny / remember / degrade) is covered by in-crate unit tests (`consent`,
//! `fs_matcher`, `config`), which can reach internal types this binary crate
//! does not export. These subprocess tests assert the user-facing contract:
//! `ask` is a recognised policy mode, and an unknown mode names it.

use std::process::Command;

fn act_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_act"))
}

#[test]
fn unknown_policy_mode_error_lists_ask() {
    // A bogus mode in --grant must fail and surface the valid modes,
    // including `ask`.
    let out = act_bin()
        .args([
            "call",
            "nonexistent.wasm",
            "noop",
            "--grant",
            r#"{"wasi:filesystem":"bogus"}"#,
            "--args",
            "{}",
        ])
        .output()
        .expect("ran act");
    assert!(
        !out.status.success(),
        "expected non-zero exit for unknown policy mode"
    );
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains("ask"),
        "expected unknown-mode error to list 'ask', got: {text}"
    );
}

#[test]
fn ask_mode_is_accepted_by_grant_parser() {
    // `ask` is a valid mode: parsing/resolution succeeds, so the command only
    // fails later (component not found), NOT with an unknown-mode error.
    let out = act_bin()
        .args([
            "call",
            "nonexistent.wasm",
            "noop",
            "--grant",
            r#"{"wasi:filesystem":"ask"}"#,
            "--args",
            "{}",
        ])
        .output()
        .expect("ran act");
    assert!(
        !out.status.success(),
        "expected non-zero exit (component does not exist)"
    );
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        !text.contains("unknown policy mode"),
        "`ask` should parse as a valid mode, got: {text}"
    );
}
