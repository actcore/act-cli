//! Integration coverage for the `ask` policy mode at the CLI surface.
//!
//! The decision-point logic (matcher defer → consent cache/prompter → allow /
//! deny / remember / degrade) is covered by in-crate unit tests (`consent`,
//! `fs_matcher`, `config`), which can reach internal types this binary crate
//! does not export. These subprocess tests assert the user-facing contract:
//! `ask` is a recognised policy mode, and an unknown mode names it.

mod common;

use common::act;
use predicates::prelude::*;

#[test]
fn unknown_policy_mode_error_lists_ask() {
    // A bogus mode in --grant must fail and surface the valid modes,
    // including `ask`.
    act()
        .args([
            "call",
            "nonexistent.wasm",
            "noop",
            "--grant",
            r#"{"wasi:filesystem":"bogus"}"#,
            "--args",
            "{}",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ask"));
}

#[test]
fn ask_mode_is_accepted_by_grant_parser() {
    // `ask` is a valid mode: parsing/resolution succeeds, so the command only
    // fails later (component not found), NOT with an unknown-mode error.
    act()
        .args([
            "call",
            "nonexistent.wasm",
            "noop",
            "--grant",
            r#"{"wasi:filesystem":"ask"}"#,
            "--args",
            "{}",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown policy mode").not());
}
