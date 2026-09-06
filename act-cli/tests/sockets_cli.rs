//! Integration coverage for uniform capability grant flag parsing.
//! Lives in tests/ so it picks up clap's derive surface as users see it.

mod common;

use common::act;
use predicates::prelude::*;

#[test]
fn grant_allow_deny_flags_listed_in_call_help() {
    act()
        .args(["call", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--grant"))
        .stdout(predicate::str::contains("--allow"))
        .stdout(predicate::str::contains("--deny"));
}

#[test]
fn malformed_grant_json_is_rejected_clearly() {
    act()
        .args([
            "call",
            "nonexistent.wasm",
            "noop",
            "--grant",
            "not json",
            "--args",
            "{}",
        ])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("grant")
                .or(predicate::str::contains("JSON"))
                .or(predicate::str::contains("json")),
        );
}
