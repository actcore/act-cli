//! The flags the config/policy work put on the CLI surface, as clap presents
//! them to a user reading `--help`.

mod common;

use common::act;
use predicates::prelude::*;

#[test]
fn cli_run_help_shows_policy_flags() {
    act()
        .args(["run", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--grant"))
        .stdout(predicate::str::contains("--allow"))
        .stdout(predicate::str::contains("--deny"))
        .stdout(predicate::str::contains("profile"))
        .stdout(predicate::str::contains("config"));
}

#[test]
fn cli_call_help_shows_policy_flags() {
    act()
        .args(["call", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--grant"))
        .stdout(predicate::str::contains("--allow"))
        .stdout(predicate::str::contains("--deny"));
}

#[test]
fn cli_legacy_allow_dir_rejected() {
    act()
        .args(["run", "--allow-dir", "a:b", "foo"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("unexpected argument")
                .or(predicate::str::contains("--allow-dir")),
        );
}

#[test]
fn cli_run_mcp_flag_appears_in_run_help() {
    act()
        .args(["run", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("mcp"));
}

#[test]
fn cli_info_help_shows_tools_and_format_flags() {
    act()
        .args(["info", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("tools"))
        .stdout(predicate::str::contains("format"));
}
