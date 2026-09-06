//! Shared scaffolding for the `act` integration tests.
//!
//! Every file here drives the real binary as a subprocess, and before this
//! module each of them carried its own copy of "where is the binary", "where
//! are the fixtures", and the `format!` that builds a filesystem grant. Eleven
//! copies of the first, four of the second — and when the grant JSON's shape
//! changed, the copies had to be found by grep.
//!
//! Kept deliberately thin: helpers for the things every file needs, not a
//! framework. A test's own setup belongs in that test's file, where the reason
//! for it is visible.

#![allow(dead_code)] // each test binary uses a different subset of this

use std::path::PathBuf;

/// The `act` binary this test run built, as an [`assert_cmd::Command`].
///
/// `assert_cmd` rather than `std::process::Command`: `.assert().success()`
/// prints the exit status *and* both streams when it fails, where the
/// hand-written `assert!(out.status.success(), "{}", stderr)` this replaced
/// showed only whichever stream its author happened to pick.
pub fn act() -> assert_cmd::Command {
    assert_cmd::Command::cargo_bin("act").expect("the `act` binary is built for this test run")
}

/// The same binary as a plain [`std::process::Command`].
///
/// For the tests whose assertions are bespoke enough that `assert_cmd`'s
/// fluent form would obscure rather than shorten them — the audit-trail tests
/// pick one line out of stderr and reason about its contents — and for the
/// ones that depend on inheriting stdin rather than having it closed.
pub fn act_cmd() -> std::process::Command {
    std::process::Command::new(act_binary_path())
}

/// The same binary as a path, for the tests that need to spawn it themselves
/// — an MCP server driven over stdio, or a prompt fed on a piped stdin, which
/// `assert_cmd`'s run-to-completion model does not cover.
pub fn act_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_act"))
}

/// A committed `.wasm` fixture under `tests/fixtures/`.
pub fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// A `--grant` value opening `dir` and everything under it for read+write.
///
/// One builder rather than a `format!` per test: the grant JSON's shape is
/// part of the CLI's contract, and a change to it should break in one place
/// rather than in however many string literals happen to spell it out.
pub fn fs_grant_rw(dir: &std::path::Path) -> String {
    fs_grant(&format!("{}/**", dir.display()), "rw")
}

/// A `--grant` value for one filesystem rule. `mode` is `ro` or `rw`.
pub fn fs_grant(rule: &str, mode: &str) -> String {
    format!(
        r#"{{"wasi:filesystem":{{"mode":"allowlist","allow":[{{"path":"{rule}","mode":"{mode}"}}]}}}}"#
    )
}

/// The first audit line in `stderr` starting with `prefix`, or a panic naming
/// what was searched and showing the whole stream.
///
/// The audit trail goes to stderr interleaved with everything else, so every
/// test that asserts on it has to find its line first. Failing here with the
/// full stream is the difference between "the deny line is missing" and a
/// bare `None` unwrap.
pub fn audit_line<'a>(stderr: &'a str, prefix: &str) -> &'a str {
    stderr
        .lines()
        .find(|l| l.starts_with(prefix))
        .unwrap_or_else(|| panic!("no line starting with {prefix:?} in stderr:\n{stderr}"))
}

/// The per-call rollup line: `audit: ● …`.
pub fn rollup_line(stderr: &str) -> &str {
    audit_line(stderr, "audit: \u{25cf}")
}

/// An immediate deny line: `audit: ✗ deny …`.
pub fn deny_line(stderr: &str) -> &str {
    audit_line(stderr, "audit: \u{2717} deny")
}
