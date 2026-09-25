//! `--allow` / `--deny` shorthand, class aliases, the `--help` class listing
//! and the audit grant hint, end to end through the `act` binary.

mod common;
use common::act_cmd as act;
use common::{deny_line, fixture, rollup_line};

#[test]
fn run_help_lists_every_builtin_class() {
    let out = act().args(["run", "--help"]).output().expect("ran act");
    let help = String::from_utf8_lossy(&out.stdout);
    for (alias, id) in [
        ("fs", "wasi:filesystem"),
        ("http", "wasi:http"),
        ("sockets", "wasi:sockets"),
        ("creds", "act:credentials"),
    ] {
        let line = help
            .lines()
            .find(|l| l.split_whitespace().nth(1) == Some(id))
            .unwrap_or_else(|| panic!("{id} missing from run --help:\n{help}"));
        assert!(
            line.trim_start().starts_with(alias),
            "{id} line lacks alias {alias}: {line}"
        );
    }
    assert!(
        help.contains("act info <ref>"),
        "semantic-class note missing"
    );
}

#[test]
fn every_registered_builtin_has_help() {
    for (id, h) in act_policy::provider::ProviderRegistry::with_builtins().builtins() {
        assert!(
            h.is_some(),
            "built-in class {id} has no ShorthandHelp — it would ship undocumented"
        );
    }
}

fn call(tool: &str, args: &str, extra: &[&str]) -> std::process::Output {
    let f = fixture("fs-canary.wasm");
    let mut c = act();
    c.args([
        "call",
        f.to_str().expect("utf-8 path"),
        tool,
        "--args",
        args,
    ]);
    c.args(extra);
    c.stdin(std::process::Stdio::null())
        .output()
        .expect("ran act")
}

#[test]
fn allow_fs_shorthand_ro_reads_but_does_not_write() {
    let d = tempfile::TempDir::new().unwrap();
    std::fs::write(d.path().join("a.txt"), "hi").unwrap();
    let rule = format!("fs={}/**:ro", d.path().display());
    let out = call(
        "read",
        &format!(r#"{{"path":"{}/a.txt"}}"#, d.path().display()),
        &["--allow", &rule],
    );
    assert!(out.status.success(), "{out:?}");
    let target = d.path().join("w.txt");
    let out = call(
        "p3-write",
        &format!(r#"{{"path":"{}","content":"x"}}"#, target.display()),
        &["--allow", &rule],
    );
    assert!(!out.status.success(), "ro must refuse the write: {out:?}");
    assert!(!target.exists());
}

#[test]
fn allow_fs_shorthand_defaults_to_rw() {
    let d = tempfile::TempDir::new().unwrap();
    let target = d.path().join("w.txt");
    let rule = format!("fs={}/**", d.path().display());
    let out = call(
        "p3-write",
        &format!(r#"{{"path":"{}","content":"x"}}"#, target.display()),
        &["--allow", &rule],
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "x");
}

#[test]
fn deny_shorthand_carves_out_a_subtree() {
    let d = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(d.path().join("secret")).unwrap();
    std::fs::write(d.path().join("secret/k"), "k").unwrap();
    std::fs::write(d.path().join("open.txt"), "o").unwrap();
    let allow = format!("fs={}/**", d.path().display());
    let deny = format!("fs={}/secret/**", d.path().display());
    let flags = ["--allow", allow.as_str(), "--deny", deny.as_str()];
    let out = call(
        "read",
        &format!(r#"{{"path":"{}/secret/k"}}"#, d.path().display()),
        &flags,
    );
    assert!(!out.status.success(), "{out:?}");
    assert!(deny_line(&String::from_utf8_lossy(&out.stderr)).contains("wasi:filesystem"));
    // …and everything outside the carved-out subtree is still granted.
    let out = call(
        "read",
        &format!(r#"{{"path":"{}/open.txt"}}"#, d.path().display()),
        &flags,
    );
    assert!(out.status.success(), "{out:?}");
}

/// An alias never reaches the audit trail.
#[test]
fn alias_is_printed_as_full_id() {
    let d = tempfile::TempDir::new().unwrap();
    std::fs::write(d.path().join("a.txt"), "hi").unwrap();
    let out = call(
        "read",
        &format!(r#"{{"path":"{}/a.txt"}}"#, d.path().display()),
        &["--allow", &format!("fs={}/**", d.path().display())],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let header = stderr.lines().next().unwrap_or_default();
    assert!(header.contains("wasi:filesystem=allowlist"), "{header}");
    assert!(
        !stderr.contains(" fs="),
        "alias leaked into audit: {stderr}"
    );
    assert!(rollup_line(&stderr).contains("under"), "{stderr}");
}

#[test]
fn bare_and_constrained_together_fail_before_running() {
    let out = call(
        "read",
        r#"{"path":"/tmp/x"}"#,
        &["--allow", "fs", "--allow", "fs=/tmp/**"],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("both given"));
}

#[test]
fn ungranted_warning_carries_the_hint() {
    let out = call("read", r#"{"path":"/tmp/x"}"#, &["--deny", "fs"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let i = stderr
        .lines()
        .position(|l| l.contains("declared but not granted"))
        .unwrap_or_else(|| panic!("no warning in: {stderr}"));
    let next = stderr.lines().nth(i + 1).unwrap_or_default();
    assert!(next.contains("hint: grant it with --allow fs"), "{stderr}");
}
