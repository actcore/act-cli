//! `--allow` / `--deny` shorthand, class aliases, the `--help` class listing
//! and the audit grant hint, end to end through the `act` binary.

mod common;
use common::act_cmd as act;

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
