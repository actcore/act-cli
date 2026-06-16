//! Integration coverage for `act inspect component-manifest`.
use std::path::PathBuf;
use std::process::Command;

fn act_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_act"))
}

fn time_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/time.wasm")
}

#[test]
fn inspect_help_lists_component_manifest() {
    let out = act_bin()
        .args(["inspect", "--help"])
        .output()
        .expect("ran act");
    assert!(out.status.success(), "act inspect --help failed");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("component-manifest"),
        "missing component-manifest in help: {text}"
    );
}

#[test]
fn inspect_component_manifest_emits_raw_json() {
    let out = act_bin()
        .args(["inspect", "component-manifest", "--format", "json"])
        .arg(time_fixture())
        .output()
        .expect("ran act");
    assert!(
        out.status.success(),
        "command failed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout is valid JSON");
    // Raw manifest exposes the `std` block verbatim.
    assert!(v.get("std").is_some(), "manifest missing std block");
    assert!(
        v["std"]["name"].as_str().is_some_and(|s| !s.is_empty()),
        "manifest missing std.name"
    );
}
