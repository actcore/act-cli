//! Integration coverage for `act inspect component-manifest` and
//! `act inspect tools`.

mod common;

use common::{act, fixture};
use predicates::prelude::*;

#[test]
fn inspect_help_lists_component_manifest() {
    act()
        .args(["inspect", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("component-manifest"));
}

#[test]
fn inspect_help_lists_tools() {
    act()
        .args(["inspect", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("tools"));
}

#[test]
fn inspect_component_manifest_emits_raw_json() {
    let out = act()
        .args(["inspect", "component-manifest", "--format", "json"])
        .arg(fixture("time.wasm"))
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_slice(&out.get_output().stdout).expect("stdout is valid JSON");
    // Raw manifest exposes the `std` block verbatim.
    assert!(v.get("std").is_some(), "manifest missing std block");
    assert!(
        v["std"]["name"].as_str().is_some_and(|s| !s.is_empty()),
        "manifest missing std.name"
    );
}

#[test]
fn inspect_tools_emits_raw_list_tools_response() {
    let out = act()
        .args(["inspect", "tools", "--format", "json"])
        .arg(fixture("time.wasm"))
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_slice(&out.get_output().stdout).expect("stdout is valid JSON");
    // Raw response shape: top-level `metadata` object + `tools` array.
    assert!(
        v.get("metadata").map(|m| m.is_object()).unwrap_or(false),
        "raw response missing top-level metadata object: {v}"
    );
    let tools = v["tools"].as_array().expect("tools is an array");
    assert!(
        !tools.is_empty(),
        "time component should expose at least one tool"
    );
    let first = &tools[0];
    assert!(
        first["name"].as_str().is_some_and(|s| !s.is_empty()),
        "tool[0] missing name"
    );
    // Raw view preserves the per-tool metadata map (curated `info --tools`
    // would have flattened it into named bool fields instead).
    assert!(
        first
            .get("metadata")
            .map(|m| m.is_object())
            .unwrap_or(false),
        "tool[0] missing raw metadata object: {first}"
    );
}
