//! `act pull` / `act store list` / `act store gc` against a temp store,
//! fully offline (local file source).

mod common;

use common::act;
use predicates::prelude::*;

#[test]
fn pull_local_then_list_then_gc() {
    let dir = tempfile::TempDir::new().unwrap();
    let store_dir = dir.path().join("store");
    let comp = dir.path().join("demo.wasm");
    std::fs::write(&comp, b"\0asm\x01\0\0\0demo").unwrap();

    let run = |args: &[&str]| {
        let mut cmd = act();
        cmd.args(args).env("ACT_STORE_DIR", &store_dir);
        cmd
    };

    // pull (install local snapshot)
    run(&["pull", comp.to_str().unwrap()]).assert().success();

    // list shows the component
    run(&["store", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("demo.wasm"));

    // gc removes nothing (the component is referenced)
    run(&["store", "gc"])
        .assert()
        .success()
        .stdout(predicate::str::contains("removed 0"));
}
