//! `act pull`/`list`/`gc` against a temp store, fully offline (local file source).

use std::process::Command;

fn act_bin() -> Command {
    let bin = env!("CARGO_BIN_EXE_act");
    Command::new(bin)
}

#[test]
fn pull_local_then_list_then_gc() {
    let dir = tempfile::TempDir::new().unwrap();
    let store_dir = dir.path().join("store");
    let comp = dir.path().join("demo.wasm");
    std::fs::write(&comp, b"\0asm\x01\0\0\0demo").unwrap();

    let run = |args: &[&str]| {
        act_bin()
            .args(args)
            .env("ACT_STORE_DIR", &store_dir)
            .output()
            .expect("spawn act")
    };

    // pull (install local snapshot)
    let out = run(&["pull", comp.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "pull failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // list shows the component
    let out = run(&["list"]);
    assert!(
        out.status.success(),
        "list failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let listing = String::from_utf8_lossy(&out.stdout);
    assert!(
        listing.contains("demo.wasm"),
        "list missing component: stdout={listing}"
    );

    // gc removes nothing (the component is referenced)
    let out = run(&["gc"]);
    assert!(
        out.status.success(),
        "gc failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("removed 0"),
        "expected 'removed 0', got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}
