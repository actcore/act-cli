//! `act secret set/list/rm` against a temp file-backed store.

use std::process::Command;

fn act() -> Command {
    Command::new(env!("CARGO_BIN_EXE_act"))
}

#[test]
fn set_then_list_shows_metadata_and_never_a_value() {
    let dir = tempfile::tempdir().unwrap();
    let backend = format!("file:{}", dir.path().display());

    let set = act()
        .args([
            "secret",
            "set",
            "ghcr.io/actpkg/notion",
            "--key",
            "default",
            "--kind",
            "std:opaque",
            "--description",
            "Notion workspace",
            "--credentials-backend",
            &backend,
            "--fields-stdin",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write;
            c.stdin
                .as_mut()
                .unwrap()
                .write_all(br#"{"std:value":"sekrit"}"#)?;
            c.wait_with_output()
        })
        .unwrap();
    assert!(
        set.status.success(),
        "{}",
        String::from_utf8_lossy(&set.stderr)
    );

    let list = act()
        .args([
            "secret",
            "list",
            "ghcr.io/actpkg/notion",
            "--credentials-backend",
            &backend,
        ])
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&list.stdout);
    assert!(out.contains("default"), "lists the key: {out}");
    assert!(
        out.contains("ghcr.io/actpkg/notion"),
        "says which profile the key belongs to: {out}"
    );
    assert!(
        out.contains("Notion workspace"),
        "lists the description: {out}"
    );
    assert!(!out.contains("sekrit"), "never prints a value: {out}");
}

#[test]
fn rm_removes_the_entry() {
    let dir = tempfile::tempdir().unwrap();
    let backend = format!("file:{}", dir.path().display());
    let mut c = act()
        .args([
            "secret",
            "set",
            "comp",
            "--key",
            "k",
            "--kind",
            "std:opaque",
            "--credentials-backend",
            &backend,
            "--fields-stdin",
        ])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        c.stdin
            .as_mut()
            .unwrap()
            .write_all(br#"{"std:value":"v"}"#)
            .unwrap();
    }
    assert!(c.wait().unwrap().success());

    assert!(
        act()
            .args([
                "secret",
                "rm",
                "comp",
                "--key",
                "k",
                "--credentials-backend",
                &backend
            ])
            .status()
            .unwrap()
            .success()
    );

    let list = act()
        .args(["secret", "list", "comp", "--credentials-backend", &backend])
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&list.stdout).contains("\"k\""));
}

#[test]
fn an_unknown_kind_is_rejected_with_the_known_ones_listed() {
    let dir = tempfile::tempdir().unwrap();
    let backend = format!("file:{}", dir.path().display());
    let out = act()
        .args([
            "secret",
            "set",
            "comp",
            "--key",
            "k",
            "--kind",
            "std:nonesuch",
            "--credentials-backend",
            &backend,
            "--fields-stdin",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("std:opaque"),
        "names the kinds that do exist: {err}"
    );
}

/// `ComponentRef::Local(p).to_string()` is `p.display()` verbatim, so
/// `./x.wasm`, `x.wasm` and its absolute form are three different strings
/// for the same file. `act secret set` and `act secret list` must agree
/// regardless of which spelling was used — that's `resolve::profile_key`
/// (act-cli/act-cli/src/resolve.rs), exercised end-to-end here through the
/// real binary and a real (relative) current directory, which a unit test
/// on `profile_key` alone can't cover safely (mutating the test process's
/// cwd is a shared, parallel-unsafe global).
///
/// The referenced `x.wasm` need not exist: `act secret set` never opens it,
/// only `act run` does.
#[test]
fn local_refs_agree_on_one_profile_regardless_of_spelling() {
    let store_dir = tempfile::tempdir().unwrap();
    let backend = format!("file:{}", store_dir.path().display());
    let cwd_dir = tempfile::tempdir().unwrap();
    let abs = cwd_dir.path().join("x.wasm");
    let abs_str = abs
        .to_str()
        .expect("tempdir path is valid UTF-8")
        .to_string();

    for (i, spelling) in ["./x.wasm", "x.wasm", abs_str.as_str()]
        .into_iter()
        .enumerate()
    {
        let key = format!("k{i}");
        let set = act()
            .current_dir(cwd_dir.path())
            .args([
                "secret",
                "set",
                spelling,
                "--key",
                &key,
                "--kind",
                "std:opaque",
                "--credentials-backend",
                &backend,
                "--fields-stdin",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut c| {
                use std::io::Write;
                c.stdin
                    .as_mut()
                    .unwrap()
                    .write_all(br#"{"std:value":"v"}"#)?;
                c.wait_with_output()
            })
            .unwrap();
        assert!(
            set.status.success(),
            "set for {spelling}: {}",
            String::from_utf8_lossy(&set.stderr)
        );
    }

    // All three writes must have landed under one profile: listing by the
    // absolute spelling sees all three keys.
    let list = act()
        .args([
            "secret",
            "list",
            &abs_str,
            "--credentials-backend",
            &backend,
        ])
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&list.stdout);
    for i in 0..3 {
        assert!(
            out.contains(&format!("k{i}")),
            "expected k{i} in one shared profile: {out}"
        );
    }
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("list prints JSON");
    let profiles = parsed.as_object().expect("list is keyed by profile");
    assert_eq!(
        profiles.len(),
        1,
        "three spellings must produce one profile, not three: {out}"
    );
    let (profile, infos) = profiles.iter().next().unwrap();
    assert_eq!(
        profile, &abs_str,
        "the profile is the cleaned absolute path: {out}"
    );
    assert_eq!(
        infos.as_array().map(Vec::len),
        Some(3),
        "three spellings, one profile, three keys: {out}"
    );

    // Listing every component agrees with listing that one: the same single
    // profile, so the unfiltered view cannot suggest three components exist.
    let all = act()
        .args(["secret", "list", "--credentials-backend", &backend])
        .output()
        .unwrap();
    let all: serde_json::Value = serde_json::from_slice(&all.stdout).expect("list prints JSON");
    assert_eq!(
        all.as_object()
            .map(|o| o.keys().cloned().collect::<Vec<_>>()),
        Some(vec![abs_str.clone()])
    );
}

/// `--credentials-backend` is not decorative on the subcommands that run a
/// component: the store the writer wrote to is the store the runtime reads.
///
/// Probed through the failure, because the success path needs a component
/// that declares `act:credentials` and no such fixture exists yet (Task 11
/// builds it). The error text can only come from the runtime's own call to
/// `runtime::credentials::resolve_backend` — `act call` reaches it after
/// reading the component file and before instantiating it — so it fails if
/// the flag is ever demoted back to something only `act secret` reads.
#[test]
fn a_run_side_subcommand_resolves_the_named_backend() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/sessions-canary.wasm"
    );
    let out = act()
        .args([
            "call",
            fixture,
            "echo",
            "--args",
            "{}",
            "--credentials-backend",
            "keyring",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "a bogus backend must not be ignored");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("unknown --credentials-backend"),
        "the run side parses the flag itself: {err}"
    );
}

/// "removed" has to mean removed. `erase` is idempotent, so a mistyped
/// `--key` would otherwise report success and leave the credential in place —
/// an operator who thinks they revoked something is worse off than one who
/// gets an error.
#[test]
fn rm_of_an_absent_key_says_so_instead_of_reporting_success() {
    let dir = tempfile::tempdir().unwrap();
    let backend = format!("file:{}", dir.path().display());

    let out = act()
        .args([
            "secret",
            "rm",
            "comp",
            "--key",
            "never-stored",
            "--credentials-backend",
            &backend,
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("no credential 'never-stored'"),
        "names the key it could not find: {err}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("removed"),
        "must not claim a removal it did not make"
    );
}
