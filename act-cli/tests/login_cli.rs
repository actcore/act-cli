//! `act login` — the interactive counterpart to `act secret set`, driven
//! against the real binary and real fixtures (see `tests/fixtures-src/README.md`
//! for how `oauth-declaring-canary.wasm` and `creds-declaring-canary.wasm` are
//! built: the same `credentials-canary` bytes, packed against a second
//! `act.toml`).
//!
//! Every case here is a refusal, on purpose: the three properties that matter
//! most for a command that writes secrets are the ones that stop it from
//! writing at all — an undeclared component is told so before anything else
//! runs, a field type this release cannot acquire is named rather than
//! prompted for, and an existing credential is never overwritten silently.
//! The success path (prompting, hidden input, the actual write) is covered by
//! `secret_cmd`'s unit tests and `login_cmd`'s own — piping a real hidden
//! prompt through a subprocess's stdin buys little a unit test on
//! `field_set`/`select_credential` doesn't already cover, and it risks a
//! flaky or hanging test if the guard under test regresses (see the last
//! test below, which relies on exactly that risk to prove the type check
//! bites).

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn act_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_act"))
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Runs `act login <fixture> <extra_args...>` with stdin closed, as a
/// headless run would see it. Every case in this file is expected to refuse
/// before it would ever read from stdin; closing it rather than piping
/// nothing means a regression that starts prompting anyway fails fast
/// (immediate EOF) instead of hanging the test suite.
///
/// Always against a throwaway store. Without `--credentials-backend` these
/// resolve the platform default — the developer's real credential store — and
/// the guards under test are the only thing keeping the suite out of it. The
/// first moment a guard regresses, the tests would write there and their own
/// results would start depending on machine state. That is not hypothetical:
/// it happened during this plan's Task 5, and left a fixture's credential in a
/// real store.
fn run_login(extra_args: &[&str], fixture_name: &str) -> Output {
    let store = tempfile::tempdir().expect("temp store");
    let backend = format!("file:{}", store.path().display());
    Command::new(act_binary_path())
        .arg("login")
        .arg(fixture(fixture_name))
        .args(["--credentials-backend", &backend])
        .args(extra_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run act login")
}

/// As [`run_login`], but against a specific `--credentials-backend`.
fn run_login_with_store(extra_args: &[&str], fixture_name: &str, backend: &str) -> Output {
    Command::new(act_binary_path())
        .arg("login")
        .arg(fixture(fixture_name))
        .args(extra_args)
        .args(["--credentials-backend", backend])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run act login")
}

/// A file-backed store, pre-seeded with a credential for
/// `creds-declaring-canary.wasm` under `key`, written by a real
/// `act secret set` rather than a direct `CredentialStore::put`.
///
/// The profile a credential lands under is derived by `resolve::profile_key`
/// — the same function `act login`'s overwrite check uses — so seeding
/// through the real write path is what makes this test mean anything: a
/// test that wrote the store directly could pass even if the two commands
/// disagreed about which profile the fixture owns.
fn seeded_store(key: &str) -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let backend = format!("file:{}", dir.path().display());

    let mut child = Command::new(act_binary_path())
        .arg("secret")
        .arg("set")
        .arg(fixture("creds-declaring-canary.wasm"))
        .args(["--key", key, "--kind", "std:string"])
        .args(["--credentials-backend", &backend])
        .arg("--fields-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn act secret set");
    {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .expect("stdin was piped")
            .write_all(br#"{"std:value":"pre-existing-value"}"#)
            .expect("write field map");
    }
    let out = child.wait_with_output().expect("act secret set");
    assert!(
        out.status.success(),
        "seeding the store failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    (backend, dir)
}

/// EOF at a prompt must abort, not store an empty credential.
///
/// Found while reading Task 5's deliberate-break report: with the type guard
/// removed, `act login` on an unpromptable field did not hang on closed stdin —
/// it read EOF as `""`, stored that, and exited 0. The guard hid a second bug
/// underneath it, and this one applies to ordinary string fields too: a piped
/// invocation, or Ctrl-D at the prompt, silently provisioned nothing while
/// reporting success. Storing an empty value is worse than failing, because the
/// operator believes the credential exists.
#[test]
fn eof_at_a_prompt_aborts_instead_of_storing_an_empty_value() {
    let dir = tempfile::tempdir().unwrap();
    let backend = format!("file:{}", dir.path().display());

    // stdin is /dev/null, so the first prompt reads EOF immediately.
    let out = run_login_with_store(
        &["--key", "default"],
        "creds-declaring-canary.wasm",
        &backend,
    );
    assert!(
        !out.status.success(),
        "an aborted prompt must not report success: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    // And nothing may be left behind: a half-written credential is the state
    // this failure mode is dangerous for.
    let list = Command::new(act_binary_path())
        .args(["secret", "list", "--credentials-backend", &backend])
        .output()
        .expect("run act secret list");
    let listed = String::from_utf8_lossy(&list.stdout);
    assert!(
        listed.trim() == "{}" || !listed.contains("default"),
        "an aborted login must store nothing, got: {listed}"
    );
}

#[test]
fn a_component_that_uses_no_credentials_is_told_so_first() {
    let out = run_login(&["--key", "anything"], "time.wasm");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("uses no credentials"),
        "the cheapest check must come first: {err}"
    );
}

#[test]
fn an_unsupported_field_type_is_named_not_prompted_for() {
    // std:oauth2 arrives with the flow, which this release does not implement.
    // Prompting for it as if it were a string would store a value the component
    // cannot use, and the user would not learn why until much later.
    let out = run_login(&["--key", "default"], "oauth-declaring-canary.wasm");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("std:oauth2"),
        "the error must name the type: {err}"
    );
    assert!(!err.contains("Password"), "it must not have prompted");
}

#[test]
fn an_existing_credential_is_not_overwritten_without_force() {
    let (store, _dir) = seeded_store("default");
    let out = run_login_with_store(&["--key", "default"], "creds-declaring-canary.wasm", &store);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--force"), "must say how to replace it: {err}");
}
