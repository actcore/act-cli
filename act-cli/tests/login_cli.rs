//! `act login` — the interactive counterpart to `act secret set`, driven
//! against the real binary and real fixtures (see `tests/fixtures-src/README.md`
//! for how `oauth-declaring-canary.wasm` and `creds-declaring-canary.wasm` are
//! built: the same `credentials-canary` bytes, packed against a second
//! `act.toml`).
//!
//! Nearly every case here is a refusal, on purpose: the three properties that
//! matter most for a command that writes secrets are the ones that stop it from
//! writing at all — an undeclared component is told so before anything else
//! runs, a field type this release cannot acquire is named rather than
//! prompted for, and an existing credential is never overwritten silently.
//! The ordinary success path (prompting, hidden input, the actual write) is
//! covered by `secret_cmd`'s unit tests and `login_cmd`'s own — piping a real
//! hidden prompt through a subprocess's stdin buys little a unit test on
//! `field_set`/`select_credential` doesn't already cover, and it risks a
//! flaky or hanging test if the guard under test regresses (see
//! `an_unsupported_field_type_is_named_not_prompted_for`, which relies on
//! exactly that risk to prove the type check bites).
//!
//! The one exception is `an_optional_field_can_be_skipped_by_answering_nothing`.
//! Skipping IS the success path there — a unit test can prove the prompt is
//! offered, but only a real run proves that answering nothing leaves the field
//! out of the record instead of storing an empty string or aborting.

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
        .args(["--key", key, "--field", "acme:value"])
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
            .write_all(br#"{"acme:value":"pre-existing-value"}"#)
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

/// A `std:oauth2` field is never prompted for — and when its declaration names
/// no resource, it cannot be acquired either.
///
/// The flow derives every address it contacts from the resource identifier
/// (design §5.5), so a declaration without one describes a credential this host
/// has no way to obtain. Refusing here, before a browser opens, is the whole
/// difference between a clear error and a half-run flow.
///
/// This fixture is exactly that case. It used to prove the type was refused
/// outright, which stopped being true when the flow landed.
#[test]
fn an_oauth2_field_without_a_resource_is_named_not_prompted_for() {
    let out = run_login(&["--key", "default"], "oauth-declaring-canary.wasm");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("std:oauth2") && err.contains("resource"),
        "the error must name the type and what is missing: {err}"
    );
    // Not `!err.contains("Password")`: this fixture's label is "OAuth token", so
    // that assertion could never fire and passed vacuously. A prompt is only
    // rendered as `label [field-key]: `, so the bracketed form is what proves
    // one was never printed — and the refusal message names the key without it.
    assert!(
        !err.contains("OAuth token ["),
        "it must refuse before rendering a prompt: {err}"
    );
}

#[test]
fn an_existing_credential_is_not_overwritten_without_force() {
    let (store, _dir) = seeded_store("default");
    let out = run_login_with_store(&["--key", "default"], "creds-declaring-canary.wasm", &store);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--force"), "must say how to replace it: {err}");
}

/// Answering nothing at an optional field's prompt leaves it out of the record.
///
/// Driven through the operator's field definitions rather than a component's
/// declaration, because that needs no fixture rebuild and exercises the same
/// `prompts_for` → `prompt_one` path; `field_def_from_declared` copies
/// `required` across unchanged, and `login_cmd`'s unit tests cover that hop.
///
/// The three outcomes this separates are the whole point: **stored** (the
/// required field), **absent** (the optional one), and **an empty string**,
/// which is the failure mode that looks like success. Asserting only the exit
/// code would pass on all three.
#[test]
fn an_optional_field_can_be_skipped_by_answering_nothing() {
    use std::io::Write;

    let home = tempfile::tempdir().expect("config home");
    let fields = home.path().join("act/fields");
    std::fs::create_dir_all(&fields).expect("fields dir");
    std::fs::write(
        fields.join("note.toml"),
        "key = \"acme:note\"\nlabel = \"Note\"\nsecret = false\nrequired = false\n",
    )
    .expect("write field definition");

    let store = tempfile::tempdir().expect("temp store");
    let backend = format!("file:{}", store.path().display());

    let mut child = Command::new(act_binary_path())
        .arg("login")
        .arg(fixture("credentials-canary.wasm"))
        .args([
            "--key",
            "k",
            "--field",
            "acme:token",
            "--field",
            "acme:note",
        ])
        .args(["--credentials-backend", &backend])
        .env("XDG_CONFIG_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn act login");
    // The required field, then an empty line for the optional one.
    child
        .stdin
        .as_mut()
        .expect("stdin was piped")
        .write_all(b"typed-secret\n\n")
        .expect("write answers");
    let out = child.wait_with_output().expect("act login");

    assert!(
        out.status.success(),
        "skipping an optional field is not an error: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Enter to skip"),
        "the prompt must have offered the way out: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("acme:token") && !stdout.contains("acme:note"),
        "it must report what was stored, not what was asked for: {stdout}"
    );

    // Read the store itself: `act secret list` prints no field names, so it
    // cannot tell an absent field from one holding "".
    let raw = std::fs::read_to_string(store.path().join("secrets.json")).expect("read store");
    assert!(
        raw.contains("acme:token"),
        "the required field is missing: {raw}"
    );
    assert!(
        !raw.contains("acme:note"),
        "a skipped field must be absent, not empty: {raw}"
    );
    assert!(
        !raw.contains(r#""""#),
        "nothing may have been stored as an empty string: {raw}"
    );
}

/// The same empty answer, on a required field, must refuse.
///
/// `eof_at_a_prompt_aborts_instead_of_storing_an_empty_value` does not cover
/// this: EOF is caught one layer down, by the read itself. Pressing Enter is a
/// successful read of an empty line, and it reaches a different branch — the
/// one that now has to tell "skip me" from "I have no value", where before the
/// optional case existed there was nothing to tell apart.
#[test]
fn an_empty_answer_on_a_required_field_is_refused() {
    use std::io::Write;

    let store = tempfile::tempdir().expect("temp store");
    let backend = format!("file:{}", store.path().display());

    let mut child = Command::new(act_binary_path())
        .arg("login")
        .arg(fixture("creds-declaring-canary.wasm"))
        .args(["--key", "default"])
        .args(["--credentials-backend", &backend])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn act login");
    child
        .stdin
        .as_mut()
        .expect("stdin was piped")
        .write_all(b"\n")
        .expect("write an empty answer");
    let out = child.wait_with_output().expect("act login");

    assert!(
        !out.status.success(),
        "an empty required field must not report success: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("cannot be empty"), "and must say why: {err}");
    assert!(
        !store.path().join("secrets.json").exists()
            || !std::fs::read_to_string(store.path().join("secrets.json"))
                .unwrap()
                .contains("acme:value"),
        "nothing may be left behind"
    );
}

/// A component's description is shown while provisioning and never recorded.
///
/// Once in the store, a description is indistinguishable from words the operator
/// typed with `--description`, and `list-secrets` hands it to the agent from
/// there (ACT-AUTH §1.1.5). Prose a component wrote has to stay attributable to
/// it (§5.5) — which it cannot be after a write that strips its origin.
///
/// The fixture declares `description = "API token"`, so that string is the
/// oracle: it must appear on stderr, marked as the component's, and must not
/// appear in what `act secret list` prints.
#[test]
fn the_components_description_is_shown_attributed_and_not_recorded() {
    use std::io::Write;

    let store = tempfile::tempdir().expect("temp store");
    let backend = format!("file:{}", store.path().display());

    let mut child = Command::new(act_binary_path())
        .arg("login")
        .arg(fixture("creds-declaring-canary.wasm"))
        .args(["--key", "default"])
        .args(["--description", "operators-own-words"])
        .args(["--credentials-backend", &backend])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn act login");
    child
        .stdin
        .as_mut()
        .expect("stdin was piped")
        .write_all(b"typed-secret\n")
        .expect("write the answer");
    let out = child.wait_with_output().expect("act login");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("API token"),
        "the component's description must be shown: {stderr}"
    );
    assert!(
        stderr.contains("That component describes it as"),
        "and marked as the component's words: {stderr}"
    );

    let list = Command::new(act_binary_path())
        .args(["secret", "list", "--credentials-backend", &backend])
        .output()
        .expect("run act secret list");
    let listed = String::from_utf8_lossy(&list.stdout);
    assert!(
        listed.contains("operators-own-words"),
        "the operator's own description is what gets recorded: {listed}"
    );
    assert!(
        !listed.contains("API token"),
        "the component's words must not be laundered into the store: {listed}"
    );

    // The case that actually pins it. With `--description` given, a fallback to
    // the component's words would be invisible here — the operator's win either
    // way. Provision a second key with no description at all: if anything falls
    // through, this is where it shows.
    let mut second = Command::new(act_binary_path())
        .arg("login")
        .arg(fixture("creds-declaring-canary.wasm"))
        .args(["--key", "default", "--force"])
        .args(["--credentials-backend", &backend])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn act login");
    second
        .stdin
        .as_mut()
        .expect("stdin was piped")
        .write_all(b"typed-secret\n")
        .expect("write the answer");
    let out = second.wait_with_output().expect("act login");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let list = Command::new(act_binary_path())
        .args(["secret", "list", "--credentials-backend", &backend])
        .output()
        .expect("run act secret list");
    let listed = String::from_utf8_lossy(&list.stdout);
    assert!(
        !listed.contains("API token"),
        "with no --description the record has none — the component's words are \
         not a fallback: {listed}"
    );
    assert!(
        !listed.contains("operators-own-words"),
        "and --force replaced the earlier record rather than merging it: {listed}"
    );
}
