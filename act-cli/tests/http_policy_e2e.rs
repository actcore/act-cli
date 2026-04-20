//! End-to-end HTTP policy tests using a real ACT component.
//!
//! Requires a built `http-client` component. Set the `ACT_TEST_HTTP_CLIENT_WASM`
//! env var to its path, or rely on the default location under
//! `../components/http-client/target/wasm32-wasip2/release/`. Tests skip with a
//! message when the component isn't available — running the full suite requires
//! a reachable `example.com` over HTTPS.
//!
//! Run with `cargo test -p act-cli --test http_policy_e2e -- --nocapture` after
//! building the http-client component with `just build` in its directory.

use std::path::PathBuf;
use std::process::Command;

const DEFAULT_PATH: &str =
    "../../components/http-client/target/wasm32-wasip2/release/component_http_client.wasm";

fn fixture_wasm() -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var("ACT_TEST_HTTP_CLIENT_WASM") {
        let p = PathBuf::from(env_path);
        if p.exists() {
            return Some(p);
        }
    }
    let default = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_PATH);
    if default.exists() {
        return Some(default);
    }
    None
}

fn skip_if_missing() -> Option<PathBuf> {
    match fixture_wasm() {
        Some(p) => Some(p),
        None => {
            eprintln!(
                "skipping: set ACT_TEST_HTTP_CLIENT_WASM or build components/http-client first"
            );
            None
        }
    }
}

fn run_call(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_act"))
        .args(args)
        .output()
        .expect("failed to spawn act");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn default_deny_blocks_http() {
    let Some(wasm) = skip_if_missing() else {
        return;
    };
    let wasm_s = wasm.to_string_lossy().to_string();
    let (ok, _stdout, stderr) = run_call(&[
        "call",
        &wasm_s,
        "fetch",
        "--args",
        r#"{"url":"https://example.com"}"#,
    ]);
    assert!(!ok, "expected call to fail under default deny policy");
    assert!(
        stderr.contains("HttpRequestDenied") || stderr.contains("blocked by ACT policy"),
        "stderr should explain denial; got: {stderr}"
    );
}

#[test]
fn http_allow_matching_host_succeeds() {
    let Some(wasm) = skip_if_missing() else {
        return;
    };
    let wasm_s = wasm.to_string_lossy().to_string();
    let (ok, stdout, stderr) = run_call(&[
        "call",
        "--http-allow",
        "example.com",
        &wasm_s,
        "fetch",
        "--args",
        r#"{"url":"https://example.com"}"#,
    ]);
    assert!(
        ok,
        "expected call to succeed with --http-allow example.com; stderr: {stderr}"
    );
    assert!(
        stdout.contains("Example Domain") || stdout.contains("example"),
        "expected response body; got stdout: {stdout}"
    );
}

#[test]
fn http_allow_mismatched_host_blocks() {
    let Some(wasm) = skip_if_missing() else {
        return;
    };
    let wasm_s = wasm.to_string_lossy().to_string();
    let (ok, _stdout, stderr) = run_call(&[
        "call",
        "--http-allow",
        "evil.example",
        &wasm_s,
        "fetch",
        "--args",
        r#"{"url":"https://example.com"}"#,
    ]);
    assert!(
        !ok,
        "expected deny when allow rule's host doesn't match request host"
    );
    assert!(
        stderr.contains("HttpRequestDenied") || stderr.contains("blocked by ACT policy"),
        "stderr should explain denial; got: {stderr}"
    );
}

#[test]
fn http_policy_open_allows_any_host() {
    let Some(wasm) = skip_if_missing() else {
        return;
    };
    let wasm_s = wasm.to_string_lossy().to_string();
    let (ok, stdout, stderr) = run_call(&[
        "call",
        "--http-policy",
        "open",
        &wasm_s,
        "fetch",
        "--args",
        r#"{"url":"https://example.com"}"#,
    ]);
    assert!(
        ok,
        "expected open policy to allow the request; stderr: {stderr}"
    );
    assert!(
        stdout.contains("Example Domain") || stdout.contains("example"),
        "expected response body; got stdout: {stdout}"
    );
}

// ── CIDR coverage: the reqwest DNS resolver hook ─────────────────────────────

#[test]
fn deny_cidr_blocks_with_dns_error() {
    // Allow host by name, deny every IP it could resolve to. The DNS
    // resolver filters all addresses out and the guest sees DnsError
    // (not ConnectionRefused — we walk reqwest's error chain to
    // surface policy denials as DNS errors).
    let Some(wasm) = skip_if_missing() else {
        return;
    };
    let wasm_s = wasm.to_string_lossy().to_string();
    let (ok, _stdout, stderr) = run_call(&[
        "call",
        "--http-allow",
        "example.com",
        "--http-deny",
        "0.0.0.0/0",
        "--http-deny",
        "::/0",
        &wasm_s,
        "fetch",
        "--args",
        r#"{"url":"https://example.com"}"#,
    ]);
    assert!(!ok, "expected deny-CIDR to block; stderr: {stderr}");
    assert!(
        stderr.contains("DnsError"),
        "expected DnsError mapping from DNS-deny, got: {stderr}"
    );
}

#[test]
fn allow_cidr_only_blocks_when_no_host_match() {
    // A user rule that's CIDR-only (no host) doesn't intersect with the
    // component's host-based declaration (`host = "*"` or any other host
    // pattern). After the effective-policy filter, the effective allow
    // is empty, so the HTTP layer denies at decide_uri before DNS even
    // runs. This is correct under the declaration-as-ceiling model:
    // components declare peers by name, and user-policy CIDR-only rules
    // have no declared host to pair with.
    let Some(wasm) = skip_if_missing() else {
        return;
    };
    let wasm_s = wasm.to_string_lossy().to_string();
    let (ok, _stdout, stderr) = run_call(&[
        "call",
        "--http-allow",
        "10.0.0.0/8",
        &wasm_s,
        "fetch",
        "--args",
        r#"{"url":"https://example.com"}"#,
    ]);
    assert!(!ok, "expected allow-CIDR-only to block; stderr: {stderr}");
    assert!(
        stderr.contains("HttpRequestDenied") || stderr.contains("blocked by ACT policy"),
        "expected HttpRequestDenied from effective-empty-allow, got: {stderr}"
    );
}

#[test]
fn allow_cidr_with_host_match_succeeds() {
    // Host-anchored allow rule approves the hostname → resolver keeps
    // every resolved IP regardless of the unrelated allow-CIDR rule.
    let Some(wasm) = skip_if_missing() else {
        return;
    };
    let wasm_s = wasm.to_string_lossy().to_string();
    let (ok, stdout, stderr) = run_call(&[
        "call",
        "--http-allow",
        "example.com",
        "--http-allow",
        "10.0.0.0/8",
        &wasm_s,
        "fetch",
        "--args",
        r#"{"url":"https://example.com"}"#,
    ]);
    assert!(
        ok,
        "expected host match to bypass allow-CIDR check; stderr: {stderr}"
    );
    assert!(
        stdout.contains("Example Domain") || stdout.contains("example"),
        "expected response body; got stdout: {stdout}"
    );
}
