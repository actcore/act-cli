//! Unit tests for the wasmtime host.
//!
//! They stayed one module across the `mod.rs` split: several reach into more
//! than one of the four files it became, and splitting them to match would
//! have meant rewriting assertions to fit a file layout rather than a
//! behaviour.

use crate::actor::{decode_meta_strings, meta_str, new_request_id, pack_visible_request_id};
use crate::audit::fmt_filter;
use crate::store::{declared_constraints, warn_if_credentials_exfil_risk};
use crate::*;
use std::sync::Arc;

#[test]
fn well_known_metadata_keys_are_extracted_for_the_envelope() {
    let md = vec![
        ("std:session-id".to_string(), "abc123".to_string()),
        ("std:agent-id".to_string(), "claude-code".to_string()),
        ("std:traceparent".to_string(), "00-aa-bb-01".to_string()),
        ("other".to_string(), "x".to_string()),
    ];
    assert_eq!(meta_str(&md, "std:session-id").as_deref(), Some("abc123"));
    assert_eq!(
        meta_str(&md, "std:agent-id").as_deref(),
        Some("claude-code")
    );
    assert_eq!(
        meta_str(&md, "std:traceparent").as_deref(),
        Some("00-aa-bb-01")
    );
    assert_eq!(meta_str(&md, "std:request-id"), None);
    assert_eq!(meta_str(&[], "std:session-id"), None);
}

#[test]
fn visible_request_id_prefixes_are_distinct_for_hundreds_of_counters_at_one_salt() {
    // Exercises `pack_visible_request_id` directly with explicit inputs,
    // not `new_request_id`'s real global counter: that counter is one
    // `static` shared by every test in this binary (integration tests
    // in `tests/*.rs` are separate processes and don't share it, but
    // other unit tests in this same file might), so drawing "several
    // hundred" real ids and asserting they're distinct would only be
    // true assuming nothing else increments the counter concurrently —
    // a coin flip with different odds, exactly what this test replaces.
    // Fixed-width bit-packing makes the counter-side of the property
    // deterministic instead: for a FIXED salt, every counter from 0 up
    // to `2^REQUEST_ID_COUNTER_BITS - 1` (512) must pack to a distinct
    // 24-bit value — provably, not "usually" — so this holds for any
    // salt, any interleaving, any number of parallel test threads.
    let salt = 0x1234;
    let mut seen = std::collections::HashSet::new();
    for counter in 0..500u64 {
        let visible = pack_visible_request_id(counter, salt);
        assert!(
            seen.insert(visible),
            "counter {counter} collided with an earlier one at salt {salt:#x}: \
             visible={visible:#08x}"
        );
    }
}

#[test]
fn fixed_width_packing_avoids_a_confirmed_variable_width_collision() {
    // Brute-force search found a genuine collision in the rejected
    // variable-width scheme `format!("{:x}{}", counter, salt)`: counter
    // 1 and counter 0x11 both render "111111" (their first 6 chars) at
    // salt 0x11111 — the counter's own digit happens to match a run of
    // repeated digits in the salt, so a short counter's representation
    // is silently absorbed into a longer counter's leading digits.
    let naive = |counter: u64, salt: u32| -> String {
        let s = format!("{counter:x}{salt:x}");
        s.chars().take(6).collect()
    };
    assert_eq!(
        naive(1, 0x11111),
        naive(0x11, 0x11111),
        "sanity check: this is the confirmed collision in the naive scheme"
    );

    // The real, fixed-width bit-packed scheme cannot exhibit this: the
    // counter always occupies the same bit positions, so no salt value
    // can shift a shorter counter's digits into a longer one's.
    let a = format!("{:06x}", pack_visible_request_id(1, 0x11111));
    let b = format!("{:06x}", pack_visible_request_id(0x11, 0x11111));
    assert_ne!(
        a, b,
        "fixed-width packing must not reproduce the naive collision"
    );
}

#[test]
fn decode_meta_strings_reads_cbor_text_and_drops_everything_else() {
    // The real call sites hand `meta_str` decoded metadata, not the raw
    // WIT tuples — this is the seam between the two.
    let raw: Vec<(String, Vec<u8>)> = vec![
        (
            "std:session-id".to_string(),
            act_types::cbor::to_cbor(&"abc123".to_string()),
        ),
        (
            "std:request-id".to_string(),
            act_types::cbor::to_cbor(&42u64),
        ),
    ];
    let decoded = decode_meta_strings(&raw);
    assert_eq!(
        meta_str(&decoded, "std:session-id").as_deref(),
        Some("abc123")
    );
    // A non-string CBOR value is dropped rather than stringified.
    assert_eq!(meta_str(&decoded, "std:request-id"), None);
}

#[test]
fn a_request_id_is_always_available() {
    // Correlation must never depend on the caller having supplied an
    // id. No literal prefix is asserted here (dropped in the request-id
    // rework — a fixed `act-` literal ate 4 of the 6 bytes
    // `render_rollup` actually shows, which was the root of the
    // collision this fixed); the format is non-normative, only
    // "always present and non-repeating" is.
    let a = new_request_id();
    let b = new_request_id();
    assert_ne!(a, b);
    assert!(!a.is_empty());
}

#[test]
fn load_component_reports_the_digest_of_the_file_bytes() {
    let engine = create_engine().expect("engine");
    let path = std::path::Path::new("tests/fixtures/ask-canary.wasm");
    if !path.exists() {
        // Fixture-dependent; skip rather than fail on a fresh checkout.
        return;
    }
    let bytes = std::fs::read(path).expect("read fixture");
    let (_component, digest) = load_component(&engine, path).expect("load");
    assert_eq!(digest, crate::audit::sha256_hex(&bytes));
}

// ── act:credentials declared-slice contract ───────────────────────────

use act_policy::grant::PolicyMode;
use act_policy::providers::credentials::CAP_CREDENTIALS;

/// Parse an `act.toml`-shaped fragment the way the real manifest is read.
///
/// These tests deliberately go through TOML rather than hand-building a
/// `Vec<serde_json::Value>`: the entire defect being guarded against is
/// that the *prescribed declaration syntax* parses to zero constraints.
/// A hand-built `vec![json!({})]` would assert the fix's output while
/// saying nothing about the input production actually receives — which is
/// exactly how this defect survived its first review.
fn info_from_act_toml(src: &str) -> ComponentInfo {
    toml::from_str(src).expect("act.toml fragment must parse into ComponentInfo")
}

#[test]
fn a_bare_credentials_table_is_handed_to_the_provider_as_a_non_empty_slice() {
    let info = info_from_act_toml(
        r#"
        [std]
        name = "notion"

        [std.capabilities."act:credentials"]
        "#,
    );

    // Precondition — this is the trap. The spec-prescribed declaration
    // form really does parse to an empty constraint list, so the raw
    // manifest cannot distinguish "declared" from "absent" on its own.
    assert!(
        info.std
            .capabilities
            .get(CAP_CREDENTIALS)
            .expect("capability must be present in the parsed manifest")
            .constraints
            .is_empty(),
        "the bare-table form is expected to carry zero constraints; if this \
         ever changes, `declared_constraints`' credentials branch is moot"
    );

    // `CredentialsProvider::resolve` derives declared-ness from
    // `!declared.is_empty()` and sees nothing else, so a sentinel must be
    // synthesized or every credential access is denied forever while the
    // audit trail blames the component for not declaring the class.
    assert!(
        !declared_constraints(&info, CAP_CREDENTIALS).is_empty(),
        "a component that declared act:credentials must reach the provider \
         as a non-empty declared slice"
    );
}

#[test]
fn an_undeclared_credentials_capability_is_handed_over_as_an_empty_slice() {
    let info = info_from_act_toml(
        r#"
        [std]
        name = "no-secrets"

        [std.capabilities."wasi:http"]
        constraints = [{ host = "api.notion.com" }]
        "#,
    );

    assert!(
        !info.std.capabilities.has(CAP_CREDENTIALS),
        "sanity: this manifest must not declare act:credentials"
    );
    assert!(
        declared_constraints(&info, CAP_CREDENTIALS).is_empty(),
        "an undeclared act:credentials must stay empty so the provider denies it"
    );
}

#[test]
fn the_sentinel_is_scoped_to_credentials_and_never_perturbs_physical_classes() {
    // For wasi:filesystem/http/sockets an empty `declared` legitimately
    // means "no ceiling, deny" — and their providers parse every element
    // of the slice as a typed constraint, so a `{}` sentinel would be fed
    // to a parser expecting `{"host": ...}` / `{"path": ...}`.
    let info = info_from_act_toml(
        r#"
        [std]
        name = "bare-physical"

        [std.capabilities."wasi:filesystem"]

        [std.capabilities."wasi:http"]

        [std.capabilities."wasi:sockets"]
        "#,
    );

    for cap in [
        act_types::constants::CAP_FILESYSTEM,
        act_types::constants::CAP_HTTP,
        act_types::constants::CAP_SOCKETS,
    ] {
        assert!(
            info.std.capabilities.has(cap),
            "sanity: {cap} must be declared in this manifest"
        );
        assert!(
            declared_constraints(&info, cap).is_empty(),
            "{cap} is declared bare, so its declared slice must stay empty — \
             no sentinel, or its provider would try to parse `{{}}` as a rule"
        );
    }
}

#[test]
fn declared_constraints_passes_physical_constraints_through_verbatim() {
    let info = info_from_act_toml(
        r#"
        [std]
        name = "scoped"

        [std.capabilities."wasi:http"]
        constraints = [{ host = "api.notion.com" }, { host = "*.example.com" }]
        "#,
    );

    assert_eq!(
        declared_constraints(&info, act_types::constants::CAP_HTTP),
        vec![
            serde_json::json!({ "host": "api.notion.com" }),
            serde_json::json!({ "host": "*.example.com" }),
        ],
        "physical classes must see their manifest constraints untouched"
    );
}

// ── the credentials ceiling reaches the audit header ──────────────────

/// Resolve one component's ceilings the way `instantiate_component` does,
/// and hand back the vec the instantiation audit header is built from.
async fn ceilings_for(
    info: &ComponentInfo,
    policy: &act_policy::grant::GrantPolicy,
) -> Vec<(String, Arc<dyn act_policy::provider::CompiledCeiling>)> {
    let engine = create_engine().expect("engine");
    let (_store, ceilings) = create_store(
        &engine,
        &[],
        policy,
        info,
        None,
        Arc::new(act_policy::consent::DenyPrompter),
        Arc::new(act_policy::consent::DecisionCache::new()),
        None,
    )
    .await
    .expect("create_store");
    ceilings
}

#[tokio::test(flavor = "current_thread")]
async fn the_credentials_class_is_among_the_ceilings_the_audit_header_renders() {
    // `instantiate_component` emits one `act.ceiling_class` event per
    // entry of this vec and nothing else, so a class missing from it is a
    // class no operator ever sees — the component's declared credential
    // access would leave no trace in the trail at all.
    let info = info_from_act_toml(
        r#"
        [std]
        name = "notion"

        [std.capabilities."act:credentials"]
        "#,
    );
    let ceilings = ceilings_for(&info, &grants(&[(CAP_CREDENTIALS, PolicyMode::Ask)])).await;

    let (_, ceiling) = ceilings
        .iter()
        .find(|(id, _)| id == CAP_CREDENTIALS)
        .expect("act:credentials must be one of the resolved ceilings");
    assert!(
        ceiling.declared(),
        "the manifest declared it, so the header must not report otherwise"
    );
    assert_eq!(ceiling.effective_mode(), PolicyMode::Ask);
}

#[tokio::test(flavor = "current_thread")]
async fn an_undeclared_credentials_class_is_still_reported_and_resolves_to_deny() {
    // Reported, not omitted: the header's job is to state the mode of
    // every class, and "deny" is the answer an operator needs when a
    // component silently fails to read a credential it never declared.
    let info = info_from_act_toml(
        r#"
        [std]
        name = "crypto"
        "#,
    );
    let ceilings = ceilings_for(&info, &grants(&[(CAP_CREDENTIALS, PolicyMode::Open)])).await;

    let (_, ceiling) = ceilings
        .iter()
        .find(|(id, _)| id == CAP_CREDENTIALS)
        .expect("act:credentials must be reported even when undeclared");
    assert!(!ceiling.declared());
    assert_eq!(
        ceiling.effective_mode(),
        PolicyMode::Deny,
        "an open grant must not widen a class the component never declared"
    );
}

// ── the credentials + open-network warning ────────────────────────────

/// A `MakeWriter` that accumulates formatted events in memory, so the
/// warning can be asserted as it is actually emitted (target included)
/// rather than by re-testing the `if` that guards it.
#[derive(Clone, Default)]
struct CapturedLog(Arc<std::sync::Mutex<Vec<u8>>>);

impl CapturedLog {
    fn contents(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).expect("utf-8 log output")
    }
}

impl std::io::Write for CapturedLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Run the warning through **the production `fmt` layer**, filter and all.
///
/// Deliberately not a bare `fmt()` subscriber. `crate::fmt_filter` drops
/// the `act::audit` and `act::guest` targets so audit events are rendered
/// only by `render.rs`, and `AuditLayer::on_event` in turn drops any event
/// that is not a typed capability record. An advisory addressed to
/// `act::audit` therefore falls between the two layers and reaches no
/// output at all — which is exactly what this warning did before, and a
/// bare `fmt()` subscriber would have happily printed it and called the
/// test green.
/// A `GrantPolicy` with explicit per-class modes and everything else denied.
fn grants(pairs: &[(&str, PolicyMode)]) -> act_policy::grant::GrantPolicy {
    act_policy::grant::GrantPolicy {
        default: PolicyMode::Deny,
        entries: pairs
            .iter()
            .map(|(id, mode)| {
                (
                    (*id).to_string(),
                    act_policy::grant::CapabilityGrant {
                        mode: *mode,
                        allow: vec![],
                        deny: vec![],
                    },
                )
            })
            .collect(),
    }
}

fn capture_exfil_warning(info: &ComponentInfo, network_grants: &[(&str, PolicyMode)]) -> String {
    use tracing_subscriber::prelude::*;

    let log = CapturedLog::default();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(log.clone())
            .with_ansi(false)
            // The default `log-level = "info"` from `config.toml`, i.e.
            // what an operator who configured nothing actually runs with.
            .with_filter(fmt_filter(tracing_subscriber::EnvFilter::new("act=info"))),
    );
    // Thread-local, so parallel tests don't fight over a global default.
    let policy = grants(network_grants);
    tracing::subscriber::with_default(subscriber, || {
        warn_if_credentials_exfil_risk(info, &policy);
    });
    log.contents()
}

/// A component with credentials **and genuine reach**: `wasi:http`
/// declared with real hosts, so an `open` grant actually leaves it able to
/// talk to them.
///
/// The earlier version of this fixture declared `wasi:http` as a bare
/// table, which `effective_http` forces to `Deny` — so the positive test
/// was asserting that the host warns about a component whose HTTP ceiling
/// blocks everything.
fn credentials_and_reachable_http() -> ComponentInfo {
    info_from_act_toml(
        r#"
        [std]
        name = "notion-sync"

        [std.capabilities."act:credentials"]

        [std.capabilities."wasi:http"]
        constraints = [{ host = "api.notion.com" }, { host = "*.notion.so" }]
        "#,
    )
}

fn credentials_and_reachable_sockets() -> ComponentInfo {
    info_from_act_toml(
        r#"
        [std]
        name = "pg-sync"

        [std.capabilities."act:credentials"]

        [std.capabilities."wasi:sockets"]
        constraints = [{ host = "db.internal", ports = [5432], protocols = ["tcp"] }]
        "#,
    )
}

#[test]
fn credentials_plus_open_http_warns_about_exfiltration_not_just_the_two_names() {
    let out = capture_exfil_warning(
        &credentials_and_reachable_http(),
        &[
            (act_types::constants::CAP_HTTP, PolicyMode::Open),
            (act_types::constants::CAP_SOCKETS, PolicyMode::Deny),
        ],
    );

    assert!(
        !out.is_empty(),
        "the warning must actually reach an output layer — addressed to \
         `act::audit` it is dropped by `fmt_filter` and then again by \
         `AuditLayer::on_event`, and nothing is printed at all"
    );
    assert!(
        out.contains("WARN"),
        "the combination must be reported at WARN, got: {out}"
    );
    assert!(
        out.contains("notion-sync"),
        "must name the component it is about, got: {out}"
    );
    assert!(
        out.contains("wasi:http"),
        "must name the class whose grant is open, got: {out}"
    );
    // The point of the warning is the *consequence* of the pairing. Naming
    // the two capabilities without saying what they add up to tells the
    // operator nothing they could not read off their own command line.
    assert!(
        out.contains("send your credentials anywhere that declaration permits"),
        "must state that credentials can be sent across that reach, got: {out}"
    );
    assert!(
        out.contains("only limit on where it can reach"),
        "must state that the artifact's own declaration is the last bound \
         standing once the operator's grant is open, got: {out}"
    );
    // An `open` grant collapses to `Allowlist` bounded by the declaration
    // (`effective.rs:144`), so "any host" is simply false. An overstated
    // warning is a warning operators learn to skip.
    assert!(
        !out.contains("any host"),
        "must not claim unbounded reach — an open grant is still bounded by \
         the component's declaration, got: {out}"
    );
}

#[test]
fn credentials_plus_open_sockets_warns_too_because_raw_tcp_exfiltrates_as_well() {
    // Design §4.1 rests containment on credentials + http *and* sockets.
    // Covering only http would leave the identical channel open under a
    // different capability id.
    let out = capture_exfil_warning(
        &credentials_and_reachable_sockets(),
        &[
            (act_types::constants::CAP_HTTP, PolicyMode::Deny),
            (act_types::constants::CAP_SOCKETS, PolicyMode::Open),
        ],
    );

    assert!(
        out.contains("wasi:sockets"),
        "an open wasi:sockets grant must warn and name the class, got: {out}"
    );
    assert!(
        out.contains("pg-sync"),
        "must name the component it is about, got: {out}"
    );
}

#[test]
fn both_network_classes_open_are_both_named() {
    let info = info_from_act_toml(
        r#"
        [std]
        name = "wide-open"

        [std.capabilities."act:credentials"]

        [std.capabilities."wasi:http"]
        constraints = [{ host = "api.example.com" }]

        [std.capabilities."wasi:sockets"]
        constraints = [{ host = "db.internal", ports = [5432], protocols = ["tcp"] }]
        "#,
    );
    let out = capture_exfil_warning(
        &info,
        &[
            (act_types::constants::CAP_HTTP, PolicyMode::Open),
            (act_types::constants::CAP_SOCKETS, PolicyMode::Open),
        ],
    );

    assert!(
        out.contains("wasi:http") && out.contains("wasi:sockets"),
        "both open classes must be named, got: {out}"
    );
}

#[test]
fn an_open_grant_on_a_class_the_component_cannot_actually_reach_stays_silent() {
    // The reach is the ceiling — grant ∩ declaration — not the grant. Both
    // shapes below are forced to `Deny` by `act_policy::effective`, so the
    // component can reach nothing and there is nothing to warn about.
    // Warning here is the false positive that trains operators to ignore
    // every warning the host emits.
    let bare_declaration = info_from_act_toml(
        r#"
        [std]
        name = "bare-net"

        [std.capabilities."act:credentials"]

        [std.capabilities."wasi:http"]

        [std.capabilities."wasi:sockets"]
        "#,
    );
    let out = capture_exfil_warning(
        &bare_declaration,
        &[
            (act_types::constants::CAP_HTTP, PolicyMode::Open),
            (act_types::constants::CAP_SOCKETS, PolicyMode::Open),
        ],
    );
    assert!(
        out.is_empty(),
        "a bare network declaration is forced to Deny (effective.rs:118), so \
         an open grant on it reaches nothing and must not warn, got: {out}"
    );

    let never_declared = info_from_act_toml(
        r#"
        [std]
        name = "no-net"

        [std.capabilities."act:credentials"]
        "#,
    );
    let out = capture_exfil_warning(
        &never_declared,
        &[
            (act_types::constants::CAP_HTTP, PolicyMode::Open),
            (act_types::constants::CAP_SOCKETS, PolicyMode::Open),
        ],
    );
    assert!(
        out.is_empty(),
        "an undeclared class is forced to Deny (effective.rs:100) — \
         `--allow wasi:http` buys such a component nothing, got: {out}"
    );
}

#[test]
fn neither_capability_alone_triggers_the_exfiltration_warning() {
    // Reach is bounded by a grant the operator chose, so no warning — the
    // artifact's declaration is not the only thing standing between the
    // credentials and the network.
    for mode in [PolicyMode::Deny, PolicyMode::Allowlist, PolicyMode::Ask] {
        let out = capture_exfil_warning(
            &credentials_and_reachable_http(),
            &[
                (act_types::constants::CAP_HTTP, mode),
                (act_types::constants::CAP_SOCKETS, mode),
            ],
        );
        assert!(
            out.is_empty(),
            "act:credentials with network in {mode} mode must not warn, got: {out}"
        );
    }

    // Wide-open network but nothing to exfiltrate: no credentials, no warning.
    let no_credentials = info_from_act_toml(
        r#"
        [std]
        name = "plain-fetcher"

        [std.capabilities."wasi:http"]
        constraints = [{ host = "api.example.com" }]

        [std.capabilities."wasi:sockets"]
        constraints = [{ host = "db.internal", ports = [5432], protocols = ["tcp"] }]
        "#,
    );
    let out = capture_exfil_warning(
        &no_credentials,
        &[
            (act_types::constants::CAP_HTTP, PolicyMode::Open),
            (act_types::constants::CAP_SOCKETS, PolicyMode::Open),
        ],
    );
    assert!(
        out.is_empty(),
        "open network without act:credentials must not warn, got: {out}"
    );
}

#[tokio::test]
async fn a_closed_actor_channel_surfaces_as_an_internal_error() {
    // The handle is opaque, so a host cannot see the request enum behind it
    // and cannot tell a dead actor from a live one by inspection. Every
    // method must therefore answer a dead actor rather than hang or panic.
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    drop(rx);
    let handle = ComponentHandle::new(tx);

    let err = handle
        .list_tools(&Metadata::default())
        .await
        .expect_err("a dropped actor must not resolve");
    match err {
        ComponentError::Internal(e) => assert_eq!(e.to_string(), "component actor unavailable"),
        ComponentError::Tool(_) => panic!("a dead actor is a host failure, not a tool error"),
    }
}
