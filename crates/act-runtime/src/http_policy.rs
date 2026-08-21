//! Layer 1 phase C2: per-request HTTP policy hook.
//!
//! Intercepts `wasi:http/outgoing-handler` via `WasiHttpHooks::send_request`
//! (both p2 and p3). Checks each outgoing request against the resolved
//! `HttpConfig` and either delegates to the default handler or returns
//! `ErrorCode::HttpRequestDenied`. Deny-by-default for `allowlist` mode;
//! `open` allows every request; `deny` blocks every request.
//!
//! Enforcement scope:
//! - Host matching: literal host, exact match or `*.suffix` wildcard.
//! - Scheme / methods / ports matching.
//! - IP literals in URI: matched against `cidr` entries at HTTP-layer.
//! - **DNS-resolved IPs against both allow and deny CIDRs**: enforced in
//!   the reqwest `PolicyDnsResolver` hook (`runtime::http_client`). The
//!   resolver runs once per request, filters denied IPs, and in
//!   `Allowlist` mode additionally requires allow-CIDR coverage when the
//!   hostname doesn't match any host-anchored allow rule. Named-host URIs
//!   with only allow-CIDR rules defer their verdict from the HTTP layer
//!   to the resolver. The single resolve pins the addresses for the
//!   subsequent connect, closing the DNS-rebinding window.
//! - Redirect re-decision: each hop re-evaluated via `reqwest::redirect`
//!   hook (see `http_client::build_redirect_policy`).

use std::future::Future;
use std::sync::Arc;

use http::Uri;
use wasmtime_wasi_http::{Error as HttpError, RequestOptions, WasiBody};

use act_policy::Decision;
use act_policy::consent::{ConsentAsk, ConsentPrompter, DecisionCache};
use act_policy::provider::{CompiledCeiling, ResourceOp};

use crate::audit::{CapDecisionRecord, Decision4, emit_cap_decision};
use crate::http_client::ActHttpClient;

/// The capability gate for `wasi:http`, as one `WasiHttpHooks` covering both
/// wasip2 and wasip3 — wasmtime 48 routes them through the same hook.
pub struct PolicyHttpHooks {
    ceiling: Arc<dyn CompiledCeiling>,
    client: Arc<crate::http_client::ActHttpClient>,
    prompter: Arc<dyn ConsentPrompter>,
    cache: Arc<DecisionCache>,
}

impl PolicyHttpHooks {
    pub fn new(
        ceiling: Arc<dyn CompiledCeiling>,
        client: Arc<crate::http_client::ActHttpClient>,
        prompter: Arc<dyn ConsentPrompter>,
        cache: Arc<DecisionCache>,
    ) -> Self {
        Self {
            ceiling,
            client,
            prompter,
            cache,
        }
    }

    /// Build the `ConsentAsk` for an outgoing request: cache key is
    /// `host:port`, summary names the method + URI.
    fn http_ask(method: Option<&str>, uri: &Uri) -> ConsentAsk {
        let host = uri.host().unwrap_or("");
        let scheme = uri.scheme_str();
        let port = uri
            .port_u16()
            .unwrap_or(if scheme == Some("https") { 443 } else { 80 });
        ConsentAsk {
            cap_id: act_types::constants::CAP_HTTP.to_string(),
            key: format!("{host}:{port}"),
            summary: format!("HTTP {} {}", method.unwrap_or("?"), uri),
        }
    }

    /// Decide an HTTP request against the ceiling. Emits an audit record for
    /// `Allow`/`Deny`; `Ask` is deliberately silent here — the verdict does
    /// not exist yet. It is emitted where the ask path actually resolves
    /// (the `Decision::Ask` arms of `send_request` below), mirroring
    /// `fs_policy::resolve_ask`.
    fn decide_uri(&self, method: Option<&str>, uri: &Uri) -> Decision {
        let host = uri.host().unwrap_or("");
        let scheme = uri.scheme_str().unwrap_or("https");
        let port = uri
            .port_u16()
            .unwrap_or(if scheme == "https" { 443 } else { 80 });
        let op = ResourceOp {
            cap_id: act_types::constants::CAP_HTTP.to_string(),
            key: format!("{host}:{port}"),
            action: method.unwrap_or("").to_string(),
            attrs: serde_json::json!({"scheme": scheme}),
        };
        let explained = self.ceiling.classify_explained(&op);
        let mode = self.ceiling.effective_mode().to_string();
        match explained.decision {
            Decision::Allow => {
                emit_cap_decision(&CapDecisionRecord::statik(
                    act_types::constants::CAP_HTTP,
                    &op.key,
                    &op.action,
                    Decision4::Allow,
                    &mode,
                    explained.rule,
                ));
            }
            Decision::Deny => {
                emit_cap_decision(&CapDecisionRecord::statik(
                    act_types::constants::CAP_HTTP,
                    &op.key,
                    &op.action,
                    Decision4::Deny,
                    &mode,
                    explained.rule,
                ));
            }
            Decision::Ask => {}
        }
        explained.decision
    }
}

fn deny_reason(method: Option<&str>, uri: &Uri) -> String {
    format!("blocked by ACT policy: {} {}", method.unwrap_or("?"), uri)
}

/// Resolve an `Ask`-mode HTTP decision via the interactive prompter (cached
/// per `host:port`), and emit the resulting `ask-allow`/`ask-deny` record.
/// Mirrors `fs_policy::resolve_ask`; used by the one hook covering both
/// wasip2 and wasip3, so
/// there is exactly one place either arm can call to reach a verdict, and no
/// way for them to drift from each other. Free function over owned data so
/// the returned future is `Send` and usable from a spawned task.
async fn resolve_http_ask(
    cache: Arc<DecisionCache>,
    prompter: Arc<dyn ConsentPrompter>,
    ask: ConsentAsk,
) -> bool {
    let key = ask.key.clone();
    let allowed = cache.decide_cached(&*prompter, ask).await;
    emit_cap_decision(&CapDecisionRecord::answered(
        act_types::constants::CAP_HTTP,
        &key,
        allowed,
    ));
    allowed
}

// ── the hook ──────────────────────────────────────────────────────────────
//
// One implementation since wasmtime 48, which routes both wasip2 and wasip3
// outgoing requests through a single `WasiHttpHooks::send_request`. Before
// that there were two hooks with two error enums and two body types, and the
// gate had to be written — and kept in step — twice.

impl wasmtime_wasi_http::WasiHttpHooks for PolicyHttpHooks {
    fn send_request(
        &mut self,
        request: http::Request<WasiBody>,
        options: Option<RequestOptions>,
        fut: Box<dyn Future<Output = Result<(), HttpError>> + Send>,
    ) -> Box<
        dyn Future<
                Output = Result<
                    (
                        http::Response<WasiBody>,
                        Box<dyn Future<Output = Result<(), HttpError>> + Send>,
                    ),
                    HttpError,
                >,
            > + Send,
    > {
        // `fut` reports a *response*-processing error back to the guest. The
        // gate has no opinion on one: by the time a response is being consumed
        // the request was already allowed.
        let _ = fut;

        let method = Some(request.method().as_str().to_string());
        let uri = request.uri().clone();
        let decision = self.decide_uri(method.as_deref(), &uri);
        let client = self.client.clone();

        match decision {
            Decision::Allow => {
                tracing::debug!(?method, %uri, "http policy allow");
                Box::new(async move { send(client, request, options).await })
            }
            Decision::Ask => {
                let cache = self.cache.clone();
                let prompter = self.prompter.clone();
                let ask = Self::http_ask(method.as_deref(), &uri);
                let log_uri = uri.clone();
                Box::new(async move {
                    if !resolve_http_ask(cache, prompter, ask).await {
                        tracing::warn!(%log_uri, "http policy ask denied");
                        return Err(HttpError::HttpRequestDenied);
                    }
                    tracing::debug!(%log_uri, "http policy ask allowed");
                    send(client, request, options).await
                })
            }
            Decision::Deny => {
                tracing::warn!(?method, %uri, "{}", deny_reason(method.as_deref(), &uri));
                Box::new(async move { Err(HttpError::HttpRequestDenied) })
            }
        }
    }
}

/// Hand an allowed request to the policy-aware client, in the box-of-futures
/// shape the hook must return.
async fn send(
    client: Arc<ActHttpClient>,
    request: http::Request<WasiBody>,
    options: Option<RequestOptions>,
) -> Result<
    (
        http::Response<WasiBody>,
        Box<dyn Future<Output = Result<(), HttpError>> + Send>,
    ),
    HttpError,
> {
    match client.send(request, options).await {
        Ok((resp, io)) => {
            let io: Box<dyn Future<Output = Result<(), HttpError>> + Send> = Box::new(io);
            Ok((resp, io))
        }
        Err(code) => Err(code),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use act_policy::grant::{CapabilityGrant, PolicyMode};
    use act_policy::provider::CapabilityProvider;
    use act_policy::providers::http::HttpProvider;
    use serde_json::json;

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    /// Build a `PolicyHttpHooks` from a `CapabilityGrant` and declared constraints.
    /// `declared` mirrors what a component would declare in its `act.toml`
    /// (`[std.capabilities."wasi:http"]` allow array).
    fn hooks_from(declared: Vec<serde_json::Value>, grant: CapabilityGrant) -> PolicyHttpHooks {
        // Use the same mode for the http client
        let mode = grant.mode;
        // `resolve` is async (the trait is), but HttpProvider does no I/O in it
        // — drive it to completion on a throwaway runtime so this sync test
        // helper stays sync and its many `#[test]` callers are untouched.
        let ceiling_box = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(HttpProvider.resolve("wasi:http", &declared, &grant))
            .expect("HttpProvider::resolve");
        let ceiling: Arc<dyn act_policy::provider::CompiledCeiling> = Arc::from(ceiling_box);
        let http_cfg = act_policy::grant::HttpConfig {
            mode,
            ..Default::default()
        };
        let client =
            Arc::new(crate::http_client::ActHttpClient::new(http_cfg).expect("client builds"));
        PolicyHttpHooks::new(
            ceiling,
            client,
            Arc::new(act_policy::consent::DenyPrompter),
            Arc::new(act_policy::consent::DecisionCache::new()),
        )
    }

    #[test]
    fn mode_deny_blocks_everything() {
        // Deny mode: no declared cap needed — ceiling hard-denies.
        let h = hooks_from(
            vec![json!({"host": "api.openai.com"})],
            CapabilityGrant {
                mode: PolicyMode::Deny,
                ..Default::default()
            },
        );
        assert_eq!(
            h.decide_uri(Some("GET"), &uri("https://api.openai.com/v1/chat")),
            Decision::Deny
        );
    }

    #[test]
    fn mode_open_allows_everything() {
        // Open mode: declared cap means component is OK with HTTP.
        let h = hooks_from(
            vec![json!({"host": "api.openai.com"})],
            CapabilityGrant {
                mode: PolicyMode::Open,
                ..Default::default()
            },
        );
        assert_eq!(
            h.decide_uri(Some("GET"), &uri("https://api.openai.com/v1/chat")),
            Decision::Allow
        );
    }

    #[test]
    fn ask_mode_is_bounded_by_allow_ceiling() {
        // mode=Ask with a declared ceiling of api.openai.com/https: in-ceiling → Ask,
        // out-of-ceiling → Deny (no prompt).
        let h = hooks_from(
            vec![json!({"host": "api.openai.com", "scheme": "https"})],
            CapabilityGrant {
                mode: PolicyMode::Ask,
                allow: vec![json!({"host": "api.openai.com", "scheme": "https"})],
                ..Default::default()
            },
        );
        assert_eq!(
            h.decide_uri(Some("POST"), &uri("https://api.openai.com/v1/chat")),
            Decision::Ask
        );
        assert_eq!(
            h.decide_uri(Some("GET"), &uri("https://evil.com/")),
            Decision::Deny
        );
    }

    #[test]
    fn ask_mode_deny_rule_beats_ceiling() {
        let h = hooks_from(
            vec![json!({"host": "*.example.com"})],
            CapabilityGrant {
                mode: PolicyMode::Ask,
                allow: vec![json!({"host": "*.example.com"})],
                deny: vec![json!({"host": "admin.example.com"})],
            },
        );
        assert_eq!(
            h.decide_uri(Some("GET"), &uri("https://api.example.com/")),
            Decision::Ask
        );
        assert_eq!(
            h.decide_uri(Some("GET"), &uri("https://admin.example.com/")),
            Decision::Deny
        );
    }

    #[test]
    fn allowlist_host_allow() {
        let h = hooks_from(
            vec![json!({"host": "api.openai.com", "scheme": "https"})],
            CapabilityGrant {
                mode: PolicyMode::Allowlist,
                allow: vec![json!({"host": "api.openai.com", "scheme": "https"})],
                ..Default::default()
            },
        );
        assert_eq!(
            h.decide_uri(Some("POST"), &uri("https://api.openai.com/v1/chat")),
            Decision::Allow
        );
        // Different scheme → deny
        assert_eq!(
            h.decide_uri(Some("GET"), &uri("http://api.openai.com/")),
            Decision::Deny
        );
        // Different host → deny
        assert_eq!(
            h.decide_uri(Some("GET"), &uri("https://evil.com/")),
            Decision::Deny
        );
    }

    #[test]
    fn allowlist_wildcard_host() {
        let h = hooks_from(
            vec![json!({"host": "*.github.com", "scheme": "https"})],
            CapabilityGrant {
                mode: PolicyMode::Allowlist,
                allow: vec![json!({"host": "*.github.com", "scheme": "https"})],
                ..Default::default()
            },
        );
        assert_eq!(
            h.decide_uri(Some("GET"), &uri("https://api.github.com/")),
            Decision::Allow
        );
        assert_eq!(
            h.decide_uri(Some("GET"), &uri("https://github.com/")),
            Decision::Allow
        );
        assert_eq!(
            h.decide_uri(Some("GET"), &uri("https://github.com.evil.com/")),
            Decision::Deny
        );
    }

    #[test]
    fn deny_rule_beats_allow() {
        let h = hooks_from(
            vec![json!({"host": "*.example.com"})],
            CapabilityGrant {
                mode: PolicyMode::Allowlist,
                allow: vec![json!({"host": "*.example.com"})],
                deny: vec![json!({"host": "admin.example.com"})],
            },
        );
        assert_eq!(
            h.decide_uri(Some("GET"), &uri("https://api.example.com/")),
            Decision::Allow
        );
        assert_eq!(
            h.decide_uri(Some("GET"), &uri("https://admin.example.com/")),
            Decision::Deny
        );
    }

    #[test]
    fn method_filter() {
        let h = hooks_from(
            vec![json!({"host": "api.example.com", "methods": ["GET", "POST"]})],
            CapabilityGrant {
                mode: PolicyMode::Allowlist,
                allow: vec![json!({"host": "api.example.com"})],
                ..Default::default()
            },
        );
        assert_eq!(
            h.decide_uri(Some("get"), &uri("https://api.example.com/")),
            Decision::Allow
        );
        assert_eq!(
            h.decide_uri(Some("DELETE"), &uri("https://api.example.com/")),
            Decision::Deny
        );
    }

    #[test]
    fn undeclared_cap_denies_all() {
        // Component didn't declare wasi:http at all → ceiling always Deny.
        let h = hooks_from(
            vec![], // no declared constraints
            CapabilityGrant {
                mode: PolicyMode::Open, // user would allow, but declaration gates it
                ..Default::default()
            },
        );
        assert_eq!(
            h.decide_uri(Some("GET"), &uri("https://example.com/")),
            Decision::Deny
        );
    }

    #[test]
    fn http_key_is_host_colon_port_and_action_is_the_method() {
        let r = crate::audit::CapDecisionRecord::statik(
            act_types::constants::CAP_HTTP,
            "api.example.com:443",
            "GET",
            crate::audit::Decision4::Deny,
            "ask",
            None,
        );
        assert_eq!(r.key, "api.example.com:443");
        assert_eq!(r.action, "GET");
        assert_eq!(r.reason.as_deref(), Some("outside ceiling"));
    }

    #[test]
    fn a_missing_http_method_becomes_an_empty_action() {
        // `decide_uri` takes Option<&str>; the record must not invent a verb.
        let r = crate::audit::CapDecisionRecord::statik(
            act_types::constants::CAP_HTTP,
            "api.example.com:443",
            "",
            crate::audit::Decision4::Allow,
            "allowlist",
            Some("*.example.com".into()),
        );
        assert_eq!(r.action, "");
        assert_eq!(r.rule.as_deref(), Some("*.example.com"));
        assert!(r.reason.is_none());
    }

    /// Drives `send_request`'s `Decision::Ask` arm through the real
    /// `WasiHttpHooks` trait method, the same way `decide_uri` is driven
    /// directly by the tests above, and captures the audit trail through a
    /// real `AuditLayer` rather than the record constructors — so the
    /// assertion is on the actual emission, not on `resolve_http_ask`'s
    /// return value, which would still pass with the `emit_cap_decision`
    /// call inside it deleted.
    ///
    /// This test was written when there were two hooks and the p2 one was
    /// unreached by any fixture (every component driving outbound HTTP goes
    /// through `wasi-fetch`, which imports `wasip3::http::*` exclusively).
    /// wasmtime 48 collapsed both onto one hook, so that gap is gone and
    /// this is now a unit-level companion to `tests/audit_cli.rs`'s
    /// `http_ask_resolution_reaches_the_audit_trail`, which exercises the
    /// same arm end to end through the real binary.
    #[tokio::test(flavor = "current_thread")]
    async fn the_ask_arm_resolves_and_audits_the_denial() {
        use crate::audit::layer::AuditWriter;
        use http_body_util::{BodyExt, Empty};
        use std::sync::Mutex;
        use tracing_subscriber::prelude::*;
        use wasmtime_wasi_http::WasiHttpHooks as _;

        #[derive(Clone, Default)]
        struct CapturingWriter(Arc<Mutex<Vec<String>>>);
        impl AuditWriter for CapturingWriter {
            fn write_line(&self, line: &str) {
                self.0.lock().unwrap().push(line.to_string());
            }
        }

        // Not `hooks_from`: it spins up its own throwaway current-thread
        // runtime via `block_on` to resolve the (actually synchronous)
        // `HttpProvider::resolve`, which is fine from a plain `#[test]` but
        // panics ("Cannot start a runtime from within a runtime") called
        // from inside this test's own `#[tokio::test]` runtime. `.await` it
        // directly instead — we're already in an async context.
        let grant = CapabilityGrant {
            mode: PolicyMode::Ask,
            allow: vec![json!({"host": "api.example.com"})],
            ..Default::default()
        };
        let ceiling_box = act_policy::providers::http::HttpProvider
            .resolve("wasi:http", &[json!({"host": "api.example.com"})], &grant)
            .await
            .expect("HttpProvider::resolve");
        let ceiling: Arc<dyn CompiledCeiling> = Arc::from(ceiling_box);
        let http_cfg = act_policy::grant::HttpConfig {
            mode: grant.mode,
            ..Default::default()
        };
        let client =
            Arc::new(crate::http_client::ActHttpClient::new(http_cfg).expect("client builds"));
        let mut h = PolicyHttpHooks::new(
            ceiling,
            client,
            Arc::new(act_policy::consent::DenyPrompter),
            Arc::new(act_policy::consent::DecisionCache::new()),
        );

        let body: WasiBody = Empty::<bytes::Bytes>::new()
            .map_err(|_| unreachable!())
            .boxed_unsync();
        let request = http::Request::builder()
            .method("GET")
            .uri("https://api.example.com/")
            .body(body)
            .unwrap();
        let options = RequestOptions {
            connect_timeout: Some(std::time::Duration::from_secs(5)),
            first_byte_timeout: Some(std::time::Duration::from_secs(5)),
            between_bytes_timeout: Some(std::time::Duration::from_secs(5)),
        };

        let writer = CapturingWriter::default();
        let sink = writer.0.clone();
        let sub = tracing_subscriber::registry().with(crate::audit::AuditLayer::new(
            writer,
            crate::audit::Detail::Rollup,
        ));
        // A guard, not `with_default`'s closure form: the audit emission
        // happens inside a task spawned via `wasmtime_wasi::runtime::spawn`,
        // driven to completion below by `.await`ing its handle — the guard
        // needs to stay live across that await point. Sound only because
        // this test runs on `flavor = "current_thread"`: `spawn` finds an
        // ambient tokio runtime already current and reuses it rather than
        // its own multi-threaded static one, so the spawned task runs on
        // this same OS thread and observes this thread-local default.
        let _guard = tracing::subscriber::set_default(sub);

        // The hook hands back a boxed future; the consent resolution and the
        // audit emission both happen inside it, so it has to be driven to
        // completion under the guard installed above.
        let resolved =
            std::pin::Pin::from(h.send_request(request, Some(options), Box::new(async { Ok(()) })))
                .await;

        drop(_guard);

        // `hooks_from` wires up `DenyPrompter` (no interactive channel) —
        // every ask degrades to deny deterministically, same as a headless
        // `act call` with stdin closed.
        assert!(
            matches!(resolved, Err(HttpError::HttpRequestDenied)),
            "expected the ask to degrade to a denied response"
        );

        let lines = sink.lock().unwrap().clone();
        let ask_line = lines
            .iter()
            .find(|l| l.contains("ask-deny"))
            .unwrap_or_else(|| panic!("no ask-deny audit line reached the trail, got {lines:?}"));
        assert!(ask_line.contains("wasi:http"), "got {ask_line}");
        assert!(ask_line.contains("denied by user"), "got {ask_line}");
    }
}
