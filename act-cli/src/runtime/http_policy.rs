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

use std::sync::Arc;

use http::Uri;
use wasmtime_wasi::TrappableError;

use act_policy::Decision;
use act_policy::consent::{ConsentAsk, ConsentPrompter, DecisionCache};
use act_policy::provider::{CompiledCeiling, ResourceOp};

type P2ErrorCode = wasmtime_wasi_http::p2::bindings::http::types::ErrorCode;
type P3ErrorCode = wasmtime_wasi_http::p3::bindings::http::types::ErrorCode;

/// Policy hook implementing both `p2::WasiHttpHooks` and `p3::WasiHttpHooks`.
pub struct PolicyHttpHooks {
    ceiling: Arc<dyn CompiledCeiling>,
    client: Arc<crate::runtime::http_client::ActHttpClient>,
    prompter: Arc<dyn ConsentPrompter>,
    cache: Arc<DecisionCache>,
}

impl PolicyHttpHooks {
    pub fn new(
        ceiling: Arc<dyn CompiledCeiling>,
        client: Arc<crate::runtime::http_client::ActHttpClient>,
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

    /// Decide an HTTP request against the ceiling.
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
        match self.ceiling.classify(&op) {
            act_policy::Decision::Allow => Decision::Allow,
            act_policy::Decision::Deny => Decision::Deny,
            act_policy::Decision::Ask => Decision::Ask,
        }
    }
}

fn deny_reason(method: Option<&str>, uri: &Uri) -> String {
    format!("blocked by ACT policy: {} {}", method.unwrap_or("?"), uri)
}

// ── p2 hook ───────────────────────────────────────────────────────────────

impl wasmtime_wasi_http::p2::WasiHttpHooks for PolicyHttpHooks {
    fn send_request(
        &mut self,
        request: hyper::Request<wasmtime_wasi_http::p2::body::HyperOutgoingBody>,
        config: wasmtime_wasi_http::p2::types::OutgoingRequestConfig,
    ) -> wasmtime_wasi_http::p2::HttpResult<wasmtime_wasi_http::p2::types::HostFutureIncomingResponse>
    {
        let method = Some(request.method().as_str());
        let uri = request.uri().clone();
        match self.decide_uri(method, &uri) {
            Decision::Deny => {
                tracing::warn!(?method, %uri, "{}", deny_reason(method, &uri));
                Err(wasmtime_wasi_http::p2::HttpError::from(
                    P2ErrorCode::HttpRequestDenied,
                ))
            }
            Decision::Allow => {
                tracing::debug!(?method, %uri, "http policy allow (p2)");
                let client = self.client.clone();
                let handle = wasmtime_wasi::runtime::spawn(async move {
                    Ok(client.send_p2(request, config).await)
                });
                Ok(wasmtime_wasi_http::p2::types::HostFutureIncomingResponse::pending(handle))
            }
            Decision::Ask => {
                // Resolve interactive consent in the spawned future so the
                // sync hook can return a pending response immediately.
                let client = self.client.clone();
                let cache = self.cache.clone();
                let prompter = self.prompter.clone();
                let ask = Self::http_ask(method, &uri);
                let log_uri = uri.clone();
                let handle = wasmtime_wasi::runtime::spawn(async move {
                    if cache.decide_cached(&*prompter, ask).await {
                        tracing::debug!(%log_uri, "http policy ask allowed (p2)");
                        Ok(client.send_p2(request, config).await)
                    } else {
                        tracing::warn!(%log_uri, "http policy ask denied (p2)");
                        Ok(Err(P2ErrorCode::HttpRequestDenied))
                    }
                });
                Ok(wasmtime_wasi_http::p2::types::HostFutureIncomingResponse::pending(handle))
            }
        }
    }
}

// ── p3 hook ───────────────────────────────────────────────────────────────

impl wasmtime_wasi_http::p3::WasiHttpHooks for PolicyHttpHooks {
    fn send_request(
        &mut self,
        request: http::Request<
            http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, P3ErrorCode>,
        >,
        options: Option<wasmtime_wasi_http::p3::RequestOptions>,
        fut: Box<dyn Future<Output = Result<(), P3ErrorCode>> + Send>,
    ) -> Box<
        dyn Future<
                Output = Result<
                    (
                        http::Response<
                            http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, P3ErrorCode>,
                        >,
                        Box<dyn Future<Output = Result<(), P3ErrorCode>> + Send>,
                    ),
                    TrappableError<P3ErrorCode>,
                >,
            > + Send,
    > {
        let method = Some(request.method().as_str().to_string());
        let uri = request.uri().clone();
        let decision = self.decide_uri(method.as_deref(), &uri);
        match decision {
            Decision::Allow => {
                tracing::debug!(?method, %uri, "http policy allow (p3)");
                let _ = fut;
                let _ = options;
                let client = self.client.clone();
                Box::new(async move {
                    match client.send_p3(request).await {
                        Ok((resp, io)) => {
                            let io: Box<dyn Future<Output = Result<(), P3ErrorCode>> + Send> =
                                Box::new(io);
                            Ok((resp, io))
                        }
                        Err(code) => Err(TrappableError::<P3ErrorCode>::from(code)),
                    }
                })
            }
            Decision::Ask => {
                let _ = fut;
                let _ = options;
                let client = self.client.clone();
                let cache = self.cache.clone();
                let prompter = self.prompter.clone();
                let ask = Self::http_ask(method.as_deref(), &uri);
                let log_uri = uri.clone();
                Box::new(async move {
                    if !cache.decide_cached(&*prompter, ask).await {
                        tracing::warn!(%log_uri, "http policy ask denied (p3)");
                        return Err(TrappableError::<P3ErrorCode>::from(
                            P3ErrorCode::HttpRequestDenied,
                        ));
                    }
                    tracing::debug!(%log_uri, "http policy ask allowed (p3)");
                    match client.send_p3(request).await {
                        Ok((resp, io)) => {
                            let io: Box<dyn Future<Output = Result<(), P3ErrorCode>> + Send> =
                                Box::new(io);
                            Ok((resp, io))
                        }
                        Err(code) => Err(TrappableError::<P3ErrorCode>::from(code)),
                    }
                })
            }
            Decision::Deny => {
                tracing::warn!(?method, %uri, "{}", deny_reason(method.as_deref(), &uri));
                Box::new(async move {
                    Err(TrappableError::<P3ErrorCode>::from(
                        P3ErrorCode::HttpRequestDenied,
                    ))
                })
            }
        }
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
        let ceiling: std::sync::Arc<dyn act_policy::provider::CompiledCeiling> =
            std::sync::Arc::from(ceiling_box);
        let http_cfg = crate::config::HttpConfig {
            mode,
            ..Default::default()
        };
        let client = std::sync::Arc::new(
            crate::runtime::http_client::ActHttpClient::new(http_cfg).expect("client builds"),
        );
        PolicyHttpHooks::new(
            ceiling,
            client,
            std::sync::Arc::new(act_policy::consent::DenyPrompter),
            std::sync::Arc::new(act_policy::consent::DecisionCache::new()),
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
}
