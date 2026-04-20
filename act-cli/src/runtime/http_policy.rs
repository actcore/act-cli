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
//! - **DNS-resolved IPs against deny CIDRs**: checked in a pre-flight
//!   `lookup_host` before the default handler runs. Catches
//!   SSRF-by-name ("fetch internal.example.com" where it resolves to a
//!   10.x host). This is a second DNS lookup per request (the default
//!   handler does its own `TcpStream::connect(authority)` which resolves
//!   again); the OS resolver cache usually makes the second lookup a
//!   no-op. There's a narrow TOCTOU window where a racing resolver
//!   could return a different IP between our check and the handler's
//!   connect — full DNS-rebinding defence requires forking the default
//!   handler to accept a pre-resolved `SocketAddr`, which is deferred.
//! - Allow-CIDR rules against DNS-resolved IPs: NOT IMPLEMENTED. Allow
//!   CIDRs still require an IP literal in the URI. Deny CIDRs are the
//!   security-critical direction.
//! - Redirect re-decision: deferred (wasi-http follows redirects inside
//!   `default_send_request`; we'd need to disable that and resubmit).

use std::sync::Arc;

use http::Uri;
use wasmtime_wasi::TrappableError;

use crate::config::{HttpConfig, PolicyMode};
use crate::runtime::network::{self, Decision, NetworkCheck};

type P2ErrorCode = wasmtime_wasi_http::p2::bindings::http::types::ErrorCode;
type P3ErrorCode = wasmtime_wasi_http::p3::bindings::http::types::ErrorCode;

/// Policy hook implementing both `p2::WasiHttpHooks` and `p3::WasiHttpHooks`.
pub struct PolicyHttpHooks {
    config: Arc<HttpConfig>,
    client: Arc<crate::runtime::http_client::ActHttpClient>,
}

impl PolicyHttpHooks {
    pub fn new(
        config: HttpConfig,
        client: Arc<crate::runtime::http_client::ActHttpClient>,
    ) -> Self {
        Self {
            config: Arc::new(config),
            client,
        }
    }

    /// Decide an HTTP request against the config. Scheme / method checks are
    /// HTTP-layer; the host / port / CIDR parts are delegated to
    /// `runtime::network::decide`.
    fn decide_uri(&self, method: Option<&str>, uri: &Uri) -> Decision {
        match self.config.mode {
            PolicyMode::Deny => return Decision::Deny,
            PolicyMode::Open => return Decision::Allow,
            PolicyMode::Allowlist => {}
        }

        let host = uri.host().unwrap_or("");
        let scheme = uri.scheme_str();
        let port = uri
            .port_u16()
            .unwrap_or(if scheme == Some("https") { 443 } else { 80 });
        let check = NetworkCheck::new(host, port);

        if self
            .config
            .deny
            .iter()
            .any(|r| http_rule_matches(r, scheme, method, &check))
        {
            return Decision::Deny;
        }
        if self
            .config
            .allow
            .iter()
            .any(|r| http_rule_matches(r, scheme, method, &check))
        {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }
}

/// HTTP-layer rule match: check scheme / method first (the HTTP-only
/// dimensions), then delegate the host / port / CIDR parts to the
/// network-level matcher.
fn http_rule_matches(
    rule: &crate::config::HttpRule,
    scheme: Option<&str>,
    method: Option<&str>,
    check: &NetworkCheck,
) -> bool {
    if let Some(want) = rule.scheme.as_deref() {
        match scheme {
            Some(have) if have.eq_ignore_ascii_case(want) => {}
            _ => return false,
        }
    }
    if let Some(want_methods) = rule.methods.as_deref() {
        let Some(have) = method else {
            return false;
        };
        if !want_methods.iter().any(|m| m.eq_ignore_ascii_case(have)) {
            return false;
        }
    }
    network::rule_matches(&rule.net, check)
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
        _options: Option<wasmtime_wasi_http::p3::RequestOptions>,
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
    use crate::config::{HttpConfig, HttpRule, PolicyMode};
    use crate::runtime::network::NetworkRule;

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    fn hooks(cfg: HttpConfig) -> PolicyHttpHooks {
        let client = std::sync::Arc::new(
            crate::runtime::http_client::ActHttpClient::new(cfg.clone()).expect("client builds"),
        );
        PolicyHttpHooks::new(cfg, client)
    }

    fn rule(
        host: Option<&str>,
        scheme: Option<&str>,
        ports: Option<Vec<u16>>,
        cidr: Option<&str>,
        except_ports: Option<Vec<u16>>,
    ) -> HttpRule {
        HttpRule {
            net: NetworkRule {
                host: host.map(String::from),
                ports,
                cidr: cidr.map(String::from),
                except_ports,
            },
            scheme: scheme.map(String::from),
            methods: None,
        }
    }

    #[test]
    fn mode_deny_blocks_everything() {
        let h = hooks(HttpConfig {
            mode: PolicyMode::Deny,
            ..Default::default()
        });
        assert_eq!(
            h.decide_uri(Some("GET"), &uri("https://api.openai.com/v1/chat")),
            Decision::Deny
        );
    }

    #[test]
    fn mode_open_allows_everything() {
        let h = hooks(HttpConfig {
            mode: PolicyMode::Open,
            ..Default::default()
        });
        assert_eq!(
            h.decide_uri(Some("GET"), &uri("https://api.openai.com/v1/chat")),
            Decision::Allow
        );
    }

    #[test]
    fn allowlist_host_allow() {
        let h = hooks(HttpConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![rule(
                Some("api.openai.com"),
                Some("https"),
                None,
                None,
                None,
            )],
            ..Default::default()
        });
        assert_eq!(
            h.decide_uri(Some("POST"), &uri("https://api.openai.com/v1/chat")),
            Decision::Allow
        );
        assert_eq!(
            h.decide_uri(Some("GET"), &uri("http://api.openai.com/")),
            Decision::Deny
        );
        assert_eq!(
            h.decide_uri(Some("GET"), &uri("https://evil.com/")),
            Decision::Deny
        );
    }

    #[test]
    fn allowlist_wildcard_host() {
        let h = hooks(HttpConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![rule(Some("*.github.com"), Some("https"), None, None, None)],
            ..Default::default()
        });
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
        let h = hooks(HttpConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![rule(Some("*.example.com"), None, None, None, None)],
            deny: vec![rule(Some("admin.example.com"), None, None, None, None)],
            ..Default::default()
        });
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
    fn cidr_deny_with_except_port() {
        let h = hooks(HttpConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![rule(Some("localhost"), None, None, None, None)],
            deny: vec![rule(
                None,
                None,
                None,
                Some("127.0.0.0/8"),
                Some(vec![3000]),
            )],
            ..Default::default()
        });
        // 127.0.0.1:80 is in the deny CIDR and not in except-ports → deny
        assert_eq!(
            h.decide_uri(Some("GET"), &uri("http://127.0.0.1/")),
            Decision::Deny
        );
        // 127.0.0.1:3000 is in except-ports → deny rule doesn't match. Allow
        // rule matches localhost literal? No, host is "127.0.0.1", not
        // "localhost". So decision is Deny for not matching any allow.
        assert_eq!(
            h.decide_uri(Some("GET"), &uri("http://127.0.0.1:3000/")),
            Decision::Deny
        );
    }

    #[test]
    fn method_filter() {
        let h = hooks(HttpConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![HttpRule {
                net: NetworkRule {
                    host: Some("api.example.com".into()),
                    ..Default::default()
                },
                methods: Some(vec!["GET".into(), "POST".into()]),
                ..Default::default()
            }],
            ..Default::default()
        });
        assert_eq!(
            h.decide_uri(Some("get"), &uri("https://api.example.com/")),
            Decision::Allow
        );
        assert_eq!(
            h.decide_uri(Some("DELETE"), &uri("https://api.example.com/")),
            Decision::Deny
        );
    }
}
