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

use std::net::IpAddr;
use std::sync::Arc;

use http::Uri;
use wasmtime_wasi::TrappableError;

use crate::config::{HttpConfig, HttpRule, PolicyMode};
use crate::runtime::network::{cidr_contains, host_matches};

type P2ErrorCode = wasmtime_wasi_http::p2::bindings::http::types::ErrorCode;
type P3ErrorCode = wasmtime_wasi_http::p3::bindings::http::types::ErrorCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    Allow,
    Deny,
}

/// Policy hook implementing both `p2::WasiHttpHooks` and `p3::WasiHttpHooks`.
pub struct PolicyHttpHooks {
    config: Arc<HttpConfig>,
}

impl PolicyHttpHooks {
    pub fn new(config: HttpConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    fn decide_uri(&self, method: Option<&str>, uri: &Uri) -> Decision {
        match self.config.mode {
            PolicyMode::Deny => Decision::Deny,
            PolicyMode::Open => Decision::Allow,
            PolicyMode::Allowlist => {
                // Deny rules short-circuit even on allowlist.
                if self
                    .config
                    .deny
                    .iter()
                    .any(|r| rule_matches(r, method, uri))
                {
                    return Decision::Deny;
                }
                if self
                    .config
                    .allow
                    .iter()
                    .any(|r| rule_matches(r, method, uri))
                {
                    Decision::Allow
                } else {
                    Decision::Deny
                }
            }
        }
    }
}

fn rule_matches(rule: &HttpRule, method: Option<&str>, uri: &Uri) -> bool {
    if let Some(ref want_scheme) = rule.scheme
        && uri.scheme_str() != Some(want_scheme.as_str())
    {
        return false;
    }
    if let Some(ref want_methods) = rule.methods
        && let Some(m) = method
        && !want_methods.iter().any(|wm| wm.eq_ignore_ascii_case(m))
    {
        return false;
    }
    let host = uri.host().unwrap_or("");
    let port = uri.port_u16();

    if let Some(ref cidr) = rule.cidr {
        let Some(ip) = host.parse::<IpAddr>().ok() else {
            return false;
        };
        if !cidr_contains(cidr, ip) {
            return false;
        }
        if let Some(except) = &rule.except_ports
            && let Some(p) = port
            && except.contains(&p)
        {
            return false;
        }
        // cidr matched; port check below
    } else if let Some(ref want_host) = rule.host {
        if !host_matches(want_host, host) {
            return false;
        }
    } else {
        // No host and no cidr — useless rule; never matches.
        return false;
    }

    if let Some(ref want_ports) = rule.ports {
        let Some(p) = port else { return false };
        if !want_ports.contains(&p) {
            return false;
        }
    }

    true
}

fn deny_reason(method: Option<&str>, uri: &Uri) -> String {
    format!("blocked by ACT policy: {} {}", method.unwrap_or("?"), uri)
}

/// Returns `true` if an IP address (typically the DNS-resolved peer of an
/// outgoing HTTP request) should be refused at connect time. This closes the
/// SSRF-by-DNS-trickery case: `deny = [{ cidr = "10.0.0.0/8" }]` catches
/// `http://internal.example.com/` when it resolves to a 10.x host, even
/// though the URI host is a name, not an IP.
///
/// Only deny rules are applied here. Allow-CIDR semantics still go through
/// the HTTP-layer matcher (URI must have an IP literal). That's an
/// asymmetry — deny is the security-relevant direction.
pub fn is_ip_denied_by_cidr(cfg: &HttpConfig, ip: std::net::IpAddr, port: u16) -> bool {
    if matches!(cfg.mode, PolicyMode::Open) {
        return false;
    }
    cfg.deny.iter().any(|rule| {
        let Some(ref spec) = rule.cidr else {
            return false;
        };
        if !cidr_contains(spec, ip) {
            return false;
        }
        if let Some(except) = &rule.except_ports
            && except.contains(&port)
        {
            return false;
        }
        true
    })
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
                let cfg = self.config.clone();
                let use_tls = config.use_tls;
                let handle = wasmtime_wasi::runtime::spawn(async move {
                    // DNS + CIDR check before handing off to the default
                    // handler. Catches SSRF-by-name (host resolves into a
                    // deny CIDR) and pins the decision to the resolved IP:
                    // if DNS flips between here and the handler's own
                    // connect, worst case is a second resolution that
                    // mis-steers — we've still blocked the original
                    // resolved target.
                    if cidr_precheck(&cfg, request.uri(), use_tls).await.is_err() {
                        return Ok(Err(P2ErrorCode::HttpRequestDenied));
                    }
                    Ok(wasmtime_wasi_http::p2::default_send_request_handler(request, config).await)
                });
                Ok(wasmtime_wasi_http::p2::types::HostFutureIncomingResponse::pending(handle))
            }
        }
    }
}

/// Resolve the request's authority to one or more socket addresses and
/// check each against configured deny CIDRs. Returns `Err(())` on any deny
/// hit; callers map to their p2/p3 `HttpRequestDenied` error variant.
/// `Ok(())` on no CIDR deny rules at all, missing authority, DNS lookup
/// failure (let the downstream handler surface that with its own
/// diagnostics), or no matching rule.
async fn cidr_precheck(cfg: &HttpConfig, uri: &Uri, use_tls: bool) -> Result<(), ()> {
    if cfg.deny.iter().all(|r| r.cidr.is_none()) {
        return Ok(());
    }
    let Some(authority) = uri.authority() else {
        return Ok(());
    };
    let host = authority.host();
    let port = authority
        .port_u16()
        .unwrap_or(if use_tls { 443 } else { 80 });
    let lookup_target = format!("{host}:{port}");
    match tokio::net::lookup_host(&lookup_target).await {
        Ok(addrs) => {
            for addr in addrs {
                if is_ip_denied_by_cidr(cfg, addr.ip(), addr.port()) {
                    tracing::warn!(%addr, uri = %uri, "http policy: connect blocked by deny CIDR");
                    return Err(());
                }
            }
            Ok(())
        }
        Err(e) => {
            tracing::debug!(%e, uri = %uri, "http policy: DNS precheck lookup failed; deferring to handler");
            Ok(())
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
                let cfg = self.config.clone();
                // p3 doesn't expose `use_tls` in RequestOptions; infer from
                // the URI scheme (the default handler does the same).
                let use_tls = uri.scheme_str() == Some("https");
                Box::new(async move {
                    use http_body_util::BodyExt;
                    // DNS + CIDR deny precheck mirrors the p2 path. Closes
                    // SSRF-by-name for wasip3 HTTP clients (e.g. wasi-fetch).
                    if cidr_precheck(&cfg, &uri, use_tls).await.is_err() {
                        return Err(TrappableError::<P3ErrorCode>::from(
                            P3ErrorCode::HttpRequestDenied,
                        ));
                    }
                    let (res, io) = wasmtime_wasi_http::p3::default_send_request(request, options)
                        .await
                        .map_err(TrappableError::<P3ErrorCode>::from)?;
                    let io: Box<dyn Future<Output = Result<(), P3ErrorCode>> + Send> = Box::new(io);
                    Ok((res.map(BodyExt::boxed_unsync), io))
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

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    fn hooks(cfg: HttpConfig) -> PolicyHttpHooks {
        PolicyHttpHooks::new(cfg)
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
            allow: vec![HttpRule {
                host: Some("api.openai.com".into()),
                scheme: Some("https".into()),
                ..Default::default()
            }],
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
            allow: vec![HttpRule {
                host: Some("*.github.com".into()),
                scheme: Some("https".into()),
                ..Default::default()
            }],
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
            allow: vec![HttpRule {
                host: Some("*.example.com".into()),
                ..Default::default()
            }],
            deny: vec![HttpRule {
                host: Some("admin.example.com".into()),
                ..Default::default()
            }],
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
            allow: vec![HttpRule {
                host: Some("localhost".into()),
                ..Default::default()
            }],
            deny: vec![HttpRule {
                cidr: Some("127.0.0.0/8".into()),
                except_ports: Some(vec![3000]),
                ..Default::default()
            }],
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
    fn ip_denied_by_cidr_matches_resolved_ip() {
        let cfg = HttpConfig {
            mode: PolicyMode::Allowlist,
            deny: vec![HttpRule {
                cidr: Some("10.0.0.0/8".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        // Any resolved IP under 10/8 is denied regardless of original URI host.
        assert!(is_ip_denied_by_cidr(&cfg, "10.1.2.3".parse().unwrap(), 443));
        assert!(!is_ip_denied_by_cidr(&cfg, "8.8.8.8".parse().unwrap(), 443));
    }

    #[test]
    fn ip_denied_by_cidr_respects_except_ports() {
        let cfg = HttpConfig {
            mode: PolicyMode::Allowlist,
            deny: vec![HttpRule {
                cidr: Some("127.0.0.0/8".into()),
                except_ports: Some(vec![3000]),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(is_ip_denied_by_cidr(&cfg, "127.0.0.1".parse().unwrap(), 80));
        assert!(!is_ip_denied_by_cidr(
            &cfg,
            "127.0.0.1".parse().unwrap(),
            3000
        ));
    }

    #[test]
    fn ip_denied_by_cidr_is_noop_for_open_mode() {
        let cfg = HttpConfig {
            mode: PolicyMode::Open,
            deny: vec![HttpRule {
                cidr: Some("10.0.0.0/8".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(!is_ip_denied_by_cidr(
            &cfg,
            "10.1.2.3".parse().unwrap(),
            443
        ));
    }

    #[test]
    fn method_filter() {
        let h = hooks(HttpConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![HttpRule {
                host: Some("api.example.com".into()),
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
