//! Layer 1 phase C2: per-request HTTP policy hook.
//!
//! Intercepts `wasi:http/outgoing-handler` via `WasiHttpHooks::send_request`
//! (both p2 and p3). Checks each outgoing request against the resolved
//! `HttpConfig` and either delegates to the default handler or returns
//! `ErrorCode::HttpRequestDenied`. Deny-by-default for `allowlist` mode;
//! `open` allows every request; `deny` blocks every request.
//!
//! Phase C2 scope:
//! - Host matching: literal host, exact match or `*.suffix` wildcard.
//! - Scheme / methods / ports matching.
//! - IP literals matched against `cidr` entries.
//! - DNS-resolved IPs against `cidr`: NOT IMPLEMENTED YET (requires
//!   intercepting the connect call; deferred to Phase D).
//! - Redirect re-decision: deferred (wasi-http follows redirects inside
//!   `default_send_request`; we'd need to disable that and resubmit).

use std::net::IpAddr;
use std::sync::Arc;

use http::Uri;
use wasmtime_wasi::TrappableError;

use crate::config::{HttpConfig, HttpRule, PolicyMode};

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

fn host_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host == suffix || host.ends_with(&format!(".{}", suffix));
    }
    host.eq_ignore_ascii_case(pattern)
}

fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    let Some((net, prefix_s)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix_s.parse::<u8>() else {
        return false;
    };
    match (net.parse::<IpAddr>(), ip) {
        (Ok(IpAddr::V4(n)), IpAddr::V4(h)) => {
            if prefix > 32 {
                return false;
            }
            let mask: u32 = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(n) & mask) == (u32::from(h) & mask)
        }
        (Ok(IpAddr::V6(n)), IpAddr::V6(h)) => {
            if prefix > 128 {
                return false;
            }
            let n = u128::from(n);
            let h = u128::from(h);
            let mask: u128 = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (n & mask) == (h & mask)
        }
        _ => false,
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
            Decision::Allow => {
                tracing::debug!(?method, %uri, "http policy allow (p2)");
                Ok(wasmtime_wasi_http::p2::default_send_request(
                    request, config,
                ))
            }
            Decision::Deny => {
                tracing::warn!(?method, %uri, "{}", deny_reason(method, &uri));
                Err(wasmtime_wasi_http::p2::HttpError::from(
                    P2ErrorCode::HttpRequestDenied,
                ))
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
                Box::new(async move {
                    use http_body_util::BodyExt;
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
    fn host_matches_exact_and_wildcard() {
        assert!(host_matches("api.example.com", "api.example.com"));
        assert!(!host_matches("api.example.com", "api2.example.com"));
        assert!(host_matches("*.example.com", "api.example.com"));
        assert!(host_matches("*.example.com", "example.com"));
        assert!(!host_matches("*.example.com", "api.other.com"));
    }

    #[test]
    fn cidr_contains_basic() {
        assert!(cidr_contains("10.0.0.0/8", "10.1.2.3".parse().unwrap()));
        assert!(!cidr_contains("10.0.0.0/8", "11.0.0.0".parse().unwrap()));
        assert!(cidr_contains("127.0.0.0/8", "127.1.2.3".parse().unwrap()));
        assert!(cidr_contains("0.0.0.0/0", "8.8.8.8".parse().unwrap()));
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
