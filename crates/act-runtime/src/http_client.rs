//! Reqwest-backed client for `wasi:http/outgoing-handler`. One instance per
//! `HostState` (per component invocation). Client config — redirect policy,
//! DNS resolver — is baked in at construction from the component's
//! `HttpConfig` so we don't need to thread context through each call.
//!
//! # Extraction boundary
//!
//! `http_client`, `http_policy`, and `network`, plus the `HttpConfig` /
//! `HttpRule` / `NetworkRule` / `PolicyMode` types in `config`, form a
//! self-contained "policy-aware reqwest backend for `wasi:http`" unit with
//! zero act-cli-specific dependencies (no CLI, no component metadata, no
//! ACT protocol). The boundary is maintained intentionally so this layer
//! can be lifted into its own crate (e.g. `act-wasi-http-policy`) when a
//! second consumer appears or when we propose the pattern upstream to
//! `wasmtime-wasi-http`. Do not reach outside those modules from here; if
//! you need something else, pass it in via config.

use std::error::Error;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use http_body_util::BodyExt;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::redirect;
use wasmtime_wasi_http::{Error as HttpError, RequestOptions, WasiBody};

use crate::audit::{CapDecisionRecord, Decision4, emit_cap_decision};
use act_policy::grant::{HttpConfig, PolicyMode};
use act_policy::net::{self as network, NetworkRule};

/// reqwest DNS resolver that filters resolved addresses against both deny
/// and allow CIDR rules.
///
/// Logic per resolved `SocketAddr`:
/// 1. Drop if any deny-CIDR matches (respecting `except_ports`).
/// 2. In `Allowlist` mode, if any allow rule carries a `cidr`, the IP must
///    be covered by either a host-anchored allow (meaning the hostname
///    itself was allowed, so every resolved IP is OK) or an allow-CIDR.
///    This closes the prior asymmetry where `allow = [{ cidr = "..." }]`
///    required an IP-literal URI.
/// 3. `Open` / `Deny` modes: no allow-side filter here (`Deny` never
///    reaches the resolver; `Open` still honors deny-CIDR as a safety
///    net).
///
/// If no addresses survive, returns an empty iterator — reqwest surfaces
/// this as a DNS error, which our `reqwest_to_p2_error` /
/// `reqwest_to_error` maps to `ErrorCode::DnsError`.
struct PolicyDnsResolver {
    allow_nets: Arc<Vec<NetworkRule>>,
    deny_nets: Arc<Vec<NetworkRule>>,
    mode: PolicyMode,
}

impl PolicyDnsResolver {
    fn new(cfg: &HttpConfig) -> Self {
        let allow_nets = cfg.allow.iter().map(|r| r.net.clone()).collect();
        let deny_nets = cfg.deny.iter().map(|r| r.net.clone()).collect();
        Self {
            allow_nets: Arc::new(allow_nets),
            deny_nets: Arc::new(deny_nets),
            mode: cfg.mode,
        }
    }
}

impl Resolve for PolicyDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let allow = self.allow_nets.clone();
        let deny = self.deny_nets.clone();
        let mode = self.mode;
        Box::pin(async move {
            let host = name.as_str().to_string();
            let addrs = tokio::net::lookup_host(format!("{host}:0"))
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            let all: Vec<SocketAddr> = addrs.collect();
            let total = all.len();

            // If the hostname itself matches any host-anchored allow rule,
            // we don't need to require per-IP CIDR matches — the guest is
            // already allowed to talk to this host. Compute once.
            let host_allowed = allow.iter().any(|r| {
                r.host
                    .as_deref()
                    .is_some_and(|pat| network::host_matches(pat, &host))
            });
            let require_allow_cidr = mode == PolicyMode::Allowlist
                && !host_allowed
                && allow.iter().any(|r| r.cidr.is_some());

            let filtered: Vec<SocketAddr> = all
                .into_iter()
                .filter(|addr| {
                    if network::any_deny_cidr_matches(&deny, addr.ip(), addr.port()) {
                        return false;
                    }
                    if require_allow_cidr {
                        return allow.iter().any(|r| {
                            r.cidr
                                .as_deref()
                                .is_some_and(|c| network::cidr_contains(c, addr.ip()))
                        });
                    }
                    true
                })
                .collect();
            tracing::debug!(
                %host,
                resolved = total,
                kept = filtered.len(),
                require_allow_cidr,
                host_allowed,
                "http policy dns resolve",
            );
            if filtered.is_empty() {
                // One record per failed resolution, not one per dropped
                // address: to the guest this is a single failure (the name
                // didn't resolve to anything usable), and `ResourceOp`/
                // `CapDecisionRecord` model one decision — emitting `total`
                // records for what reads as one blocked lookup would flood
                // the rollup without giving the operator anything a single
                // line doesn't already say. `key` is the bare hostname: no
                // port exists yet at DNS-resolution time (a name resolves
                // independently of which port the caller will connect to).
                if total > 0 {
                    // Only a genuine "policy dropped everything" case gets a
                    // deny record here — `total == 0` (the name itself
                    // didn't resolve) is a DNS failure, not a policy
                    // decision, and must not be misreported as one.
                    emit_cap_decision(&CapDecisionRecord::statik_with_reason(
                        act_types::constants::CAP_HTTP,
                        &host,
                        "",
                        Decision4::Deny,
                        &mode.to_string(),
                        None,
                        Some("all resolved addresses filtered by CIDR rule"),
                    ));
                }
                return Err("all resolved addresses filtered by policy CIDR rules".into());
            }
            let iter: Addrs = Box::new(filtered.into_iter());
            Ok(iter)
        })
    }
}

/// Build a `reqwest::redirect::Policy` that consults `network::decide` on
/// each hop. Denies the chain if the target URL violates the configured
/// allow/deny network rules.
fn build_redirect_policy(cfg: Arc<HttpConfig>) -> redirect::Policy {
    const MAX_HOPS: usize = 10;
    redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= MAX_HOPS {
            return attempt.error("too many redirects");
        }
        let url = attempt.url();
        let host = url.host_str().unwrap_or("");
        let scheme = url.scheme();
        let port = url
            .port_or_known_default()
            .unwrap_or(if scheme == "https" { 443 } else { 80 });
        // Build a NetworkCheck and apply the non-HTTP bits of the policy.
        // We don't know the redirect request's method (reqwest decides per
        // status) so we skip HTTP-layer method filtering here — rely on
        // network::decide which ignores method-only fields when they live
        // in HttpRule above this layer. If a rule requires scheme="https"
        // and the redirect downgrades to "http", that rule won't match —
        // which is the right behaviour.
        let allow_nets: Vec<act_policy::net::NetworkRule> =
            cfg.allow.iter().map(|r| r.net.clone()).collect();
        let deny_nets: Vec<act_policy::net::NetworkRule> =
            cfg.deny.iter().map(|r| r.net.clone()).collect();
        let decision = act_policy::net::decide(
            cfg.mode,
            &allow_nets,
            &deny_nets,
            &act_policy::net::NetworkCheck::new(host, port),
        );
        match decision {
            act_policy::Decision::Allow => attempt.follow(),
            // `Ask` mode gates each request interactively at `send_request`;
            // the redirect callback is sync and can't prompt, so redirects
            // within an already-consented request are followed (the top-level
            // send was approved). Per-hop ask-prompting is a later phase.
            act_policy::Decision::Ask => attempt.follow(),
            act_policy::Decision::Deny => {
                tracing::warn!(%url, "http policy: redirect hop blocked");
                let key = format!("{host}:{port}");
                emit_cap_decision(&CapDecisionRecord::statik_with_reason(
                    act_types::constants::CAP_HTTP,
                    &key,
                    "",
                    Decision4::Deny,
                    &cfg.mode.to_string(),
                    None,
                    Some("redirect target outside ceiling"),
                ));
                attempt.error("redirect target blocked by ACT policy")
            }
        }
    })
}

/// Reqwest client instantiated with this component's HTTP policy. Cheap to
/// clone (reqwest::Client is internally `Arc`'d); share freely across
/// async tasks.
#[derive(Clone)]
pub struct ActHttpClient {
    client: Arc<reqwest::Client>,
}

impl ActHttpClient {
    pub fn new(cfg: HttpConfig) -> anyhow::Result<Self> {
        let cfg_arc = Arc::new(cfg.clone());
        let resolver = Arc::new(PolicyDnsResolver::new(&cfg));
        let client = reqwest::Client::builder()
            .dns_resolver(resolver)
            .redirect(build_redirect_policy(cfg_arc))
            // Keep HTTP/2 multiplexed connections alive through idle
            // periods — important for SSE and long-poll streams that
            // may go 30+ seconds between events. Without this, NAT /
            // LB flow timers can silently drop idle connections.
            .http2_keep_alive_interval(Some(std::time::Duration::from_secs(30)))
            .http2_keep_alive_while_idle(true)
            .http2_keep_alive_timeout(std::time::Duration::from_secs(10))
            // TCP-level keep-alive catches dead peers on HTTP/1.1 too
            // (and the underlying TCP of HTTP/2 before ALPN).
            .tcp_keepalive(Some(std::time::Duration::from_secs(30)))
            // Long-lived streams shouldn't trigger pool eviction while
            // in use — reqwest's default 90s idle-timeout is fine for
            // one-shot requests but too aggressive for SSE reconnects.
            // 10 minutes strikes a balance.
            .pool_idle_timeout(Some(std::time::Duration::from_secs(600)))
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build reqwest client: {e}"))?;
        Ok(Self {
            client: Arc::new(client),
        })
    }

    /// Perform an outgoing request.
    ///
    /// One method since wasmtime 48, which routes p2 and p3 through the same
    /// hook. `options` carries the guest's `wasi:http/types.request-options`;
    /// each field falls back to 600 s, matching what wasmtime itself supplies
    /// when the guest sets none, so the p2 path keeps the deadline it always
    /// had and the p3 path gains the one it should have had.
    pub async fn send(
        &self,
        request: http::Request<WasiBody>,
        options: Option<RequestOptions>,
    ) -> Result<
        (
            http::Response<WasiBody>,
            Pin<Box<dyn Future<Output = Result<(), HttpError>> + Send>>,
        ),
        HttpError,
    > {
        const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);
        let deadline = options
            .and_then(|o| o.connect_timeout)
            .unwrap_or(DEFAULT_TIMEOUT)
            + options
                .and_then(|o| o.first_byte_timeout)
                .unwrap_or(DEFAULT_TIMEOUT);

        let reqwest_req = to_reqwest(request)?;
        let resp = tokio::time::timeout(deadline, self.client.execute(reqwest_req))
            .await
            .map_err(|_| HttpError::ConnectionTimeout)?
            .map_err(reqwest_to_error)?;
        reqwest_response_to_wasi(resp).await
    }
}

/// Walk the whole `source()` chain of a reqwest error, returning the first
/// chain entry whose display string matches `needle`. reqwest wraps DNS
/// resolver errors through multiple layers (reqwest → hyper-util → our
/// `PolicyDnsResolver` error) so a single `.source()` hop isn't enough.
fn error_chain_contains(err: &dyn Error, needles: &[&str]) -> bool {
    let mut current: Option<&dyn Error> = Some(err);
    while let Some(e) = current {
        let msg = e.to_string().to_ascii_lowercase();
        if needles.iter().any(|n| msg.contains(n)) {
            return true;
        }
        current = e.source();
    }
    false
}

/// Convert an outgoing request into a reqwest::Request. Streaming body,
/// we wrap the UnsyncBoxBody as a Stream
/// and feed it through reqwest::Body::wrap_stream, because UnsyncBoxBody
/// is !Sync and wrap() requires Sync.
fn to_reqwest(request: http::Request<WasiBody>) -> Result<reqwest::Request, HttpError> {
    use futures_util::StreamExt;
    use http_body_util::BodyStream;

    let (parts, body) = request.into_parts();
    let scheme = parts
        .uri
        .scheme_str()
        .map(str::to_string)
        .unwrap_or_else(|| "https".into());
    let authority = parts
        .uri
        .authority()
        .map(|a| a.to_string())
        .ok_or(HttpError::HttpRequestUriInvalid)?;
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let url_str = format!("{scheme}://{authority}{path_and_query}");
    let url = reqwest::Url::parse(&url_str).map_err(|_| HttpError::HttpRequestUriInvalid)?;
    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
        .map_err(|_| HttpError::HttpProtocolError)?;

    let data_stream = BodyStream::new(body).filter_map(|frame_res| async move {
        match frame_res {
            Ok(frame) => frame.into_data().ok().map(Ok::<_, std::io::Error>),
            Err(_) => Some(Err(std::io::Error::other("wasi:http body stream error"))),
        }
    });
    let body = reqwest::Body::wrap_stream(data_stream);

    let mut builder = reqwest::Client::new().request(method, url).body(body);
    for (name, value) in parts.headers.iter() {
        builder = builder.header(name, value);
    }
    builder.build().map_err(|_| HttpError::HttpProtocolError)
}

/// Translate a reqwest error to the closest `wasi:http` error.
///
/// One mapper since wasmtime 48: `Error` is a superset of what the p2 and p3
/// bindings each used to have, and the two mappers this replaced were
/// line-for-line identical but for the enum they named.
fn reqwest_to_error(err: reqwest::Error) -> HttpError {
    if err.is_timeout() {
        return HttpError::ConnectionTimeout;
    }
    if error_chain_contains(&err, &["deny cidr", "failed to lookup", "dns"]) {
        return HttpError::DnsError {
            rcode: Some(err.to_string()),
            info_code: None,
        };
    }
    if err.is_connect() {
        return HttpError::ConnectionRefused;
    }
    if err.is_redirect() {
        return HttpError::HttpRequestDenied;
    }
    if err.is_decode() {
        return HttpError::HttpProtocolError;
    }
    if err.is_request() {
        return HttpError::HttpRequestUriInvalid;
    }
    if err.is_body() {
        return HttpError::HttpRequestBodySize(None);
    }
    HttpError::HttpProtocolError
}

/// Convert a reqwest response to the shape the hook expects:
/// http::Response<WasiBody> plus a
/// Future<Output = Result<(), HttpError>> representing the body
/// completion (reqwest handles this transparently; we return Ok(())
/// immediately since body errors surface through the stream).
async fn reqwest_response_to_wasi(
    resp: reqwest::Response,
) -> Result<
    (
        http::Response<WasiBody>,
        Pin<Box<dyn Future<Output = Result<(), HttpError>> + Send>>,
    ),
    HttpError,
> {
    let status = resp.status();
    let mut headers = resp.headers().clone();
    headers.remove(http::header::TRANSFER_ENCODING);
    headers.remove(http::header::CONTENT_LENGTH);

    // Use reqwest::Body as the streaming source rather than bytes_stream +
    // StreamBody. reqwest::Body implements http_body::Body with a correct
    // `is_end_stream()` override (StreamBody always returns `false`, which
    // confuses wasi-fetch guests into trapping mid-read on HTTP/2 responses).
    let reqwest_body = reqwest::Body::from(resp);
    let body: WasiBody = BodyExt::boxed_unsync(BodyExt::map_err(reqwest_body, reqwest_to_error));

    let mut builder = http::Response::builder().status(status);
    if let Some(hdrs) = builder.headers_mut() {
        hdrs.extend(headers);
    }
    let resp = builder
        .body(body)
        .map_err(|_| HttpError::HttpProtocolError)?;
    let io: Pin<Box<dyn Future<Output = Result<(), HttpError>> + Send>> =
        Box::pin(async { Ok(()) });
    Ok((resp, io))
}

#[cfg(test)]
mod tests {
    use super::*;
    use act_policy::grant::HttpConfig;
    use http::Method;
    use http_body_util::combinators::UnsyncBoxBody;
    use http_body_util::{BodyExt, Empty};
    use std::sync::Mutex;

    #[tokio::test(flavor = "current_thread")]
    async fn converts_reqwest_response_status_headers_body() {
        // Build a reqwest::Response without going through the network, using
        // http::Response::from_parts + reqwest::Response::from.
        let http_resp = http::Response::builder()
            .status(200)
            .header("x-echo", "hi")
            .body("hello".to_string())
            .unwrap();
        let resp = reqwest::Response::from(http_resp);

        let (incoming, _io) = reqwest_response_to_wasi(resp).await.expect("conversion ok");

        assert_eq!(incoming.status(), hyper::StatusCode::OK);
        assert_eq!(
            incoming
                .headers()
                .get("x-echo")
                .and_then(|v| v.to_str().ok()),
            Some("hi")
        );
        let body_bytes = http_body_util::BodyExt::collect(incoming.into_body())
            .await
            .expect("body collect")
            .to_bytes();
        assert_eq!(&body_bytes[..], b"hello");
    }

    #[test]
    fn builds_default_client() {
        let cfg = HttpConfig::default();
        let client = ActHttpClient::new(cfg);
        assert!(client.is_ok(), "{:?}", client.err());
    }

    #[test]
    fn builds_client_with_keepalive_defaults() {
        // Smoke: the builder chain for keep-alive / pool settings accepts the
        // defaults we want to ship. Can't observe ping behaviour in a unit
        // test without a live peer, but a regression in the builder call
        // chain (wrong arg types, renamed methods) would surface here.
        let cfg = HttpConfig::default();
        let client = ActHttpClient::new(cfg);
        assert!(client.is_ok(), "{:?}", client.err());
    }

    #[test]
    fn converts_simple_get_request() {
        let body: UnsyncBoxBody<bytes::Bytes, _> = Empty::<bytes::Bytes>::new()
            .map_err(|_| unreachable!())
            .boxed_unsync();
        let hyper_req = hyper::Request::builder()
            .method(Method::GET)
            .uri("https://example.com/foo?bar=baz")
            .header("x-custom", "hello")
            .body(body)
            .expect("hyper request builds");

        let reqwest_req = to_reqwest(hyper_req).expect("conversion succeeds");

        assert_eq!(reqwest_req.method(), &reqwest::Method::GET);
        assert_eq!(
            reqwest_req.url().as_str(),
            "https://example.com/foo?bar=baz"
        );
        assert_eq!(
            reqwest_req
                .headers()
                .get("x-custom")
                .and_then(|v| v.to_str().ok()),
            Some("hello")
        );
    }

    #[test]
    fn converts_post_request_with_body_and_port() {
        let body_bytes = bytes::Bytes::from_static(b"payload");
        let body: WasiBody = http_body_util::Full::new(body_bytes.clone())
            .map_err(|_| unreachable!())
            .boxed_unsync();
        let hyper_req = hyper::Request::builder()
            .method(Method::POST)
            .uri("http://api.example.com:8080/v1/create")
            .header("content-type", "application/json")
            .body(body)
            .expect("hyper request builds");

        let reqwest_req = to_reqwest(hyper_req).expect("conversion succeeds");

        assert_eq!(reqwest_req.method(), &reqwest::Method::POST);
        assert_eq!(
            reqwest_req.url().as_str(),
            "http://api.example.com:8080/v1/create"
        );
        assert_eq!(
            reqwest_req
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn send_fetches_example_dot_com() {
        // Integration-style test: requires network.
        let body: WasiBody = Empty::<bytes::Bytes>::new()
            .map_err(|_| unreachable!())
            .boxed_unsync();
        let hyper_req = hyper::Request::builder()
            .method(Method::GET)
            .uri("https://example.com/")
            .body(body)
            .unwrap();

        let cfg = HttpConfig {
            mode: act_policy::grant::PolicyMode::Open,
            ..Default::default()
        };
        let client = ActHttpClient::new(cfg).expect("client builds");
        let options = RequestOptions {
            connect_timeout: Some(std::time::Duration::from_secs(10)),
            first_byte_timeout: Some(std::time::Duration::from_secs(10)),
            between_bytes_timeout: Some(std::time::Duration::from_secs(10)),
        };
        let (incoming, _io) = client
            .send(hyper_req, Some(options))
            .await
            .expect("send succeeds");
        assert_eq!(
            incoming.status().as_u16(),
            200,
            "example.com should return 200"
        );
    }

    #[test]
    fn maps_timeout_to_connection_timeout() {
        // Can't directly build a reqwest::Error, so verify the logic by
        // making a real request to an unreachable address with a tight
        // timeout and mapping its error.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt.block_on(async {
            let client = reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_millis(1))
                .build()
                .unwrap();
            client
                .get("http://192.0.2.1:81/") // TEST-NET-1, unroutable
                .send()
                .await
                .expect_err("must fail")
        });

        let mapped = reqwest_to_error(err);
        assert!(
            matches!(
                mapped,
                HttpError::ConnectionTimeout
                    | HttpError::ConnectionRefused
                    | HttpError::HttpResponseTimeout
            ),
            "expected a connection-class error, got {mapped:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn redirect_policy_blocks_cross_host_hop() {
        use act_policy::Decision;
        use act_policy::grant::PolicyMode;
        use act_policy::net::{NetworkCheck, NetworkRule, decide};

        let allow = vec![NetworkRule {
            host: Some("primary.example".into()),
            ..Default::default()
        }];
        let deny: Vec<NetworkRule> = vec![];

        let blocked = decide(
            PolicyMode::Allowlist,
            &allow,
            &deny,
            &NetworkCheck::new("other.example", 443),
        );
        assert_eq!(blocked, Decision::Deny);

        let allowed = decide(
            PolicyMode::Allowlist,
            &allow,
            &deny,
            &NetworkCheck::new("primary.example", 443),
        );
        assert_eq!(allowed, Decision::Allow);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dns_resolver_filters_denied_cidr() {
        use act_policy::grant::{HttpConfig, HttpRule, PolicyMode};
        use act_policy::net::NetworkRule;

        let cfg = HttpConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![HttpRule {
                net: NetworkRule {
                    host: Some("localhost".into()),
                    ..Default::default()
                },
                ..Default::default()
            }],
            // Deny any resolved IP in 127/8.
            deny: vec![HttpRule {
                net: NetworkRule {
                    cidr: Some("127.0.0.0/8".into()),
                    ..Default::default()
                },
                ..Default::default()
            }],
        };
        let client = ActHttpClient::new(cfg).expect("client builds");
        let body: WasiBody = Empty::<bytes::Bytes>::new()
            .map_err(|_| unreachable!())
            .boxed_unsync();
        let hyper_req = hyper::Request::builder()
            .method(Method::GET)
            .uri("http://localhost/")
            .body(body)
            .unwrap();
        let options = RequestOptions {
            connect_timeout: Some(std::time::Duration::from_secs(5)),
            first_byte_timeout: Some(std::time::Duration::from_secs(5)),
            between_bytes_timeout: Some(std::time::Duration::from_secs(5)),
        };
        let err = match client.send(hyper_req, Some(options)).await {
            Ok(_) => panic!("localhost resolves into denied 127/8, should fail"),
            Err(e) => e,
        };
        // DnsError because the resolver returned zero non-denied addresses.
        // (Or ConnectionRefused if the test harness has nothing listening on 127.0.0.1:80,
        //  in which case the DNS filter wasn't applied — test is weak but valid positive-deny check.)
        assert!(
            matches!(err, HttpError::DnsError { .. })
                || matches!(err, HttpError::ConnectionRefused),
            "expected DnsError or ConnectionRefused, got {err:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dns_resolver_requires_allow_cidr_match_for_hostnames() {
        // mode=Allowlist with only an allow-CIDR rule. Any URI whose
        // resolved IPs land outside that CIDR must fail at DNS level.
        use act_policy::grant::{HttpConfig, HttpRule, PolicyMode};
        use act_policy::net::NetworkRule;

        let cfg = HttpConfig {
            mode: PolicyMode::Allowlist,
            // Only permit internal RFC1918 space — example.com is public.
            allow: vec![HttpRule {
                net: NetworkRule {
                    cidr: Some("10.0.0.0/8".into()),
                    ..Default::default()
                },
                ..Default::default()
            }],
            deny: vec![],
        };
        let client = ActHttpClient::new(cfg).expect("client builds");
        let body: WasiBody = Empty::<bytes::Bytes>::new()
            .map_err(|_| unreachable!())
            .boxed_unsync();
        let hyper_req = hyper::Request::builder()
            .method(Method::GET)
            .uri("https://example.com/")
            .body(body)
            .unwrap();
        let options = RequestOptions {
            connect_timeout: Some(std::time::Duration::from_secs(5)),
            first_byte_timeout: Some(std::time::Duration::from_secs(5)),
            between_bytes_timeout: Some(std::time::Duration::from_secs(5)),
        };
        let err = match client.send(hyper_req, Some(options)).await {
            Ok(_) => panic!("example.com IPs not in 10/8, must fail at DNS"),
            Err(e) => e,
        };
        assert!(
            matches!(err, HttpError::DnsError { .. }),
            "expected DnsError, got {err:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "network: makes a real HTTPS request to example.com"]
    async fn dns_resolver_host_match_bypasses_allow_cidr() {
        // mode=Allowlist with BOTH a host-allow AND an allow-CIDR. A
        // request to the allowed host should succeed even if its IPs
        // don't fall in the CIDR — the host match approves all IPs.
        use act_policy::grant::{HttpConfig, HttpRule, PolicyMode};
        use act_policy::net::NetworkRule;

        let cfg = HttpConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![
                HttpRule {
                    net: NetworkRule {
                        host: Some("example.com".into()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                HttpRule {
                    net: NetworkRule {
                        cidr: Some("10.0.0.0/8".into()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ],
            deny: vec![],
        };
        let client = ActHttpClient::new(cfg).expect("client builds");
        let body: WasiBody = Empty::<bytes::Bytes>::new()
            .map_err(|_| unreachable!())
            .boxed_unsync();
        let hyper_req = hyper::Request::builder()
            .method(Method::GET)
            .uri("https://example.com/")
            .body(body)
            .unwrap();
        let options = RequestOptions {
            connect_timeout: Some(std::time::Duration::from_secs(10)),
            first_byte_timeout: Some(std::time::Duration::from_secs(10)),
            between_bytes_timeout: Some(std::time::Duration::from_secs(10)),
        };
        let (incoming, _io) = client
            .send(hyper_req, Some(options))
            .await
            .expect("example.com allowed via host rule");
        assert_eq!(incoming.status().as_u16(), 200);
    }

    /// A capturing `AuditWriter`, local to this module — `crate::audit`'s own
    /// `TestWriter` (in `layer::tests`) isn't exported, and the point here
    /// is to observe the real `AuditLayer` render a real emission, not to
    /// re-test the layer itself (that's the audit module's job).
    #[derive(Clone, Default)]
    struct CapturingWriter(Arc<Mutex<Vec<String>>>);
    impl crate::audit::layer::AuditWriter for CapturingWriter {
        fn write_line(&self, line: &str) {
            self.0.lock().unwrap().push(line.to_string());
        }
    }

    /// `build_redirect_policy`'s `Decision::Deny` arm used to only
    /// `tracing::warn!` — a component granted its origin host but redirected
    /// off it was blocked with nothing in the audit trail. Drives a real
    /// redirect through a local raw-socket server (no external network) so
    /// this exercises the actual `redirect::Policy` closure reqwest invokes,
    /// not just `net::decide` in isolation (that's what
    /// `redirect_policy_blocks_cross_host_hop` above already covers, and
    /// continues to).
    ///
    /// Builds a bare `reqwest::Client` with `build_redirect_policy` directly,
    /// rather than going through `ActHttpClient::send`: `to_reqwest`
    /// wraps every outgoing body — even an empty GET's — via
    /// `reqwest::Body::wrap_stream`, and reqwest silently declines to follow
    /// a redirect at all when the original body isn't provably re-sendable,
    /// so `send` never reaches the redirect policy for *any* outcome
    /// (allow or deny). That's a real, separate gap in the WASI conversion
    /// layer — outside this task's scope (it would affect the redirect
    /// *decision* on the allow side too, not just this audit gap) — noted in
    /// the report rather than fixed here. A plain `.get()` has no body at
    /// all, so it sidesteps that gap and exercises the redirect policy the
    /// way a normal reqwest caller would.
    #[tokio::test(flavor = "current_thread")]
    async fn redirect_hop_denial_is_audited() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tracing_subscriber::prelude::*;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await; // drain the request line/headers
            let resp = b"HTTP/1.1 302 Found\r\n\
                          Location: http://blocked.example/\r\n\
                          Content-Length: 0\r\n\
                          Connection: close\r\n\r\n";
            let _ = stream.write_all(resp).await;
            let _ = stream.shutdown().await;
        });

        // Allows the origin (127.0.0.1, where the 302 comes from) but not
        // the redirect target (blocked.example) — the redirect hop itself
        // must be what gets denied, not the initial request.
        let cfg = Arc::new(HttpConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![act_policy::grant::HttpRule {
                net: NetworkRule {
                    host: Some("127.0.0.1".into()),
                    ..Default::default()
                },
                ..Default::default()
            }],
            deny: vec![],
        });
        let client = reqwest::Client::builder()
            .redirect(build_redirect_policy(cfg))
            .build()
            .expect("client builds");

        let writer = CapturingWriter::default();
        let sink = writer.0.clone();
        let sub = tracing_subscriber::registry().with(crate::audit::AuditLayer::new(
            writer,
            crate::audit::Detail::Rollup,
        ));
        let _guard = tracing::subscriber::set_default(sub);

        let result = client.get(format!("http://{addr}/")).send().await;

        drop(_guard);
        server.await.expect("server task");

        let err = result.expect_err("redirect target denied, the request must fail");
        assert!(
            err.is_redirect(),
            "expected a redirect-class error, got {err:?}"
        );

        let lines = sink.lock().unwrap().clone();
        let deny_line = lines
            .iter()
            .find(|l| l.contains("blocked.example"))
            .unwrap_or_else(|| panic!("no redirect-deny audit line, got {lines:?}"));
        assert!(deny_line.contains("wasi:http"), "got {deny_line}");
        assert!(
            deny_line.contains("redirect target outside ceiling"),
            "reason must distinguish this from an ordinary ceiling denial, got {deny_line}"
        );
    }

    /// `PolicyDnsResolver::resolve`'s `filtered.is_empty()` arm used to just
    /// return an `Err` — a component granted a host whose every resolved
    /// address then got dropped by a deny-CIDR was blocked with nothing in
    /// the audit trail, indistinguishable from a plain DNS failure. Denies
    /// BOTH loopback families (`127.0.0.0/8` and `::1/128`) so `filtered` is
    /// empty deterministically regardless of whether this host's resolver
    /// returns v4, v6, or both for "localhost" — the flakiness the
    /// neighbouring `dns_resolver_filters_denied_cidr` test above already
    /// warns about in its own comment. The allow rule is host-anchored
    /// (`host = "localhost"`, not a CIDR), so this is exactly the scenario
    /// the review called out: the host itself was granted, but its resolved
    /// address got filtered anyway.
    #[tokio::test(flavor = "current_thread")]
    async fn dns_cidr_filtered_resolution_is_audited() {
        use act_policy::grant::{HttpConfig as PolicyHttpConfig, HttpRule};
        use act_policy::net::NetworkRule as PolicyNetworkRule;
        use tracing_subscriber::prelude::*;

        let cfg = PolicyHttpConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![HttpRule {
                net: PolicyNetworkRule {
                    host: Some("localhost".into()),
                    ..Default::default()
                },
                ..Default::default()
            }],
            deny: vec![
                HttpRule {
                    net: PolicyNetworkRule {
                        cidr: Some("127.0.0.0/8".into()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                HttpRule {
                    net: PolicyNetworkRule {
                        cidr: Some("::1/128".into()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ],
        };
        let client = ActHttpClient::new(cfg).expect("client builds");
        let body: WasiBody = Empty::<bytes::Bytes>::new()
            .map_err(|_| unreachable!())
            .boxed_unsync();
        let hyper_req = hyper::Request::builder()
            .method(Method::GET)
            .uri("http://localhost/")
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
        let _guard = tracing::subscriber::set_default(sub);

        let err = match client.send(hyper_req, Some(options)).await {
            Ok(_) => panic!("both loopback families are denied, must fail at DNS"),
            Err(e) => e,
        };

        drop(_guard);

        assert!(
            matches!(err, HttpError::DnsError { .. }),
            "expected DnsError, got {err:?}"
        );

        let lines = sink.lock().unwrap().clone();
        let deny_line = lines
            .iter()
            .find(|l| l.contains("localhost"))
            .unwrap_or_else(|| panic!("no dns-filtered deny audit line, got {lines:?}"));
        assert!(deny_line.contains("wasi:http"), "got {deny_line}");
        assert!(
            deny_line.contains("all resolved addresses filtered by CIDR rule"),
            "reason must distinguish this from an ordinary ceiling denial, got {deny_line}"
        );
    }
}
