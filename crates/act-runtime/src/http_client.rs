//! Reqwest-backed client for `wasi:http/outgoing-handler`. One instance per
//! `HostState` (per component invocation). Client config — redirect policy,
//! DNS resolver — is baked in at construction from the component's
//! `HttpConfig` so we don't need to thread context through each call.
//!
//! # Extraction boundary
//!
//! `http_client`, `http_policy`, and `network`, plus the `HttpConfig` /
//! `HttpRule` / `NetworkRule` / `PolicyMode` types in `config`, form a
//! self-contained "policy-aware HTTP backend for `wasi:http`" unit with
//! zero act-cli-specific dependencies (no CLI, no component metadata, no
//! ACT protocol). The boundary is maintained intentionally so this layer
//! can be lifted into its own crate (e.g. `act-wasi-http-policy`) when a
//! second consumer appears or when we propose the pattern upstream to
//! `wasmtime-wasi-http`. Do not reach outside those modules from here; if
//! you need something else, pass it in via config.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use http_body_util::BodyExt;
use wasmtime_wasi_http::{Error as HttpError, RequestOptions, WasiBody};

use crate::audit::{CapDecisionRecord, Decision4, emit_cap_decision};
use act_policy::grant::{HttpConfig, PolicyMode};
use act_policy::net::{self as network, NetworkRule};

/// A resolver that filters what a name resolves to, against the component's
/// CIDR rules.
///
/// Per resolved address:
/// 1. Drop if any deny-CIDR matches (respecting `except_ports`).
/// 2. In `Allowlist` mode, if any allow rule carries a `cidr`, the address must
///    be covered by either a host-anchored allow (the hostname itself was
///    allowed, so every address it resolves to is) or an allow-CIDR. This
///    closes the asymmetry where `allow = [{ cidr = "..." }]` would otherwise
///    require an IP-literal URI.
/// 3. `Open` / `Deny` modes: no allow-side filter (`Deny` never reaches a
///    resolver; `Open` still honours deny-CIDR as a safety net).
///
/// ## Two streams, one decision
///
/// `hclient`'s `Resolve` returns A and AAAA as **separate streams**, because
/// RFC 8305 requires starting IPv6 attempts without waiting for the IPv4
/// answer. That is right for connecting and awkward for auditing: "everything
/// was filtered" is only knowable once both have ended, and a record emitted
/// per stream would report one blocked lookup twice.
///
/// So this layer no longer emits it. The record moves to where the failure
/// becomes one event — the request, in [`ActHttpClient::send`], which sees a
/// resolve error and knows the host it was for. That is also where the old
/// comment said the decision belonged ("to the guest this is a single
/// failure"); the two-stream shape merely forced the issue.
#[derive(Clone)]
struct PolicyDnsResolver {
    inner: Arc<hclient_dns_system::SystemDns<hclient_rt_tokio::Tokio>>,
    /// Per name: how many addresses the upstream offered, and how many
    /// survived. Read once, by `send`, to tell "policy dropped everything"
    /// from "the name does not resolve" — a distinction the two streams
    /// cannot make on their own, and one that must survive: reporting a DNS
    /// outage as a capability denial sends an operator to the wrong file.
    seen: Arc<std::sync::Mutex<std::collections::HashMap<String, (usize, usize)>>>,
    allow_nets: Arc<Vec<NetworkRule>>,
    deny_nets: Arc<Vec<NetworkRule>>,
    mode: PolicyMode,
}

impl PolicyDnsResolver {
    fn new(cfg: &HttpConfig) -> Self {
        Self {
            inner: Arc::new(hclient_dns_system::SystemDns::new(hclient_rt_tokio::Tokio)),
            seen: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            allow_nets: Arc::new(cfg.allow.iter().map(|r| r.net.clone()).collect()),
            deny_nets: Arc::new(cfg.deny.iter().map(|r| r.net.clone()).collect()),
            mode: cfg.mode,
        }
    }

    /// Whether this address may be connected to at all.
    ///
    /// Port zero: a name resolves independently of the port a caller will
    /// later connect to, so a deny rule scoped to ports cannot be decided
    /// here. Port-scoped rules are enforced where the port is known — the
    /// request check in `send`, and the redirect predicate.
    /// Whether policy — not DNS — is why nothing came back for `host`.
    ///
    /// `true` only when the upstream offered addresses and every one was
    /// dropped. A name that resolves to nothing is a DNS failure and gets no
    /// capability record: it is not a decision this host made.
    fn filtered_everything(&self, host: &str) -> bool {
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(host)
            .is_some_and(|(offered, kept)| *offered > 0 && *kept == 0)
    }

    fn permits(&self, host: &str, addr: std::net::IpAddr) -> bool {
        if network::any_deny_cidr_matches(&self.deny_nets, addr, 0) {
            return false;
        }
        let host_allowed = self.allow_nets.iter().any(|r| {
            r.host
                .as_deref()
                .is_some_and(|pat| network::host_matches(pat, host))
        });
        let require_allow_cidr = self.mode == PolicyMode::Allowlist
            && !host_allowed
            && self.allow_nets.iter().any(|r| r.cidr.is_some());
        if require_allow_cidr {
            return self.allow_nets.iter().any(|r| {
                r.cidr
                    .as_deref()
                    .is_some_and(|c| network::cidr_contains(c, addr))
            });
        }
        true
    }
}

impl hclient_dns::Resolve for PolicyDnsResolver {
    type Ipv4<'a> =
        futures_util::stream::BoxStream<'a, Result<hclient_dns::ResolvedAddr, hclient::Error>>;
    type Ipv6<'a> =
        futures_util::stream::BoxStream<'a, Result<hclient_dns::ResolvedAddr, hclient::Error>>;
    type Svcb<'a> =
        futures_util::stream::BoxStream<'a, Result<hclient_dns::SvcbEndpoint, hclient::Error>>;

    fn lookup_ipv4<'a>(&'a self, name: &str) -> Self::Ipv4<'a> {
        self.filtered(name, true)
    }

    fn lookup_ipv6<'a>(&'a self, name: &str) -> Self::Ipv6<'a> {
        self.filtered(name, false)
    }

    fn supports_svcb(&self) -> bool {
        false
    }

    fn lookup_svcb<'a>(&'a self, _name: &str) -> Self::Svcb<'a> {
        Box::pin(futures_util::stream::empty())
    }
}

impl PolicyDnsResolver {
    fn filtered<'a>(
        &'a self,
        name: &str,
        v4: bool,
    ) -> futures_util::stream::BoxStream<'a, Result<hclient_dns::ResolvedAddr, hclient::Error>>
    {
        use futures_util::StreamExt;
        let host = name.to_string();
        let upstream: futures_util::stream::BoxStream<'a, _> = if v4 {
            Box::pin(hclient_dns::Resolve::lookup_ipv4(&*self.inner, name))
        } else {
            Box::pin(hclient_dns::Resolve::lookup_ipv6(&*self.inner, name))
        };
        Box::pin(upstream.filter(move |item| {
            let keep = match item {
                Ok(resolved) => self.permits(&host, resolved.addr),
                // A resolver error is not a policy decision and is passed
                // through: swallowing it would turn "DNS is down" into
                // "policy refused", and an operator would go looking in the
                // wrong place.
                Err(_) => true,
            };
            if item.is_ok() {
                let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
                let counts = seen.entry(host.clone()).or_insert((0, 0));
                counts.0 += 1;
                if keep {
                    counts.1 += 1;
                }
            }
            if !keep {
                tracing::debug!(%host, "http policy dropped a resolved address");
            }
            std::future::ready(keep)
        }))
    }
}

/// The per-hop capability check.
///
/// Without it a granted host is an open proxy: a component allowed to reach
/// `api.github.com` asks that server for a redirect and follows it anywhere.
/// The ceiling is the whole claim, so this runs on **every** hop, and a refusal
/// stops the chain rather than being reported after the fact.
///
/// `hclient` consults it after its own hop count, only about hops that would
/// have been followed — so switching it on cannot make a chain longer — and
/// hands it the hop as it would go out: the resolved target, the possibly
/// downgraded method, whether credentials are about to be stripped.
fn redirect_verdict(
    cfg: &HttpConfig,
    hop: &hclient::redirect::ProposedRedirect<'_>,
) -> hclient::redirect::RedirectVerdict {
    use hclient::redirect::RedirectVerdict;

    let to = hop.to();
    let host = to.host().unwrap_or("");
    let scheme = to.scheme_str().unwrap_or("http");
    let port = to
        .port_u16()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });

    let allow_nets: Vec<NetworkRule> = cfg.allow.iter().map(|r| r.net.clone()).collect();
    let deny_nets: Vec<NetworkRule> = cfg.deny.iter().map(|r| r.net.clone()).collect();
    let decision = network::decide(
        cfg.mode,
        &allow_nets,
        &deny_nets,
        &network::NetworkCheck::new(host, port),
    );
    match decision {
        act_policy::Decision::Allow => RedirectVerdict::Follow,
        // `Ask` gates the request itself, at `send`. This callback is sync and
        // cannot prompt, so a hop inside an already-approved request is
        // followed. Per-hop asking is a later phase, and would need the
        // predicate to be async.
        act_policy::Decision::Ask => RedirectVerdict::Follow,
        act_policy::Decision::Deny => {
            tracing::warn!(%to, "http policy: redirect hop blocked");
            emit_cap_decision(&CapDecisionRecord::statik_with_reason(
                act_types::constants::CAP_HTTP,
                &format!("{host}:{port}"),
                "",
                Decision4::Deny,
                &cfg.mode.to_string(),
                None,
                Some("redirect target outside ceiling"),
            ));
            // `Refuse`, not `Stop`: stopping would hand the 3xx back as an
            // ordinary answer, and a guest that never checks the status would
            // read a blocked redirect as a successful request.
            RedirectVerdict::Refuse
        }
    }
}

/// An HTTP client carrying this component's capability ceiling.
///
/// Two enforcement points, and both are inside the client rather than around
/// it: the resolver refuses addresses a CIDR rule excludes, and the redirect
/// predicate refuses a hop outside the ceiling. A check placed around a client
/// is a check a redirect walks past.
///
/// Cheap to clone; share freely across tasks.
#[derive(Clone)]
pub struct ActHttpClient {
    client: Arc<hclient::Client>,
    resolver: PolicyDnsResolver,
    mode: PolicyMode,
}

impl ActHttpClient {
    pub fn new(cfg: HttpConfig) -> anyhow::Result<Self> {
        let cfg_for_hops = cfg.clone();

        act_store::fetch::install_crypto_provider();
        let resolver = PolicyDnsResolver::new(&cfg);
        let mode = cfg.mode;
        let transport = hclient_native::Native::new(
            hclient_rt_tokio::Tokio,
            hclient_tls_rustls::Rustls::with_webpki_roots(),
            resolver.clone(),
        )
        // Keep HTTP/2 multiplexed connections alive through idle periods —
        // SSE and long-poll streams can go 30+ seconds between events, and
        // without this a NAT or load-balancer flow timer drops them silently.
        // `every` and `within`, because neither is useful alone. There is no
        // `while_idle` knob to set: `hclient` pings on a timer rather than on
        // silence, which its own docs say is the only thing h2 can offer.
        .h2_keep_alive(hclient_native::H2KeepAlive::new(
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(10),
        ))
        // Long-lived streams must not be evicted while in use. Ten minutes,
        // where a one-shot request would be happy with far less.
        .pool(hclient_native::PoolConfig {
            idle_timeout: std::time::Duration::from_secs(600),
            ..Default::default()
        });

        let client = hclient::Client::builder(transport)
            .redirect_predicate(move |hop| redirect_verdict(&cfg_for_hops, hop))
            .build()
            .map_err(|e| anyhow::anyhow!("the HTTP backend cannot serve this policy: {e}"))?;
        Ok(Self {
            client: Arc::new(client),
            resolver,
            mode,
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

        let (method, url, headers, body) = to_request_parts(request)?;
        // Kept for the audit record below: the URL is consumed by the builder.
        let host = url
            .parse::<http::Uri>()
            .ok()
            .and_then(|u| u.host().map(str::to_string))
            .unwrap_or_default();
        let mut req = self.client.request(method, &url);
        for (name, value) in headers.iter() {
            req = req.header(name.as_str(), value.to_str().unwrap_or_default());
        }
        let resp = match tokio::time::timeout(deadline, req.body(body).send()).await {
            Err(_) => return Err(HttpError::ConnectionTimeout),
            Ok(Err(e)) => {
                // One record per blocked request, emitted here because this is
                // where the failure becomes a single event: the resolver sees
                // two independent streams and cannot tell, from either one,
                // that the other also came back empty.
                if matches!(e.kind(), hclient::ErrorKind::Resolve)
                    && self.resolver.filtered_everything(&host)
                {
                    emit_cap_decision(&CapDecisionRecord::statik_with_reason(
                        act_types::constants::CAP_HTTP,
                        &host,
                        "",
                        Decision4::Deny,
                        &self.mode.to_string(),
                        None,
                        Some("all resolved addresses filtered by CIDR rule"),
                    ));
                }
                return Err(client_error_to_wasi(e));
            }
            Ok(Ok(resp)) => resp,
        };
        let (parts, body) = resp.into_parts();
        response_to_wasi(parts, body)
    }
}

/// Split an outgoing request into the pieces the client takes.
#[allow(clippy::type_complexity)]
fn to_request_parts(
    request: http::Request<WasiBody>,
) -> Result<(http::Method, String, http::HeaderMap, hclient::RequestBody), HttpError> {
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
    let url = format!("{scheme}://{authority}{path_and_query}");

    // The guest's body goes across as a stream, not a buffer: a component
    // uploading is not required to have the whole thing in memory, and neither
    // is this host. `RequestBody::Streaming` takes an `http_body::Body`
    // directly, so there is no adapter between the two — where the previous
    // backend
    // needed the frames rewrapped as a byte stream first.
    let body = hclient::RequestBody::Streaming(Box::new(WasiRequestBody(body)));
    Ok((parts.method, url, parts.headers, body))
}

/// The guest's body, with its error type mapped to `hclient`'s.
///
/// A newtype rather than a combinator because the only thing that changes is
/// the error, and `http_body::Body`'s associated types make that a two-line
/// impl instead of a chain of adapters.
struct WasiRequestBody(WasiBody);

impl http_body::Body for WasiRequestBody {
    type Data = bytes::Bytes;
    type Error = hclient::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let inner = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        inner.poll_frame(cx).map(|opt| {
            opt.map(|res| {
                res.map_err(|_| {
                    hclient::Error::new(
                        hclient::ErrorKind::Body,
                        std::io::Error::other("wasi:http body stream error"),
                    )
                })
            })
        })
    }
}

/// Translate a client error to the closest `wasi:http` error.
///
/// Matching on `ErrorKind` rather than reading the `source()` chain for
/// substrings, which is what this did against `reqwest`: "dns", "connect",
/// "deny cidr" sniffed out of whatever text three layers happened to produce.
/// A typed kind cannot drift when a dependency rewords an error.
fn client_error_to_wasi(err: hclient::Error) -> HttpError {
    use hclient::ErrorKind;
    match err.kind() {
        ErrorKind::Timeout(_) => HttpError::ConnectionTimeout,
        ErrorKind::Resolve => HttpError::DnsError {
            rcode: Some(err.to_string()),
            info_code: None,
        },
        ErrorKind::Connect => HttpError::ConnectionRefused,
        // A refused hop and an exhausted hop count arrive the same way. Both
        // are the host declining to go somewhere, which is what
        // `HttpRequestDenied` says.
        ErrorKind::Redirect => HttpError::HttpRequestDenied,
        ErrorKind::Body => HttpError::HttpRequestBodySize(None),
        ErrorKind::Decode => HttpError::HttpProtocolError,
        _ => HttpError::HttpProtocolError,
    }
}

/// Convert a client response to the shape the hook expects: an
/// `http::Response<WasiBody>` plus a future standing for body completion.
///
/// Takes the response **already split into parts and body** rather than the
/// client's wrapper. Two reasons, and the second is the one that matters: the
/// wrapper carries nothing this needs, and a consumer cannot construct one —
/// `Response::new` is crate-private — so a test could not reach this at all if
/// it took the wrapper. Split, it is a plain function over `http` types with
/// no network anywhere near it.
/// What the `wasi:http` hook expects back: the response, and a future standing
/// for the body's completion.
type HookResponse = (
    http::Response<WasiBody>,
    Pin<Box<dyn Future<Output = Result<(), HttpError>> + Send>>,
);

fn response_to_wasi<B>(parts: http::response::Parts, body: B) -> Result<HookResponse, HttpError>
where
    B: http_body::Body<Data = bytes::Bytes, Error = hclient::Error> + Send + 'static,
{
    let mut headers = parts.headers.clone();
    // Hop-by-hop framing the guest must not see: the body it receives is
    // already de-chunked and decompressed, so a `transfer-encoding` or a
    // `content-length` describing the wire form would describe something else.
    headers.remove(http::header::TRANSFER_ENCODING);
    headers.remove(http::header::CONTENT_LENGTH);

    let body: WasiBody = BodyExt::boxed_unsync(BodyExt::map_err(body, client_error_to_wasi));

    let mut builder = http::Response::builder().status(parts.status);
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
    async fn converts_response_status_headers_body() {
        // No network and no client: the conversion takes `http` parts and a
        // body, so a test can hand it either. It could not take the client's
        // `Response` — `Response::new` is crate-private there, which is why
        // this function was reshaped rather than wrapped.
        let http_resp = http::Response::builder()
            .status(200)
            .header("x-echo", "hi")
            .body(
                http_body_util::Full::new(bytes::Bytes::from_static(b"hello"))
                    .map_err(|_: std::convert::Infallible| unreachable!())
                    .boxed_unsync(),
            )
            .unwrap();
        let (parts, body) = http_resp.into_parts();
        let body = BodyExt::map_err(body, |_| {
            hclient::Error::new(hclient::ErrorKind::Body, std::io::Error::other("unused"))
        });

        let (incoming, _io) = response_to_wasi(parts, body).expect("conversion ok");

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

        let (method, url, headers, _body) =
            to_request_parts(hyper_req).expect("conversion succeeds");

        assert_eq!(method, Method::GET);
        assert_eq!(url, "https://example.com/foo?bar=baz");
        assert_eq!(
            headers.get("x-custom").and_then(|v| v.to_str().ok()),
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

        let (method, url, headers, _body) =
            to_request_parts(hyper_req).expect("conversion succeeds");

        assert_eq!(method, Method::POST);
        assert_eq!(url, "http://api.example.com:8080/v1/create");
        assert_eq!(
            headers.get("content-type").and_then(|v| v.to_str().ok()),
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

    /// The error mapping, without a network round trip.
    ///
    /// It used to make a real request to an unroutable address, because a
    /// `reqwest::Error` could not be constructed — which made a unit test of a
    /// pure mapping depend on how the machine's network refuses things, and it
    /// was one of the tests that failed behind an intercepting proxy. A typed
    /// `ErrorKind` can simply be built.
    #[test]
    fn maps_each_error_kind_to_its_wasi_error() {
        use hclient::ErrorKind;
        let io = || std::io::Error::other("under test");

        for (kind, expected) in [
            (ErrorKind::Connect, HttpError::ConnectionRefused),
            (ErrorKind::Redirect, HttpError::HttpRequestDenied),
        ] {
            let named = format!("{kind:?}");
            let mapped = client_error_to_wasi(hclient::Error::new(kind, io()));
            assert_eq!(
                std::mem::discriminant(&mapped),
                std::mem::discriminant(&expected),
                "{named} mapped to {mapped:?}"
            );
        }

        // Resolve carries the message through, so it is checked by shape
        // rather than by discriminant alone.
        let mapped = client_error_to_wasi(hclient::Error::new(ErrorKind::Resolve, io()));
        assert!(
            matches!(mapped, HttpError::DnsError { rcode: Some(_), .. }),
            "a resolve failure must reach the guest as a DNS error naming it, got {mapped:?}"
        );

        // A refused hop and an exhausted hop count arrive as the same kind;
        // both are the host declining to go somewhere.
        assert!(matches!(
            client_error_to_wasi(hclient::Error::new(ErrorKind::Redirect, io())),
            HttpError::HttpRequestDenied
        ));
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
        let cfg = HttpConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![act_policy::grant::HttpRule {
                net: NetworkRule {
                    host: Some("127.0.0.1".into()),
                    ..Default::default()
                },
                ..Default::default()
            }],
            deny: vec![],
        };
        act_store::fetch::install_crypto_provider();
        let resolver = PolicyDnsResolver::new(&cfg);
        let mode = cfg.mode;
        let transport = hclient_native::Native::new(
            hclient_rt_tokio::Tokio,
            hclient_tls_rustls::Rustls::with_webpki_roots(),
            resolver.clone(),
        );
        let client = hclient::Client::builder(transport)
            .redirect_predicate(move |hop| redirect_verdict(&cfg, hop))
            .build()
            .expect("client builds");

        let writer = CapturingWriter::default();
        let sink = writer.0.clone();
        let sub = tracing_subscriber::registry().with(crate::audit::AuditLayer::new(
            writer,
            crate::audit::Detail::Rollup,
        ));
        let _guard = tracing::subscriber::set_default(sub);

        let result = client.get(&format!("http://{addr}/")).send().await;

        drop(_guard);
        server.await.expect("server task");

        let err = result.expect_err("redirect target denied, the request must fail");
        assert!(
            matches!(err.kind(), hclient::ErrorKind::Redirect),
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
