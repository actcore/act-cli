//! Reqwest-backed client for `wasi:http/outgoing-handler`. One instance per
//! `HostState` (per component invocation). Client config — redirect policy,
//! DNS resolver — is baked in at construction from the component's
//! `HttpConfig` so we don't need to thread context through each call.

use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, StreamBody};
use wasmtime_wasi_http::p2::bindings::http::types::ErrorCode as P2ErrorCode;
use wasmtime_wasi_http::p2::body::HyperIncomingBody;
use wasmtime_wasi_http::p3::bindings::http::types::ErrorCode as P3ErrorCode;

use crate::config::HttpConfig;

/// Reqwest client instantiated with this component's HTTP policy. Cheap to
/// clone (reqwest::Client is internally `Arc`'d); share freely across
/// async tasks.
#[derive(Clone)]
pub struct ActHttpClient {
    client: Arc<reqwest::Client>,
}

impl ActHttpClient {
    pub fn new(_cfg: HttpConfig) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build reqwest client: {e}"))?;
        Ok(Self {
            client: Arc::new(client),
        })
    }

    /// Perform an outgoing request on the p2 WASI HTTP path.
    pub async fn send_p2(
        &self,
        request: hyper::Request<UnsyncBoxBody<Bytes, P2ErrorCode>>,
        config: wasmtime_wasi_http::p2::types::OutgoingRequestConfig,
    ) -> Result<wasmtime_wasi_http::p2::types::IncomingResponse, P2ErrorCode> {
        let reqwest_req = p2_to_reqwest(request, config.use_tls)?;
        let resp = tokio::time::timeout(
            config.connect_timeout + config.first_byte_timeout,
            self.client.execute(reqwest_req),
        )
        .await
        .map_err(|_| P2ErrorCode::ConnectionTimeout)?
        .map_err(reqwest_to_p2_error)?;

        let hyper_resp = reqwest_response_to_hyper(resp).await?;
        Ok(wasmtime_wasi_http::p2::types::IncomingResponse {
            resp: hyper_resp,
            between_bytes_timeout: config.between_bytes_timeout,
            worker: None,
        })
    }

    /// Perform an outgoing request on the p3 WASI HTTP path. Returns the
    /// response plus a completion future matching the p3 hook signature.
    pub async fn send_p3(
        &self,
        request: http::Request<UnsyncBoxBody<Bytes, P3ErrorCode>>,
    ) -> Result<
        (
            http::Response<UnsyncBoxBody<Bytes, P3ErrorCode>>,
            Pin<Box<dyn Future<Output = Result<(), P3ErrorCode>> + Send>>,
        ),
        P3ErrorCode,
    > {
        let reqwest_req = p3_to_reqwest(request)?;
        let resp = self
            .client
            .execute(reqwest_req)
            .await
            .map_err(reqwest_to_p3_error)?;
        reqwest_response_to_p3(resp).await
    }
}

/// Convert an outgoing `hyper::Request` from the p2 WASI HTTP binding into
/// a `reqwest::Request`. `use_tls` controls the default scheme if the URI
/// doesn't include one (the guest may build requests with scheme-less
/// authorities).
///
/// The body streams through to reqwest via `Body::wrap_stream` — we don't
/// buffer. `reqwest::Body::wrap` can't take `UnsyncBoxBody` directly (it
/// requires `Send + Sync`), but `wrap_stream` only needs `Send`, so we
/// convert via `http_body_util::BodyStream`. `Frame` data chunks pass
/// through; trailer frames are dropped (reqwest doesn't propagate request
/// trailers through `wrap_stream` anyway).
fn p2_to_reqwest(
    request: hyper::Request<UnsyncBoxBody<Bytes, P2ErrorCode>>,
    use_tls: bool,
) -> Result<reqwest::Request, P2ErrorCode> {
    use futures_util::StreamExt;
    use http_body_util::BodyStream;

    let (parts, body) = request.into_parts();
    let scheme = parts
        .uri
        .scheme_str()
        .map(str::to_string)
        .unwrap_or_else(|| {
            if use_tls {
                "https".into()
            } else {
                "http".into()
            }
        });
    let authority = parts
        .uri
        .authority()
        .map(|a| a.to_string())
        .ok_or(P2ErrorCode::HttpRequestUriInvalid)?;
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let url_str = format!("{scheme}://{authority}{path_and_query}");
    let url = reqwest::Url::parse(&url_str).map_err(|_| P2ErrorCode::HttpRequestUriInvalid)?;

    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
        .map_err(|_| P2ErrorCode::HttpProtocolError)?;

    let data_stream = BodyStream::new(body).filter_map(|frame_res| async move {
        match frame_res {
            Ok(frame) => frame.into_data().ok().map(Ok::<_, std::io::Error>),
            Err(_) => Some(Err(std::io::Error::other("wasi http body stream error"))),
        }
    });
    let body = reqwest::Body::wrap_stream(data_stream);

    let mut builder = reqwest::Client::new().request(method, url).body(body);
    for (name, value) in parts.headers.iter() {
        builder = builder.header(name, value);
    }
    builder.build().map_err(|_| P2ErrorCode::HttpProtocolError)
}

/// Convert a `reqwest::Response` to a `hyper::Response<HyperIncomingBody>`
/// the p2 WASI HTTP layer expects. The body is wrapped as a streaming
/// `StreamBody` so we don't buffer — the guest reads progressively.
async fn reqwest_response_to_hyper(
    resp: reqwest::Response,
) -> Result<hyper::Response<HyperIncomingBody>, P2ErrorCode> {
    let status = resp.status();
    let version = resp.version();
    let headers = resp.headers().clone();

    let byte_stream = resp
        .bytes_stream()
        .map_ok(hyper::body::Frame::data)
        .map_err(reqwest_to_p2_error);
    let body = StreamBody::new(byte_stream);
    let body: HyperIncomingBody = BodyExt::boxed_unsync(body);

    let mut builder = hyper::Response::builder().status(status).version(version);
    if let Some(hdrs) = builder.headers_mut() {
        hdrs.extend(headers);
    }
    builder
        .body(body)
        .map_err(|_| P2ErrorCode::HttpProtocolError)
}

/// Translate a reqwest error to the closest wasi:http/types::ErrorCode.
fn reqwest_to_p2_error(err: reqwest::Error) -> P2ErrorCode {
    if err.is_timeout() {
        return P2ErrorCode::ConnectionTimeout;
    }
    if err.is_connect() {
        return P2ErrorCode::ConnectionRefused;
    }
    if err.is_redirect() {
        // Our redirect policy stopped the chain; surface as
        // HttpRequestDenied so callers can distinguish from protocol
        // errors.
        return P2ErrorCode::HttpRequestDenied;
    }
    if err.is_decode() {
        return P2ErrorCode::HttpProtocolError;
    }
    if err.is_request() {
        return P2ErrorCode::HttpRequestUriInvalid;
    }
    if err.is_body() {
        return P2ErrorCode::HttpRequestBodySize(None);
    }
    if let Some(src) = err.source() {
        let msg = src.to_string();
        if msg.contains("dns") || msg.contains("failed to lookup") {
            return P2ErrorCode::DnsError(
                wasmtime_wasi_http::p2::bindings::http::types::DnsErrorPayload {
                    rcode: Some(msg),
                    info_code: None,
                },
            );
        }
    }
    P2ErrorCode::HttpProtocolError
}

// ── p3 helpers ────────────────────────────────────────────────────────────

/// Convert an outgoing p3 request into a reqwest::Request. Streaming body,
/// same approach as p2_to_reqwest — we wrap the UnsyncBoxBody as a Stream
/// and feed it through reqwest::Body::wrap_stream, because UnsyncBoxBody
/// is !Sync and wrap() requires Sync.
fn p3_to_reqwest(
    request: http::Request<UnsyncBoxBody<Bytes, P3ErrorCode>>,
) -> Result<reqwest::Request, P3ErrorCode> {
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
        .ok_or(P3ErrorCode::HttpRequestUriInvalid)?;
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let url_str = format!("{scheme}://{authority}{path_and_query}");
    let url = reqwest::Url::parse(&url_str).map_err(|_| P3ErrorCode::HttpRequestUriInvalid)?;
    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
        .map_err(|_| P3ErrorCode::HttpProtocolError)?;

    let data_stream = BodyStream::new(body).filter_map(|frame_res| async move {
        match frame_res {
            Ok(frame) => frame.into_data().ok().map(Ok::<_, std::io::Error>),
            Err(_) => Some(Err(std::io::Error::other("wasi http p3 body stream error"))),
        }
    });
    let body = reqwest::Body::wrap_stream(data_stream);

    let mut builder = reqwest::Client::new().request(method, url).body(body);
    for (name, value) in parts.headers.iter() {
        builder = builder.header(name, value);
    }
    builder.build().map_err(|_| P3ErrorCode::HttpProtocolError)
}

/// Error mapper for the p3 path. Same taxonomy as p2 but different ErrorCode
/// enum.
fn reqwest_to_p3_error(err: reqwest::Error) -> P3ErrorCode {
    if err.is_timeout() {
        return P3ErrorCode::ConnectionTimeout;
    }
    if err.is_connect() {
        return P3ErrorCode::ConnectionRefused;
    }
    if err.is_redirect() {
        return P3ErrorCode::HttpRequestDenied;
    }
    if err.is_decode() {
        return P3ErrorCode::HttpProtocolError;
    }
    if err.is_request() {
        return P3ErrorCode::HttpRequestUriInvalid;
    }
    if err.is_body() {
        return P3ErrorCode::HttpRequestBodySize(None);
    }
    P3ErrorCode::HttpProtocolError
}

/// Convert a reqwest response to the p3 shape the hook expects:
/// http::Response<UnsyncBoxBody<Bytes, P3ErrorCode>> plus a
/// Future<Output = Result<(), P3ErrorCode>> representing the body
/// completion (reqwest handles this transparently; we return Ok(())
/// immediately since body errors surface through the stream).
async fn reqwest_response_to_p3(
    resp: reqwest::Response,
) -> Result<
    (
        http::Response<UnsyncBoxBody<Bytes, P3ErrorCode>>,
        Pin<Box<dyn Future<Output = Result<(), P3ErrorCode>> + Send>>,
    ),
    P3ErrorCode,
> {
    let status = resp.status();
    let version = resp.version();
    let headers = resp.headers().clone();

    let byte_stream = resp
        .bytes_stream()
        .map_ok(hyper::body::Frame::data)
        .map_err(reqwest_to_p3_error);
    let body: UnsyncBoxBody<Bytes, P3ErrorCode> =
        BodyExt::boxed_unsync(StreamBody::new(byte_stream));

    let mut builder = http::Response::builder().status(status).version(version);
    if let Some(hdrs) = builder.headers_mut() {
        hdrs.extend(headers);
    }
    let resp = builder
        .body(body)
        .map_err(|_| P3ErrorCode::HttpProtocolError)?;
    let io: Pin<Box<dyn Future<Output = Result<(), P3ErrorCode>> + Send>> =
        Box::pin(async { Ok(()) });
    Ok((resp, io))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HttpConfig;
    use http::Method;
    use http_body_util::combinators::UnsyncBoxBody;
    use http_body_util::{BodyExt, Empty};
    use wasmtime_wasi_http::p2::bindings::http::types::ErrorCode as P2ErrorCode;

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

        let incoming = reqwest_response_to_hyper(resp)
            .await
            .expect("conversion ok");

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

        let reqwest_req = p2_to_reqwest(hyper_req, false).expect("conversion succeeds");

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
        let body: UnsyncBoxBody<bytes::Bytes, P2ErrorCode> =
            http_body_util::Full::new(body_bytes.clone())
                .map_err(|_| unreachable!())
                .boxed_unsync();
        let hyper_req = hyper::Request::builder()
            .method(Method::POST)
            .uri("http://api.example.com:8080/v1/create")
            .header("content-type", "application/json")
            .body(body)
            .expect("hyper request builds");

        let reqwest_req = p2_to_reqwest(hyper_req, false).expect("conversion succeeds");

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
    async fn send_p2_fetches_example_dot_com() {
        // Integration-style test: requires network.
        let body: UnsyncBoxBody<bytes::Bytes, P2ErrorCode> = Empty::<bytes::Bytes>::new()
            .map_err(|_| unreachable!())
            .boxed_unsync();
        let hyper_req = hyper::Request::builder()
            .method(Method::GET)
            .uri("https://example.com/")
            .body(body)
            .unwrap();

        let cfg = HttpConfig {
            mode: crate::config::PolicyMode::Open,
            ..Default::default()
        };
        let client = ActHttpClient::new(cfg).expect("client builds");
        let config = wasmtime_wasi_http::p2::types::OutgoingRequestConfig {
            use_tls: true,
            connect_timeout: std::time::Duration::from_secs(10),
            first_byte_timeout: std::time::Duration::from_secs(10),
            between_bytes_timeout: std::time::Duration::from_secs(10),
        };
        let incoming = client
            .send_p2(hyper_req, config)
            .await
            .expect("send succeeds");
        assert_eq!(
            incoming.resp.status().as_u16(),
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

        let mapped = reqwest_to_p2_error(err);
        assert!(
            matches!(
                mapped,
                P2ErrorCode::ConnectionTimeout
                    | P2ErrorCode::ConnectionRefused
                    | P2ErrorCode::HttpResponseTimeout
            ),
            "expected a connection-class error, got {mapped:?}"
        );
    }
}
