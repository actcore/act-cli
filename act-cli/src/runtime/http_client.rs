//! Reqwest-backed client for `wasi:http/outgoing-handler`. One instance per
//! `HostState` (per component invocation). Client config — redirect policy,
//! DNS resolver — is baked in at construction from the component's
//! `HttpConfig` so we don't need to thread context through each call.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use wasmtime_wasi_http::p2::bindings::http::types::ErrorCode as P2ErrorCode;

use crate::config::HttpConfig;

/// Reqwest client instantiated with this component's HTTP policy. Cheap to
/// clone (reqwest::Client is internally `Arc`'d); share freely across
/// async tasks.
#[derive(Clone)]
#[allow(dead_code)] // wired into HostState in Task 7
pub struct ActHttpClient {
    client: Arc<reqwest::Client>,
}

impl ActHttpClient {
    #[allow(dead_code)] // wired into HostState in Task 7
    pub fn new(_cfg: HttpConfig) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build reqwest client: {e}"))?;
        Ok(Self {
            client: Arc::new(client),
        })
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
#[allow(dead_code)] // called in Task 6 (send_p2)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HttpConfig;
    use http::Method;
    use http_body_util::combinators::UnsyncBoxBody;
    use http_body_util::{BodyExt, Empty};
    use wasmtime_wasi_http::p2::bindings::http::types::ErrorCode as P2ErrorCode;

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
}
