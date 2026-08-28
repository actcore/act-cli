//! Metadata discovery: RFC 9728 for the resource, RFC 8414 (then OpenID
//! Connect) for the authorization server.
//!
//! Every URL contacted here is **derived**, never supplied. The component names
//! a resource *identifier*; this module computes that identifier's own
//! well-known location, and the authorization servers it may use come from the
//! document served there. A component that could name an endpoint could name
//! its own (design §5.5).

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use url::Url;

/// RFC 9728 §3.1.
#[derive(Debug, Clone, Deserialize)]
pub struct ResourceMetadata {
    /// The resource identifier the document describes. Checked against the one
    /// asked for: a document that describes a different resource is not this
    /// resource's metadata, however it was served.
    pub resource: String,
    #[serde(default)]
    pub authorization_servers: Vec<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
}

/// RFC 8414 §2, plus the RFC 9207 flag.
#[derive(Debug, Clone, Deserialize)]
pub struct AsMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub registration_endpoint: Option<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
}

/// Where a resource identifier's RFC 9728 metadata lives.
///
/// The well-known segment goes **after the host and before the path** — for
/// `https://host/mcp` that is `https://host/.well-known/oauth-protected-resource/mcp`,
/// not `https://host/mcp/.well-known/…`. Getting this backwards is the common
/// implementation error and it fails as a 404 that looks like "this server does
/// not support discovery" rather than like a bug here.
pub fn protected_resource_url(resource: &Url) -> Result<Url> {
    require_secure(resource)?;
    let mut url = resource.clone();
    let path = resource.path().trim_end_matches('/');
    url.set_path(&format!("/.well-known/oauth-protected-resource{path}"));
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

/// Where an authorization server's metadata may live, in the order to try.
///
/// RFC 8414 first, then OpenID Connect Discovery — the design's order. A server
/// that answers both serves the same document; one that answers only the second
/// is an OIDC provider that never adopted 8414, which is common enough that
/// stopping at the first would rule out real upstreams.
pub fn as_metadata_urls(issuer: &Url) -> Result<Vec<Url>> {
    require_secure(issuer)?;
    let path = issuer.path().trim_end_matches('/');
    let mut out = Vec::new();
    for well_known in [
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
    ] {
        let mut u = issuer.clone();
        u.set_path(&format!("{well_known}{path}"));
        u.set_query(None);
        u.set_fragment(None);
        out.push(u);
    }
    Ok(out)
}

/// HTTPS, or loopback. Public so the endpoints inside a metadata document are
/// held to the same rule as the document's own URL.
pub(crate) fn require_secure_url(url: &Url) -> Result<()> {
    require_secure(url)
}

/// HTTPS, or loopback.
///
/// The loopback exception is not a convenience: without it nothing in this
/// module can be tested end to end, and a test that has to reach the internet
/// is a test that gets disabled. It is narrow on purpose — `127.0.0.1`, `::1`
/// and `localhost`, nothing else — so a plain-http upstream on a LAN is still
/// refused, which is where a token would actually be exposed.
fn require_secure(url: &Url) -> Result<()> {
    let loopback = matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    );
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "'{url}' is not https; a credential must not be negotiated in the clear"
    );
    Ok(())
}

/// Fetch and validate the resource's metadata.
pub async fn fetch_resource_metadata(
    client: &hclient::Client,
    resource: &Url,
) -> Result<ResourceMetadata> {
    let url = protected_resource_url(resource)?;
    let md: ResourceMetadata = fetch_json(client, &url)
        .await
        .with_context(|| format!("fetching protected-resource metadata from {url}"))?;

    // A document that names a different resource is not this resource's,
    // whatever served it. Without this, a host that redirects its well-known
    // location to a neighbour's document would point the flow at whatever
    // authorization server the neighbour names.
    let asked = resource.as_str().trim_end_matches('/');
    ensure!(
        md.resource.trim_end_matches('/') == asked,
        "{url} describes resource '{}', not '{asked}'",
        md.resource
    );
    ensure!(
        !md.authorization_servers.is_empty(),
        "{url} names no authorization servers, so there is no flow to run"
    );
    Ok(md)
}

/// Fetch and validate an authorization server's metadata.
pub async fn fetch_as_metadata(client: &hclient::Client, issuer: &Url) -> Result<AsMetadata> {
    let candidates = as_metadata_urls(issuer)?;
    let mut last: Option<anyhow::Error> = None;
    for url in &candidates {
        match fetch_json::<AsMetadata>(client, url).await {
            Ok(md) => {
                // RFC 8414 §3.3: the issuer in the document MUST match the one
                // whose metadata was requested. This is what stops a server
                // from claiming to be someone else — and the value that is
                // later checked against `iss` on the callback, so a lie here
                // would defeat the mix-up defence downstream.
                ensure!(
                    md.issuer.trim_end_matches('/') == issuer.as_str().trim_end_matches('/'),
                    "{url} claims issuer '{}', which is not '{issuer}'",
                    md.issuer
                );
                // We speak S256 and nothing else. A server that lists its
                // methods and omits S256 cannot be used, and saying so here
                // beats an opaque rejection at the token endpoint.
                if !md.code_challenge_methods_supported.is_empty() {
                    ensure!(
                        md.code_challenge_methods_supported
                            .iter()
                            .any(|m| m == "S256"),
                        "{issuer} supports PKCE methods {:?}, and this host only \
                         implements S256",
                        md.code_challenge_methods_supported
                    );
                }
                // The endpoints are held to the same rule as the document
                // that carried them. Nothing else checks them: the
                // authorization endpoint is handed to the platform's URL
                // opener, so a metadata document naming `file:` or any scheme
                // with a registered handler would have this host open it. The
                // token endpoint is safer only by accident — the client
                // refuses a non-HTTP scheme — and accident is not a check.
                for (what, endpoint) in [
                    ("authorization_endpoint", &md.authorization_endpoint),
                    ("token_endpoint", &md.token_endpoint),
                ] {
                    let parsed = Url::parse(endpoint)
                        .with_context(|| format!("{issuer} named a {what} that is not a URL"))?;
                    require_secure(&parsed)
                        .with_context(|| format!("{issuer} named an unusable {what}"))?;
                }
                if let Some(reg) = &md.registration_endpoint {
                    let parsed = Url::parse(reg).with_context(|| {
                        format!("{issuer} named a registration_endpoint that is not a URL")
                    })?;
                    require_secure(&parsed).with_context(|| {
                        format!("{issuer} named an unusable registration_endpoint")
                    })?;
                }
                return Ok(md);
            }
            Err(e) => last = Some(e),
        }
    }
    bail!(
        "no authorization-server metadata at {} — {}",
        candidates
            .iter()
            .map(Url::as_str)
            .collect::<Vec<_>>()
            .join(" or "),
        last.map(|e| e.to_string())
            .unwrap_or_else(|| "no response".into())
    )
}

async fn fetch_json<T: serde::de::DeserializeOwned>(
    client: &hclient::Client,
    url: &Url,
) -> Result<T> {
    let resp = client
        .get(url.as_str())
        .header("accept", "application/json")
        .send()
        .await
        .with_context(|| format!("requesting {url}"))?;
    // Status before body, where it was read before: a metadata endpoint that
    // answers 404 with an HTML page must be reported as the 404, not as a JSON
    // parse failure.
    let status = resp.status();
    ensure!(status.is_success(), "{url} answered {status}");
    resp.collect()
        .await
        .with_context(|| format!("reading {url}"))?
        .json::<T>()
        .with_context(|| format!("{url} did not answer with the expected JSON"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn the_well_known_segment_goes_before_the_path() {
        // RFC 9728 §3.1. The inverted form is the common mistake and it fails
        // as a 404 that reads like "no discovery here".
        assert_eq!(
            protected_resource_url(&u("https://mcp.example.com/mcp"))
                .unwrap()
                .as_str(),
            "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
        );
        assert_eq!(
            protected_resource_url(&u("https://mcp.example.com"))
                .unwrap()
                .as_str(),
            "https://mcp.example.com/.well-known/oauth-protected-resource"
        );
        assert_eq!(
            protected_resource_url(&u("https://mcp.example.com/deep/path/"))
                .unwrap()
                .as_str(),
            "https://mcp.example.com/.well-known/oauth-protected-resource/deep/path"
        );
    }

    #[test]
    fn query_and_fragment_are_dropped() {
        // They are not part of a resource identifier, and carrying them into a
        // well-known request would leak whatever the component put there.
        assert_eq!(
            protected_resource_url(&u("https://x.example.com/mcp?tenant=acme#frag"))
                .unwrap()
                .as_str(),
            "https://x.example.com/.well-known/oauth-protected-resource/mcp"
        );
    }

    #[test]
    fn as_metadata_is_tried_rfc8414_then_oidc() {
        let urls = as_metadata_urls(&u("https://as.example.com")).unwrap();
        assert_eq!(
            urls.iter().map(Url::as_str).collect::<Vec<_>>(),
            [
                "https://as.example.com/.well-known/oauth-authorization-server",
                "https://as.example.com/.well-known/openid-configuration"
            ]
        );
    }

    #[test]
    fn an_issuer_with_a_path_keeps_it_after_the_well_known() {
        let urls = as_metadata_urls(&u("https://as.example.com/tenant1")).unwrap();
        assert_eq!(
            urls[0].as_str(),
            "https://as.example.com/.well-known/oauth-authorization-server/tenant1"
        );
    }

    /// The endpoints inside a metadata document reach two places that treat a
    /// URL as an instruction: the platform's URL opener, and the client. A scheme
    /// nobody checked is the difference between opening a browser and opening
    /// whatever `file:` or a custom handler is registered to.
    #[test]
    fn a_metadata_endpoint_with_a_dangerous_scheme_is_refused() {
        for bad in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "vscode://vscode.git/clone?url=x",
            "ftp://as.example.com/authorize",
        ] {
            assert!(
                require_secure(&Url::parse(bad).unwrap()).is_err(),
                "{bad} must not reach a URL opener"
            );
        }
    }

    /// The validations `fetch_*` performs after a document arrives.
    ///
    /// The end-to-end test serves correct documents, so these guards never run
    /// there — every one of them is a refusal that only fires against a server
    /// behaving badly, which is precisely when it matters.
    mod against_a_hostile_document {
        use super::*;

        async fn serve(routes: axum::Router) -> String {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", l.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(l, routes).await.unwrap() });
            base
        }

        #[tokio::test]
        async fn a_document_describing_a_different_resource_is_refused() {
            // The attack: a well-known location that redirects, or a host that
            // serves a neighbour's document. Following it would point the flow
            // at whatever authorization server the neighbour names.
            let base = serve(axum::Router::new().route(
                "/.well-known/oauth-protected-resource/mcp",
                axum::routing::get(|| async {
                    axum::Json(serde_json::json!({
                        "resource": "https://someone-else.example.com/mcp",
                        "authorization_servers": ["https://evil.example.com"],
                    }))
                }),
            ))
            .await;

            let err = fetch_resource_metadata(
                &crate::oauth::http_client().unwrap(),
                &Url::parse(&format!("{base}/mcp")).unwrap(),
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(err.contains("someone-else.example.com"), "{err}");
        }

        #[tokio::test]
        async fn a_document_naming_no_authorization_server_is_refused() {
            let base = serve(axum::Router::new().route(
                "/.well-known/oauth-protected-resource/mcp",
                axum::routing::get(|| async {
                    axum::Json(serde_json::json!({ "resource": "PLACEHOLDER" }))
                }),
            ))
            .await;
            // The document has to name itself correctly to get past the first
            // check, so the resource is patched in below by re-serving.
            let err = fetch_resource_metadata(
                &crate::oauth::http_client().unwrap(),
                &Url::parse(&format!("{base}/mcp")).unwrap(),
            )
            .await
            .unwrap_err()
            .to_string();
            // Either refusal is correct here; what must not happen is a flow
            // that proceeds with no server to talk to.
            assert!(
                err.contains("PLACEHOLDER") || err.contains("no authorization servers"),
                "{err}"
            );
        }

        #[tokio::test]
        async fn a_server_claiming_someone_elses_issuer_is_refused() {
            // RFC 8414 §3.3. This is the value the `iss` check later compares
            // against, so a lie accepted here would defeat the mix-up defence
            // downstream without any of it looking wrong.
            let base = serve(axum::Router::new().route(
                "/.well-known/oauth-authorization-server",
                axum::routing::get(|| async {
                    axum::Json(serde_json::json!({
                        "issuer": "https://as.example.com",
                        "authorization_endpoint": "https://as.example.com/authorize",
                        "token_endpoint": "https://as.example.com/token",
                    }))
                }),
            ))
            .await;

            let err = fetch_as_metadata(
                &crate::oauth::http_client().unwrap(),
                &Url::parse(&base).unwrap(),
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(err.contains("as.example.com"), "{err}");
        }

        #[tokio::test]
        async fn a_server_without_s256_is_refused_by_name() {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", l.local_addr().unwrap());
            let issuer = base.clone();
            let app = axum::Router::new().route(
                "/.well-known/oauth-authorization-server",
                axum::routing::get(move || {
                    let issuer = issuer.clone();
                    async move {
                        axum::Json(serde_json::json!({
                            "issuer": issuer,
                            "authorization_endpoint": format!("{issuer}/authorize"),
                            "token_endpoint": format!("{issuer}/token"),
                            "code_challenge_methods_supported": ["plain"],
                        }))
                    }
                }),
            );
            tokio::spawn(async move { axum::serve(l, app).await.unwrap() });

            let err = fetch_as_metadata(
                &crate::oauth::http_client().unwrap(),
                &Url::parse(&base).unwrap(),
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(err.contains("S256"), "say what is missing: {err}");
        }

        #[tokio::test]
        async fn a_server_naming_a_file_endpoint_is_refused_before_anything_opens() {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", l.local_addr().unwrap());
            let issuer = base.clone();
            let app = axum::Router::new().route(
                "/.well-known/oauth-authorization-server",
                axum::routing::get(move || {
                    let issuer = issuer.clone();
                    async move {
                        axum::Json(serde_json::json!({
                            "issuer": issuer,
                            "authorization_endpoint": "file:///etc/passwd",
                            "token_endpoint": format!("{issuer}/token"),
                        }))
                    }
                }),
            );
            tokio::spawn(async move { axum::serve(l, app).await.unwrap() });

            let err = fetch_as_metadata(
                &crate::oauth::http_client().unwrap(),
                &Url::parse(&base).unwrap(),
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(
                err.contains("authorization_endpoint"),
                "name which endpoint: {err}"
            );
        }
    }

    #[test]
    fn plain_http_is_refused_except_on_loopback() {
        assert!(protected_resource_url(&u("http://api.example.com/mcp")).is_err());
        assert!(as_metadata_urls(&u("http://as.example.com")).is_err());
        // The exception, and its whole extent.
        assert!(protected_resource_url(&u("http://127.0.0.1:8080/mcp")).is_ok());
        assert!(protected_resource_url(&u("http://localhost:8080/mcp")).is_ok());
        // Not "anything that looks local".
        assert!(protected_resource_url(&u("http://localhost.evil.test/mcp")).is_err());
        assert!(protected_resource_url(&u("http://192.168.1.10/mcp")).is_err());
    }
}
