//! The flow, end to end (design §5.4).
//!
//! The order is the security property. Discovery derives every address from the
//! resource identifier; the user is shown the domain before a browser opens;
//! the `iss` check runs at the callback, **before** the code is transmitted to
//! any token endpoint. A rearrangement that moves the check after the exchange
//! passes its own unit test and defends nothing.

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use std::path::Path;
use url::Url;

use super::discovery::{self, AsMetadata};
use super::issuer::{self, Expected};
use super::listener::Listener;
use super::pkce::Pkce;
use super::registration::{self, ClientStore};
use super::state::Pending;

/// What the flow was asked to obtain.
pub struct Request<'a> {
    /// The resource identifier from the field's declaration. An identifier, not
    /// an address: nothing here is fetched from it directly (design §5.5).
    pub resource: &'a str,
    /// Scopes from the declaration; empty means "whatever the server offers".
    pub scopes: &'a [String],
    /// A fixed callback port for a pre-registered client. `None` takes an
    /// ephemeral one, which is what DCR registrations expect.
    pub port: Option<u16>,
    /// Where client registrations live — beside the credential store.
    pub store_root: &'a Path,
    /// How the authorization URL reaches a browser. `None` is the real thing:
    /// print it, then hand it to the platform opener.
    ///
    /// Injectable because a flow with no way to visit its own authorization URL
    /// cannot be tested end to end, and the parts that matter — `state`, the
    /// `iss` check, the exchange — only run on the way back from one. A test
    /// supplies a closure that fetches the URL itself.
    pub open_with: Option<Box<dyn FnOnce(String) + Send>>,
}

/// What it obtained. Shaped for `ACT-CONSTANTS.md` §8.3 plus the host-only half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acquired {
    pub access_token: String,
    /// Unix seconds, when the server said. Absent means "no known expiry",
    /// which §8.3 has consumers read as never expiring — so it is only ever set
    /// from a real `expires_in`.
    pub expires_at: Option<u64>,
    pub scopes: Vec<String>,
    /// Never projected to a component: it lives in the record's host-only
    /// compartment and is what silent refresh uses.
    pub refresh_token: Option<String>,
    /// The authorization server this came from, recorded beside the refresh
    /// token. Refresh re-derives the token endpoint from it rather than storing
    /// one, so the endpoint cannot go stale and every discovery validation runs
    /// again.
    pub issuer: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
    /// RFC 6749 §5.1: space-delimited, and present only when it differs from
    /// what was requested.
    #[serde(default)]
    scope: Option<String>,
}

/// Run it. `now` is injected so a test can pin `expires_at` without waiting.
pub async fn acquire(req: Request<'_>, now: u64) -> Result<Acquired> {
    let resource = Url::parse(req.resource).with_context(|| {
        format!(
            "'{}' is not a URL, so it cannot be a resource identifier",
            req.resource
        )
    })?;
    let client = super::http_client().context("building the HTTP client for the OAuth flow")?;

    // 1-2. Everything downstream is derived from here.
    let resource_md = discovery::fetch_resource_metadata(&client, &resource).await?;
    let as_url = Url::parse(&resource_md.authorization_servers[0]).with_context(|| {
        format!(
            "{} names an authorization server that is not a URL",
            resource_md.resource
        )
    })?;
    let as_md = discovery::fetch_as_metadata(&client, &as_url).await?;

    // 4. Bind before registering: the redirect has to be known to register it.
    let listener = Listener::bind(req.port).await?;
    let registered_redirect = match req.port {
        // A fixed port means a pre-registered client, whose redirect must match
        // what was registered exactly — port included.
        Some(_) => listener.redirect_uri(),
        None => Listener::registered_redirect_uri(),
    };

    // 3. One registration per issuer (SEP-2352).
    let mut clients = ClientStore::load(req.store_root)?;
    let reg = match clients.get(&as_md.issuer, &registered_redirect) {
        Some(existing) => existing.clone(),
        None => {
            let endpoint = as_md.registration_endpoint.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "{} supports no dynamic client registration, and this host has no \
                     pre-registered client for it",
                    as_md.issuer
                )
            })?;
            let fresh = registration::register(&client, endpoint, &registered_redirect).await?;
            clients.insert(&as_md.issuer, fresh.clone());
            clients.save(req.store_root)?;
            fresh
        }
    };

    // 5. The authorization request.
    let pending = Pending::generate()?;
    let pkce = Pkce::generate()?;
    let scopes = effective_scopes(req.scopes, &resource_md.scopes_supported, &as_md);
    let auth_url = authorization_url(
        &as_md,
        &reg.client_id,
        &listener.redirect_uri(),
        &pending,
        &pkce,
        &scopes,
        &resource_md.resource,
    )?;

    // The domain the user is about to visit, before they visit it. This is the
    // whole defence against authorization-server substitution being invisible:
    // the host derived it, and the user gets to see what was derived.
    eprintln!("Authorizing with {}", host_of(&auth_url));
    if !scopes.is_empty() {
        eprintln!("Requesting scopes: {}", scopes.join(" "));
    }
    // Checked again here, at the point of use. `fetch_as_metadata` refuses a
    // bad scheme in the document, but this is the line that hands a URL to the
    // platform's opener, and a guard one call away from what it protects is a
    // guard a refactor moves.
    discovery::require_secure_url(&auth_url).context("refusing to open an authorization URL")?;
    match req.open_with {
        Some(open) => open(auth_url.to_string()),
        None => {
            eprintln!("Opening your browser. If it does not open, visit:\n  {auth_url}");
            open_browser(auth_url.as_str());
        }
    }

    // 6. Callback, then the checks, then the exchange.
    let cb = listener.accept(&pending).await?;
    if let Some(error) = &cb.error {
        let detail = cb
            .error_description
            .as_deref()
            .map(|d| format!(": {d}"))
            .unwrap_or_default();
        bail!("the authorization server refused: {error}{detail}");
    }
    let returned_state = cb.state.as_deref().unwrap_or_default();
    ensure!(
        pending.state_matches(returned_state),
        "the callback's 'state' does not match the authorization request — \
         refusing to send the code, since a mismatched state is what a forged \
         callback looks like"
    );
    issuer::check(
        &Expected {
            issuer: as_md.issuer.clone(),
            advertises_iss: as_md.authorization_response_iss_parameter_supported,
        },
        cb.iss.as_deref(),
    )?;
    let code = cb
        .code
        .ok_or_else(|| anyhow::anyhow!("the callback carried neither a code nor an error"))?;

    let token = exchange(
        &client,
        &as_md,
        &reg,
        &code,
        &listener.redirect_uri(),
        &pkce,
        &resource_md.resource,
    )
    .await?;

    Ok(Acquired {
        issuer: as_md.issuer.clone(),
        expires_at: token.expires_in.map(|s| now + s),
        scopes: token
            .scope
            .map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or(scopes),
        refresh_token: token.refresh_token,
        access_token: token.access_token,
    })
}

/// Declared scopes win; otherwise take what the resource or the server offers.
///
/// Asking for everything a server supports would be the wrong default — a
/// credential should carry the reach the component declared it needs — but a
/// declaration with no scopes has to ask for something, and the resource's own
/// `scopes_supported` is the narrower of the two available answers.
fn effective_scopes(declared: &[String], resource: &[String], as_md: &AsMetadata) -> Vec<String> {
    if !declared.is_empty() {
        return declared.to_vec();
    }
    if !resource.is_empty() {
        return resource.to_vec();
    }
    as_md.scopes_supported.clone()
}

#[allow(clippy::too_many_arguments)]
fn authorization_url(
    as_md: &AsMetadata,
    client_id: &str,
    redirect_uri: &str,
    pending: &Pending,
    pkce: &Pkce,
    scopes: &[String],
    resource: &str,
) -> Result<Url> {
    let mut url = Url::parse(&as_md.authorization_endpoint)
        .with_context(|| format!("'{}' is not a URL", as_md.authorization_endpoint))?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", client_id);
        q.append_pair("redirect_uri", redirect_uri);
        q.append_pair("state", pending.state());
        q.append_pair("code_challenge", pkce.challenge());
        q.append_pair("code_challenge_method", "S256");
        // RFC 8707. Without it a server that serves several resources may issue
        // a token valid at all of them, which is a wider credential than asked
        // for and one the user cannot see is wider.
        q.append_pair("resource", resource);
        if !scopes.is_empty() {
            q.append_pair("scope", &scopes.join(" "));
        }
    }
    Ok(url)
}

async fn exchange(
    client: &hclient::Client,
    as_md: &AsMetadata,
    reg: &registration::Registration,
    code: &str,
    redirect_uri: &str,
    pkce: &Pkce,
    resource: &str,
) -> Result<TokenResponse> {
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", reg.client_id.as_str()),
        ("code_verifier", pkce.verifier()),
        ("resource", resource),
    ];
    if let Some(secret) = &reg.client_secret {
        form.push(("client_secret", secret.as_str()));
    }
    // RFC 6749 §4.1.3. `form` sets the content type itself, and only if the
    // caller has not.
    let resp = client
        .post(&as_md.token_endpoint)
        .form(form)
        .send()
        .await
        .with_context(|| format!("exchanging the code at {}", as_md.token_endpoint))?;
    let status = resp.status();
    let text = resp
        .collect()
        .await
        .map(|c| c.text().unwrap_or_default())
        .unwrap_or_default();
    // The body is not quoted back: a token-endpoint error can echo the request,
    // and the request carries the code and the verifier.
    ensure!(
        status.is_success(),
        "{} refused the code exchange with {status}",
        as_md.token_endpoint
    );
    serde_json::from_str(&text)
        .with_context(|| format!("{} did not answer with a token", as_md.token_endpoint))
}

fn host_of(url: &Url) -> String {
    url.host_str().unwrap_or("an unknown host").to_string()
}

/// Best effort, and never fatal: the URL was printed first, so a failure here
/// costs a copy-paste rather than the login.
///
/// `webbrowser` with its `hardened` feature, which refuses anything that is not
/// an http(s) URL. That is the check that matters here — this is the one place
/// in the flow where a URL is not fetched but **dispatched by scheme**, so a
/// `file:` or a registered custom handler in a discovered server's metadata
/// would be opened by whatever claims it. The flow validates the scheme too
/// (twice, at discovery and at the point of use); having the opener refuse it
/// as well means no future path into it can reintroduce the hole.
fn open_browser(url: &str) {
    if let Err(e) = webbrowser::open(url) {
        // Said out loud rather than swallowed: on a headless box or over SSH
        // there may be no browser at all, and an operator staring at a prompt
        // that never returns should know the URL above is theirs to open.
        eprintln!("act: could not open a browser ({e}); open the URL above yourself.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn as_md() -> AsMetadata {
        AsMetadata {
            issuer: "https://as.example.com".into(),
            authorization_endpoint: "https://as.example.com/authorize".into(),
            token_endpoint: "https://as.example.com/token".into(),
            registration_endpoint: Some("https://as.example.com/register".into()),
            scopes_supported: vec!["read".into(), "write".into()],
            code_challenge_methods_supported: vec!["S256".into()],
            authorization_response_iss_parameter_supported: true,
        }
    }

    #[test]
    fn the_authorization_url_carries_pkce_state_and_the_resource() {
        let p = Pending::generate().unwrap();
        let k = Pkce::generate().unwrap();
        let url = authorization_url(
            &as_md(),
            "cid",
            "http://127.0.0.1:5000/callback",
            &p,
            &k,
            &["read".to_string()],
            "https://api.example.com/mcp",
        )
        .unwrap();
        let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["client_id"], "cid");
        assert_eq!(q["redirect_uri"], "http://127.0.0.1:5000/callback");
        assert_eq!(q["state"], p.state());
        assert_eq!(q["code_challenge"], k.challenge());
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["scope"], "read");
        // RFC 8707: without it the token may be valid at every resource the
        // server serves, which is wider than what was asked for.
        assert_eq!(q["resource"], "https://api.example.com/mcp");
        // The verifier is what proves the exchange belongs to this request; it
        // must never travel in the URL the browser follows.
        assert!(
            !url.as_str().contains(k.verifier()),
            "the verifier leaked into the authorization URL"
        );
    }

    #[test]
    fn declared_scopes_win_then_the_resource_then_the_server() {
        let md = as_md();
        assert_eq!(
            effective_scopes(&["a".to_string()], &["b".to_string()], &md),
            ["a"],
            "a declaration is the component saying what it needs"
        );
        assert_eq!(
            effective_scopes(&[], &["b".to_string()], &md),
            ["b"],
            "then the resource's own list, which is the narrower of what is left"
        );
        assert_eq!(
            effective_scopes(&[], &[], &md),
            ["read", "write"],
            "and only then everything the server offers"
        );
    }

    #[test]
    fn a_url_with_no_scope_omits_the_parameter_rather_than_sending_an_empty_one() {
        // `scope=` is not the same as no scope: some servers read it as a
        // request for none and issue a token that can do nothing.
        let url = authorization_url(
            &as_md(),
            "cid",
            "http://127.0.0.1:5000/callback",
            &Pending::generate().unwrap(),
            &Pkce::generate().unwrap(),
            &[],
            "https://api.example.com/mcp",
        )
        .unwrap();
        assert!(!url.query().unwrap().contains("scope="), "{url}");
    }
}

/// The flow against a mock authorization server, end to end.
///
/// A binary crate cannot be reached from `tests/`, so this lives here. It is
/// the only test that runs discovery, registration, the browser hop, the
/// callback, the checks and the exchange in one piece — every unit test above
/// covers a part in isolation, and a flow assembled wrongly passes all of them.
///
/// The mock verifies PKCE the way a real server does: `/authorize` remembers
/// the challenge, `/token` recomputes `S256(verifier)` and refuses a mismatch.
/// Without that the test would prove the parameters were *sent*, not that they
/// were right.
#[cfg(test)]
mod e2e {
    use super::*;
    use axum::extract::{Query, State};
    use axum::response::{IntoResponse, Redirect};
    use axum::routing::{get, post};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Mock {
        /// code → the challenge presented at /authorize.
        issued: Mutex<HashMap<String, String>>,
        base: Mutex<String>,
        /// Set when /token was reached, so a test can tell "never exchanged"
        /// from "exchanged and refused".
        exchanged: Mutex<bool>,
    }

    async fn spawn_mock() -> (Arc<Mock>, String) {
        let mock = Arc::new(Mock::default());
        let app = axum::Router::new()
            .route(
                "/.well-known/oauth-protected-resource/mcp",
                get(|State(m): State<Arc<Mock>>| async move {
                    let base = m.base.lock().unwrap().clone();
                    axum::Json(serde_json::json!({
                        "resource": format!("{base}/mcp"),
                        "authorization_servers": [base],
                        "scopes_supported": ["read"],
                    }))
                }),
            )
            .route(
                "/.well-known/oauth-authorization-server",
                get(|State(m): State<Arc<Mock>>| async move {
                    let base = m.base.lock().unwrap().clone();
                    axum::Json(serde_json::json!({
                        "issuer": base,
                        "authorization_endpoint": format!("{base}/authorize"),
                        "token_endpoint": format!("{base}/token"),
                        "registration_endpoint": format!("{base}/register"),
                        "scopes_supported": ["read", "write"],
                        "code_challenge_methods_supported": ["S256"],
                        "authorization_response_iss_parameter_supported": true,
                    }))
                }),
            )
            .route(
                "/register",
                post(|body: String| async move {
                    // A native app registering a loopback redirect (SEP-837).
                    assert!(body.contains("\"application_type\":\"native\""), "{body}");
                    assert!(body.contains("127.0.0.1"), "{body}");
                    axum::Json(serde_json::json!({ "client_id": "test-client" }))
                }),
            )
            .route(
                "/authorize",
                get(
                    |State(m): State<Arc<Mock>>, Query(q): Query<HashMap<String, String>>| async move {
                        assert_eq!(q["code_challenge_method"], "S256");
                        assert_eq!(q["response_type"], "code");
                        let code = "code-for-this-flow".to_string();
                        m.issued
                            .lock()
                            .unwrap()
                            .insert(code.clone(), q["code_challenge"].clone());
                        let base = m.base.lock().unwrap().clone();
                        Redirect::to(&format!(
                            "{}?code={code}&state={}&iss={}",
                            q["redirect_uri"],
                            urlencoding(&q["state"]),
                            urlencoding(&base),
                        ))
                        .into_response()
                    },
                ),
            )
            .route(
                "/token",
                post(|State(m): State<Arc<Mock>>, body: String| async move {
                    *m.exchanged.lock().unwrap() = true;
                    let form: HashMap<String, String> =
                        url::form_urlencoded::parse(body.as_bytes())
                            .map(|(k, v)| (k.into_owned(), v.into_owned()))
                            .collect();
                    // What PKCE is for: the verifier must hash to the challenge
                    // presented when the code was issued.
                    let expected = m.issued.lock().unwrap().get(&form["code"]).cloned();
                    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
                    use sha2::Digest;
                    let got = super::super::b64url(&sha2::Sha256::digest(verifier.as_bytes()));
                    assert_eq!(expected.as_deref(), Some(got.as_str()), "PKCE mismatch");
                    assert_eq!(form["grant_type"], "authorization_code");
                    assert_eq!(form["client_id"], "test-client");
                    // RFC 8707 — the token is bound to the resource asked for.
                    assert!(form["resource"].ends_with("/mcp"), "{:?}", form["resource"]);
                    axum::Json(serde_json::json!({
                        "access_token": "the-access-token",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "refresh_token": "the-refresh-token",
                        "scope": "read",
                    }))
                }),
            )
            .with_state(mock.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        *mock.base.lock().unwrap() = base.clone();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (mock, base)
    }

    fn urlencoding(s: &str) -> String {
        url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
    }

    /// A closure that plays the browser: fetch the authorization URL and follow
    /// the redirect, which is what delivers the callback to the loopback
    /// listener.
    fn browser() -> Box<dyn FnOnce(String) + Send> {
        Box::new(|url: String| {
            tokio::spawn(async move {
                let _ = crate::oauth::http_client().unwrap().get(&url).send().await;
            });
        })
    }

    #[tokio::test]
    async fn the_whole_flow_against_a_mock_authorization_server() {
        let (mock, base) = spawn_mock().await;
        let dir = tempfile::tempdir().unwrap();

        let acquired = acquire(
            Request {
                resource: &format!("{base}/mcp"),
                scopes: &["read".to_string()],
                port: None,
                store_root: dir.path(),
                open_with: Some(browser()),
            },
            1_700_000_000,
        )
        .await
        .expect("the flow completes");

        assert_eq!(acquired.access_token, "the-access-token");
        assert_eq!(
            acquired.expires_at,
            Some(1_700_000_000 + 3600),
            "expires_in is turned into an absolute expiry against the injected clock"
        );
        assert_eq!(acquired.scopes, ["read"]);
        assert_eq!(
            acquired.refresh_token.as_deref(),
            Some("the-refresh-token"),
            "kept for refresh, and never projected to a component"
        );
        assert!(*mock.exchanged.lock().unwrap());

        // The registration was persisted, so a second login reuses it rather
        // than minting a second client identity for the same issuer.
        let clients = ClientStore::load(dir.path()).unwrap();
        assert!(
            clients
                .get(
                    &base,
                    &super::super::listener::Listener::registered_redirect_uri()
                )
                .is_some(),
            "the registration is keyed by issuer (SEP-2352)"
        );
    }

    /// The mix-up defence, exercised where it matters: the code must not reach
    /// the token endpoint at all.
    #[tokio::test]
    async fn a_callback_from_another_issuer_never_reaches_the_token_endpoint() {
        let (mock, base) = spawn_mock().await;
        let dir = tempfile::tempdir().unwrap();

        // A browser that arrives with a valid-looking callback claiming a
        // different issuer — what a mix-up produces.
        let forged: Box<dyn FnOnce(String) + Send> = Box::new(|url: String| {
            tokio::spawn(async move {
                let parsed = Url::parse(&url).unwrap();
                let q: HashMap<_, _> = parsed.query_pairs().into_owned().collect();
                let cb = format!(
                    "{}?code=stolen&state={}&iss=https%3A%2F%2Fevil.example.com",
                    q["redirect_uri"], q["state"]
                );
                let _ = crate::oauth::http_client().unwrap().get(&cb).send().await;
            });
        });

        let err = acquire(
            Request {
                resource: &format!("{base}/mcp"),
                scopes: &[],
                port: None,
                store_root: dir.path(),
                open_with: Some(forged),
            },
            1_700_000_000,
        )
        .await
        .expect_err("a foreign issuer must be refused");

        assert!(err.to_string().contains("evil.example.com"), "{err}");
        assert!(
            !*mock.exchanged.lock().unwrap(),
            "the code must never have been transmitted"
        );
    }

    /// A discovered server naming a scheme the platform would hand to a
    /// registered handler.
    ///
    /// This is the one place in the flow where a URL is not fetched but
    /// *executed* — `xdg-open`/`open`/`explorer` dispatch on scheme — so the
    /// check has to be on the way in, before anything opens.
    #[tokio::test]
    async fn an_authorization_endpoint_with_a_dangerous_scheme_never_opens() {
        let (_mock, base) = spawn_mock().await;

        // The mock serves a normal document; this test drives the validation
        // directly against the shape a hostile one would have, because the
        // failure must happen before any listener or browser is involved.
        let md = AsMetadata {
            issuer: base.clone(),
            authorization_endpoint: "file:///etc/passwd".into(),
            token_endpoint: format!("{base}/token"),
            registration_endpoint: None,
            scopes_supported: vec![],
            code_challenge_methods_supported: vec!["S256".into()],
            authorization_response_iss_parameter_supported: true,
        };
        let url = authorization_url(
            &md,
            "cid",
            "http://127.0.0.1:5000/callback",
            &Pending::generate().unwrap(),
            &Pkce::generate().unwrap(),
            &[],
            "https://api.example.com/mcp",
        )
        .unwrap();
        let err = discovery::require_secure_url(&url).unwrap_err().to_string();
        assert!(err.contains("not https"), "{err}");
    }

    /// The same, for `state`: a forged callback that guesses nothing.
    #[tokio::test]
    async fn a_callback_with_the_wrong_state_never_reaches_the_token_endpoint() {
        let (mock, base) = spawn_mock().await;
        let dir = tempfile::tempdir().unwrap();

        let forged: Box<dyn FnOnce(String) + Send> = Box::new(|url: String| {
            tokio::spawn(async move {
                let parsed = Url::parse(&url).unwrap();
                let q: HashMap<_, _> = parsed.query_pairs().into_owned().collect();
                let cb = format!("{}?code=stolen&state=not-the-state", q["redirect_uri"]);
                let _ = crate::oauth::http_client().unwrap().get(&cb).send().await;
            });
        });

        let err = acquire(
            Request {
                resource: &format!("{base}/mcp"),
                scopes: &[],
                port: None,
                store_root: dir.path(),
                open_with: Some(forged),
            },
            1_700_000_000,
        )
        .await
        .expect_err("a mismatched state must be refused");

        assert!(err.to_string().contains("state"), "{err}");
        assert!(!*mock.exchanged.lock().unwrap());
    }
}
