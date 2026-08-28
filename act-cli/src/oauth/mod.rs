//! The OAuth 2.1 authorization-code flow `act login` runs for a
//! `std:oauth2`-typed field (design §5.4).
//!
//! ## What the host derives, and what it is told
//!
//! A component supplies a **resource identifier** and a scope list, and nothing
//! else (design §5.5). Every address the host contacts is derived from that
//! identifier's own RFC 9728 well-known location — never from a URL the
//! component wrote. A component that could name the authorization server could
//! steer a user's browser at its own, collect the credential there, and the
//! user would see a normal-looking consent screen. So `resource` is treated as
//! an identifier and the domain the user is about to visit is printed before a
//! browser opens.
//!
//! ## Layering
//!
//! [`pkce`], [`state`] and [`issuer`] are pure and unit-tested against their
//! RFCs. [`discovery`] and [`registration`] speak HTTP but hold no state.
//! [`listener`] owns the loopback socket. [`run`] is the only part that needs
//! all of them, and it is the only part a test cannot run without a server.
//!
//! ## Not here yet
//!
//! **Silent refresh.** `get-secret` returning a token that is valid *now*,
//! refreshing first when it is near expiry, is the operational half of §5.4 and
//! is deliberately separate: it needs a per-key lock, an advisory file lock
//! around the store's read-modify-write, and a re-read after acquisition,
//! because two live sessions against one upstream refreshing at once is routine
//! and rotation makes one of them invalidate the other. Acquisition is
//! self-contained; refresh is not, and mixing them would hide the concurrency
//! work inside a feature that looks finished.

pub mod discovery;
pub mod issuer;
pub mod listener;
pub mod pkce;
pub mod refresh;
pub mod refresher;
pub mod registration;
pub mod run;
pub mod state;

/// The flow's HTTP client.
///
/// One constructor, because a flow that discovered metadata over one stack and
/// exchanged a code over another would be two security postures wearing one
/// name. `hclient` keeps the runtime, TLS and resolver as separate seams rather
/// than picking for you: this is the host's pick — tokio, rustls over the
/// webpki root set, the system resolver.
///
/// Webpki roots rather than the platform store: an authorization server is on
/// the public web and the bundled set is identical on every machine, so a CI
/// image with an empty system store cannot make a login fail here and nowhere
/// else.
pub(crate) fn http_client() -> anyhow::Result<hclient::Client> {
    // One home for this choice, in the lowest crate that needs it — see its
    // doc comment for why two rustls providers are in this graph at all.
    act_store::fetch::install_crypto_provider();

    let transport = hclient_native::Native::new(
        hclient_rt_tokio::Tokio,
        hclient_tls_rustls::Rustls::with_webpki_roots(),
        hclient_dns_system::SystemDns::new(hclient_rt_tokio::Tokio),
    );
    hclient::Client::builder(transport)
        .user_agent(http::HeaderValue::from_static(concat!(
            "act/",
            env!("CARGO_PKG_VERSION")
        )))
        .build()
        .map_err(|e| anyhow::anyhow!("the HTTP backend cannot serve this configuration: {e}"))
}

/// Bytes from the OS CSPRNG.
///
/// Every unguessable value in this flow comes through here: the PKCE verifier,
/// `state`, and the one-time callback path. `getrandom` rather than a seeded
/// PRNG — a `state` an attacker can predict is a CSRF hole, and the OS is the
/// one source with no seeding question to get wrong.
pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], anyhow::Error> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf)
        .map_err(|e| anyhow::anyhow!("the OS random source is unavailable: {e}"))?;
    Ok(buf)
}

/// URL-safe base64 without padding — what every value in this flow is spelled
/// in (RFC 7636 §4.1 for the verifier, and the same alphabet keeps `state` and
/// the callback path free of anything needing escaping in a URL).
pub(crate) fn b64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
