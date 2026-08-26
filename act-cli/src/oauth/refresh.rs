//! Silent refresh: a `get-secret` returns a token valid **now**, renewing it
//! first when it is close to expiry (design §5.4).
//!
//! The component never learns this happened. It asked for a credential and got
//! one that works; it never sees a refresh token, and it never has to re-open a
//! session because one expired.
//!
//! **When** to renew is not decided here: that reads a stored value's
//! `std:expires-at` and belongs to the crate that owns the stored shape
//! (`act_credentials::expiry`), because the host runtime makes that call on
//! every `get-secret` and holds no opinion about OAuth. This module is the
//! protocol half — what a renewal *is*.
//!
//! ## What is renewed, and what is not
//!
//! Exactly one field: the `std:oauth2`-typed one whose value is near expiry.
//! Sibling fields — a tenant id, an account identifier — are not in scope, so
//! "refresh silently dropped the tenant id" is a bug this shape cannot express
//! rather than one an implementer has to remember not to write.
//!
//! ## Why the endpoint is re-derived rather than stored
//!
//! What the record keeps is the **issuer**, not a token endpoint. Re-running
//! discovery at refresh time costs one request against a credential that is
//! renewed rarely, and buys two things: the endpoint cannot go stale if the
//! server moves it, and every validation in [`super::discovery`] runs again —
//! the issuer match, the scheme checks — against a document that could have
//! changed since the credential was acquired.

use anyhow::{Context, Result, ensure};

use super::discovery;
use super::registration::Registration;
use super::run::Acquired;

/// Exchange a refresh token for a new access token.
///
/// Returns the same shape acquisition does, so the two paths write a record the
/// same way and cannot drift in what they store.
pub async fn refresh(
    client: &reqwest::Client,
    issuer: &str,
    reg: &Registration,
    refresh_token: &str,
    now: u64,
) -> Result<Acquired> {
    let issuer_url = url::Url::parse(issuer)
        .with_context(|| format!("the stored issuer '{issuer}' is not a URL"))?;
    let as_md = discovery::fetch_as_metadata(client, &issuer_url)
        .await
        .with_context(|| format!("rediscovering {issuer} to refresh"))?;

    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "refresh_token")
        .append_pair("refresh_token", refresh_token)
        .append_pair("client_id", &reg.client_id)
        .finish();
    let body = match &reg.client_secret {
        Some(secret) => format!(
            "{body}&{}",
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair("client_secret", secret)
                .finish()
        ),
        None => body,
    };

    let resp = client
        .post(&as_md.token_endpoint)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .with_context(|| format!("refreshing at {}", as_md.token_endpoint))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    // The body is never quoted back: a token-endpoint error can echo the
    // request, and the request carries the refresh token.
    ensure!(
        status.is_success(),
        "{} refused the refresh with {status}",
        as_md.token_endpoint
    );

    let parsed: RefreshResponse = serde_json::from_str(&text)
        .with_context(|| format!("{} did not answer with a token", as_md.token_endpoint))?;
    Ok(Acquired {
        issuer: issuer.to_string(),
        expires_at: parsed.expires_in.map(|s| now + s),
        scopes: parsed
            .scope
            .map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default(),
        // RFC 6749 §6: a server MAY issue a new refresh token, and one that
        // rotates invalidates the old. Keeping the old on rotation is how a
        // credential dies at the *next* refresh, long after the change that
        // caused it — so an absent one means "keep what we had", and a present
        // one always replaces.
        refresh_token: parsed.refresh_token,
        access_token: parsed.access_token,
    })
}

#[derive(serde::Deserialize)]
struct RefreshResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}
