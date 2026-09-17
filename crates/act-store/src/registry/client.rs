//! Manifest and token requests over `hclient`.

use super::auth::{Challenge, pull_scope};
use crate::store::StoreError;

/// The media types a component manifest may arrive as, in `Accept` order.
pub const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.v2+json, \
     application/vnd.oci.image.index.v1+json";

fn io(e: impl std::fmt::Display) -> StoreError {
    StoreError::Io(std::io::Error::other(e.to_string()))
}

/// Exchange a challenge for a bearer token.
///
/// `None` when the registry answers without one, which is not an error: an
/// anonymous-readable registry may return `200` to the retried request anyway,
/// and refusing here would turn a working pull into a failure.
pub async fn fetch_token(
    http: &hclient::Client,
    challenge: &Challenge,
) -> Result<Option<String>, StoreError> {
    let resp = http.get(challenge.token_url()).send().await.map_err(io)?;
    if !resp.status().is_success() {
        return Ok(None);
    }
    let body = resp.collect().await.map_err(io)?;
    let text = body.text().unwrap_or_default();
    Ok(token_from_response(&text))
}

/// Read the token out of a token-endpoint response.
///
/// **`token` first, `access_token` second, and both are optional.** The
/// distribution spec names `token`; the OAuth2 profile names `access_token`;
/// registries disagree about which to send. Measured: `ghcr.io` sends `token`
/// alone, `actpkg.dev` sends both. Requiring either one by itself would break
/// against half the registries this host talks to.
pub fn token_from_response(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let pick = |k: &str| {
        v.get(k)
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    pick("token").or_else(|| pick("access_token"))
}

/// GET a manifest, doing the token dance once if the registry asks for it.
///
/// Returns the raw bytes and the digest the registry computed, alongside the
/// token — callers need the token again for the blob GETs that follow, and
/// acquiring it twice would double the round trips to the token endpoint.
pub async fn fetch_manifest(
    http: &hclient::Client,
    registry: &str,
    repository: &str,
    reference: &str,
) -> Result<(Vec<u8>, String, Option<String>), StoreError> {
    let url = format!("https://{registry}/v2/{repository}/manifests/{reference}");

    let first = http
        .get(&url)
        .header("accept", MANIFEST_ACCEPT)
        .send()
        .await
        .map_err(io)?;

    // `401` is the expected first answer from an authenticating registry, not
    // a failure: the challenge it carries is how the token is obtained.
    // Compared numerically rather than against `http::StatusCode`: this crate
    // does not depend on `http`, and adding it for one constant would be a
    // dependency bought for a name.
    let (resp, token) = if first.status().as_u16() == 401 {
        let challenge = first
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .and_then(Challenge::parse)
            .ok_or_else(|| {
                io(format!(
                    "{registry} refused {repository} without a usable Bearer challenge"
                ))
            })?;
        // The registry's own scope when it named one; ours otherwise, since a
        // token request without a scope yields one good for nothing.
        let challenge = Challenge {
            scope: challenge.scope.or_else(|| Some(pull_scope(repository))),
            ..challenge
        };
        let token = fetch_token(http, &challenge).await?;
        let mut req = http.get(&url).header("accept", MANIFEST_ACCEPT);
        if let Some(t) = &token {
            req = req.header("authorization", &format!("Bearer {t}"));
        }
        (req.send().await.map_err(io)?, token)
    } else {
        (first, None)
    };

    if !resp.status().is_success() {
        return Err(io(format!(
            "HTTP {} fetching manifest {registry}/{repository}:{reference}",
            resp.status()
        )));
    }

    // The registry states the digest it computed; trusting our own hash of the
    // bytes instead would paper over a transport that altered them.
    let digest = resp
        .headers()
        .get("docker-content-digest")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let bytes = resp.collect().await.map_err(io)?.bytes().to_vec();
    let digest = digest.unwrap_or_else(|| format!("sha256:{}", crate::layout::sha256_hex(&bytes)));

    Ok((bytes, digest, token))
}

/// GET the referrers index for `digest`.
///
/// `Ok(None)` when the registry does not implement the API or has nothing to
/// say. Referrer collection is best-effort by design — a signature that cannot
/// be fetched must not fail the component pull that carries it — so the
/// distinction that matters to the caller is "index or not", and the reason is
/// logged rather than returned.
pub async fn fetch_referrers(
    http: &hclient::Client,
    reg: &super::reference::ParsedRef,
    digest: &str,
    token: Option<&str>,
) -> Option<oci_spec::image::ImageIndex> {
    let url = format!(
        "https://{}/v2/{}/referrers/{digest}",
        reg.registry, reg.repository
    );
    let mut req = http.get(&url);
    if let Some(t) = token {
        req = req.header("authorization", &format!("Bearer {t}"));
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(%url, error = %e, "referrers request failed");
            return None;
        }
    };
    // A registry without the API answers 404; that is the documented way to
    // say "not supported", not a failure to report.
    if !resp.status().is_success() {
        tracing::debug!(%url, status = resp.status().as_u16(), "no referrers");
        return None;
    }
    let body = resp.collect().await.ok()?;
    match serde_json::from_slice(body.bytes()) {
        Ok(index) => Some(index),
        Err(e) => {
            tracing::debug!(%url, error = %e, "referrers index did not parse");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both shapes seen on the wire. `ghcr.io` sends `token` alone;
    /// `actpkg.dev` sends both. A reader that required `access_token` would
    /// fail against the first, and one that required `token` against a
    /// registry following the OAuth2 profile.
    #[test]
    fn a_token_is_read_under_either_name() {
        assert_eq!(
            token_from_response(r#"{"token":"abc"}"#).as_deref(),
            Some("abc")
        );
        assert_eq!(
            token_from_response(r#"{"access_token":"xyz"}"#).as_deref(),
            Some("xyz")
        );
        // Both present and disagreeing: `token` is the distribution spec's
        // name, so it wins.
        assert_eq!(
            token_from_response(r#"{"token":"a","access_token":"b"}"#).as_deref(),
            Some("a")
        );
    }

    #[test]
    fn a_response_with_no_token_is_none_rather_than_an_error() {
        assert!(token_from_response(r#"{"expires_in":300}"#).is_none());
        assert!(token_from_response("not json").is_none());
        // An empty string is not a token; sending it as a bearer would be a
        // request that authenticates as nobody while looking authenticated.
        assert!(token_from_response(r#"{"token":""}"#).is_none());
    }

    #[test]
    fn the_accept_header_offers_both_manifest_media_types() {
        assert!(MANIFEST_ACCEPT.contains("vnd.oci.image.manifest.v1+json"));
        assert!(MANIFEST_ACCEPT.contains("vnd.docker.distribution.manifest.v2+json"));
    }
}
