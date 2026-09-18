//! Uploading blobs and manifests.
//!
//! Lives in `act-store` beside the pull half so one module owns the wire
//! format; `act-build` drives it.

use super::auth::Challenge;
use super::client::fetch_token;
use super::reference::ParsedRef;
use crate::store::StoreError;

fn io(e: impl std::fmt::Display) -> StoreError {
    StoreError::Io(std::io::Error::other(e.to_string()))
}

/// The scope a push needs.
///
/// `pull,push` rather than `push` alone: a push re-reads what it wrote — the
/// manifest check after the upload — and a token scoped to push only would be
/// refused for that read by registries that enforce the distinction.
pub fn push_scope(repository: &str) -> String {
    format!("repository:{repository}:pull,push")
}

/// Obtain a token for pushing, if the registry asks for one.
///
/// A `401` on the upload endpoint is the normal first answer; anything else,
/// including `200`, means no token is needed and `None` is correct.
pub async fn push_token(
    http: &hclient::Client,
    reg: &ParsedRef,
    creds: &super::auth::Credentials,
) -> Result<Option<String>, StoreError> {
    let probe = format!(
        "https://{}/v2/{}/blobs/uploads/",
        reg.registry, reg.repository
    );
    let resp = http.post(&probe).send().await.map_err(io)?;
    if resp.status().as_u16() != 401 {
        return Ok(None);
    }
    let challenge = resp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .and_then(Challenge::parse)
        .ok_or_else(|| {
            io(format!(
                "{} asked for auth without a Bearer challenge",
                reg.registry
            ))
        })?;
    // The registry's own scope names what it wants; ours only fills a gap,
    // and ours has to be the push scope or the upload is refused after the
    // token round trip rather than before it.
    let challenge = Challenge {
        scope: challenge
            .scope
            .or_else(|| Some(push_scope(&reg.repository))),
        ..challenge
    };
    fetch_token(http, &challenge, creds).await
}

/// Attach the bearer when there is one.
fn bearer<'a>(
    req: hclient::RequestBuilder<'a>,
    token: Option<&str>,
) -> hclient::RequestBuilder<'a> {
    match token {
        Some(t) => req.header("authorization", &format!("Bearer {t}")),
        None => req,
    }
}

/// Upload one blob, monolithically.
///
/// Two requests, which is what the distribution spec calls the monolithic
/// path: `POST` opens a session and answers `202` with a `Location`, then one
/// `PUT` carrying the bytes and the digest closes it. Chunked upload exists
/// for resumability across a dropped connection; a component layer is a
/// single-digit number of megabytes, so the complexity would buy nothing.
///
/// A blob the registry already has is not re-sent: `HEAD` first, and a `200`
/// there means every byte of this upload would be discarded.
pub async fn push_blob(
    http: &hclient::Client,
    reg: &ParsedRef,
    digest: &str,
    bytes: Vec<u8>,
    token: Option<&str>,
) -> Result<(), StoreError> {
    let head_url = format!(
        "https://{}/v2/{}/blobs/{digest}",
        reg.registry, reg.repository
    );
    if let Ok(r) = bearer(http.head(&head_url), token).send().await
        && r.status().is_success()
    {
        return Ok(());
    }

    let start = format!(
        "https://{}/v2/{}/blobs/uploads/",
        reg.registry, reg.repository
    );
    let resp = bearer(http.post(&start), token).send().await.map_err(io)?;
    if !resp.status().is_success() {
        return Err(io(format!(
            "HTTP {} opening a blob upload on {}",
            resp.status(),
            reg.registry
        )));
    }
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| io("the upload session carried no Location"))?
        .to_string();

    let url = absolute(&location, &reg.registry);
    let sep = if url.contains('?') { '&' } else { '?' };
    let put = format!("{url}{sep}digest={digest}");

    let resp = bearer(
        http.put(&put)
            .header("content-type", "application/octet-stream")
            .body(hclient::RequestBody::Full(bytes.into())),
        token,
    )
    .send()
    .await
    .map_err(io)?;
    if !resp.status().is_success() {
        return Err(io(format!(
            "HTTP {} completing the blob upload of {digest}",
            resp.status()
        )));
    }
    Ok(())
}

/// PUT a manifest as the exact bytes given.
///
/// **Verbatim, never re-serialised.** The digest a caller published is the
/// hash of these bytes; re-encoding the same JSON with different key order or
/// spacing yields a different digest, and every signature over the old one
/// stops verifying.
pub async fn push_manifest(
    http: &hclient::Client,
    reg: &ParsedRef,
    reference: &str,
    bytes: Vec<u8>,
    content_type: &str,
    token: Option<&str>,
) -> Result<String, StoreError> {
    let url = format!(
        "https://{}/v2/{}/manifests/{reference}",
        reg.registry, reg.repository
    );
    let mut req = http
        .put(&url)
        .header("content-type", content_type)
        .body(hclient::RequestBody::Full(bytes.into()));
    if let Some(t) = token {
        req = req.header("authorization", &format!("Bearer {t}"));
    }
    let resp = req.send().await.map_err(io)?;
    if !resp.status().is_success() {
        return Err(io(format!(
            "HTTP {} pushing manifest {}/{}:{reference}",
            resp.status(),
            reg.registry,
            reg.repository
        )));
    }
    Ok(resp
        .headers()
        .get("docker-content-digest")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string())
}

/// Resolve a `Location` that may be a path or already absolute.
///
/// Registries answer with both shapes, and joining an already-absolute URL
/// onto the host produces a URL to nowhere.
fn absolute(location: &str, registry: &str) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        location.to_string()
    } else {
        format!("https://{registry}{location}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_push_scope_asks_for_pull_as_well() {
        // A push re-reads what it wrote; a push-only token is refused for that
        // read on registries that separate the two.
        assert_eq!(
            push_scope("library/time"),
            "repository:library/time:pull,push"
        );
    }

    #[test]
    fn a_relative_location_is_joined_and_an_absolute_one_is_not() {
        assert_eq!(
            absolute("/v2/a/blobs/uploads/abc", "reg.example"),
            "https://reg.example/v2/a/blobs/uploads/abc"
        );
        // Some registries redirect the upload to object storage on another
        // host; treating that as a path would send the bytes to the registry
        // instead, which answers 404.
        assert_eq!(
            absolute("https://blobs.example/upload/abc", "reg.example"),
            "https://blobs.example/upload/abc"
        );
    }
}
