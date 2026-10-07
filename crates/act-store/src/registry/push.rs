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

/// Upload one blob, chunked when it is large enough to need it.
///
/// Two requests — `POST` opening a session, one `PUT` carrying the bytes and
/// the digest — is what the distribution spec calls the monolithic path, and
/// it is still what small blobs take. Above [`CHUNK_THRESHOLD`] the push
/// switches to the spec's chunked path instead: each `PATCH` carries a
/// `Content-Range` slice of at most [`CHUNK_SIZE`] bytes, so every request
/// individually completes well inside the response windows of proxy chains
/// that sit in front of registries (a Cloudflare edge 524s an origin that
/// takes longer than ~100 s, which is exactly how a 47 MB monolithic push of
/// python-env died). The final `PUT ?digest=` carries the remaining tail (it
/// may be empty when the last chunk was also the last byte) and closes the
/// session.
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
    let mut url = absolute(&location, &reg.registry);

    // What the closing PUT carries: the whole body when the push stayed
    // monolithic, the unPATCHed tail when it went out in chunks (the
    // registry already holds everything before the tail — a full-body PUT
    // after PATCHed chunks would double-count and fail the digest).
    let put_body = if bytes.len() > CHUNK_THRESHOLD {
        push_chunked(http, reg, &mut url, &bytes, token).await?
    } else {
        bytes
    };

    let sep = if url.contains('?') { '&' } else { '?' };
    let put = format!("{url}{sep}digest={digest}");

    let resp = bearer(
        http.put(&put)
            .header("content-type", "application/octet-stream")
            .body(hclient::RequestBody::Full(put_body.into())),
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

/// Blobs larger than this go out as chunks.
///
/// Two interacting windows shaped it: Cloudflare's ~100 s origin timeout (the
/// registry path is behind one), and a slow uplink. At 4 MiB a chunk finishes
/// in under 45 s even at a ~800 Kbps effective rate, and a 50 MB layer fits
/// in a dozen requests.
const CHUNK_THRESHOLD: usize = 8 * 1024 * 1024;
const CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// The byte ranges of the fixed-size chunks over `len`:
/// `(start, end)` inclusive per the spec's `Content-Range`.
fn chunk_ranges(len: usize) -> Vec<(usize, usize)> {
    if len == 0 {
        return Vec::new();
    }
    (0..len.div_ceil(CHUNK_SIZE))
        .map(|i| {
            let start = i * CHUNK_SIZE;
            (start, (start + CHUNK_SIZE).min(len) - 1)
        })
        .collect()
}

/// Push the blob in PATCH chunks, leaving the final tail for the caller's
/// `PUT ?digest=`.
///
/// After every `202` the session's `Location` is re-read — registries may
/// rotate it per chunk (zot does) — and the last full chunk stays unPATCHed
/// so the closing `PUT ?digest=` carries real bytes. A `405`/`501` on the
/// FIRST patch means the registry doesn't speak chunked at all; the session
/// is untouched at that point, so the caller falls back to the monolithic
/// `PUT` of the whole body on the same session.
async fn push_chunked(
    http: &hclient::Client,
    reg: &ParsedRef,
    url: &mut String,
    bytes: &[u8],
    token: Option<&str>,
) -> Result<Vec<u8>, StoreError> {
    let ranges = chunk_ranges(bytes.len());

    for (i, (start, end)) in ranges.iter().enumerate() {
        let first = i == 0;
        let content_len = (end - start + 1).to_string();
        // `patch` takes the URL by reference: the loop rotates `url` in place
        // below, and hclient's AsRef<str> bound would move the &mut out of it.
        let resp = bearer(
            http.patch(url.as_str())
                .header("content-type", "application/octet-stream")
                .header("content-range", &format!("{start}-{end}"))
                .header("content-length", &content_len)
                .body(hclient::RequestBody::Full(
                    bytes[*start..=*end].to_vec().into(),
                )),
            token,
        )
        .send()
        .await
        .map_err(io)?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            if first && (status == 405 || status == 501) {
                // The registry refuses chunked uploads; the session is fresh,
                // so the caller's monolithic PUT can still take the whole
                // body.
                return Ok(bytes.to_vec());
            }
            return Err(io(format!(
                "HTTP {} patching chunk {start}-{end} of the blob upload",
                resp.status()
            )));
        }
        // Registries may rotate the session Location per chunk (zot does);
        // a silent one means the URL is unchanged.
        if let Some(loc) = resp.headers().get("location").and_then(|v| v.to_str().ok()) {
            *url = absolute(loc, &reg.registry);
        }
    }

    // The closing PUT carries an empty body: every byte went out as PATCH
    // chunks, and zot's chunked-session PUT answers 400 on a non-empty body
    // (measured: it treats the PUT as a fresh monolithic restart rather than
    // an append).
    Ok(Vec::new())
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
    fn chunk_ranges_covers_the_body_in_order() {
        // 10 MiB over 4 MiB chunks: 4 + 4 + 2, ranges contiguous and inclusive.
        let ranges = chunk_ranges(10 * 1024 * 1024);
        assert_eq!(ranges.len(), 3);
        assert_eq!(ranges[0], (0, 4 * 1024 * 1024 - 1));
        assert_eq!(ranges[1], (4 * 1024 * 1024, 8 * 1024 * 1024 - 1));
        assert_eq!(
            ranges[2],
            (8 * 1024 * 1024, 10 * 1024 * 1024 - 1),
            "the tail is smaller and still inclusive-ended"
        );
        // Contiguity: each range starts exactly where the previous ended + 1.
        for w in ranges.windows(2) {
            assert_eq!(w[1].0, w[0].1 + 1);
        }
        // Under one chunk: a single range spanning the whole body.
        assert_eq!(chunk_ranges(1024), vec![(0, 1023)]);
    }

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
