//! Fetching components into the store: OCI / HTTP / local. Network I/O is
//! isolated in thin wrappers; store-assembly logic is offline-testable.

use std::path::{Path, PathBuf};

use oci_client::manifest::OciImageManifest;

use crate::provenance::{Provenance, Source};
use crate::reference::Ref;
use crate::store::{Store, StoreError, Stored};

/// RFC 3339 timestamp for "now".
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// A reqwest client that requests + transparently decompresses gzip/br/zstd and
/// reuses one HTTP/2 connection (ALPN-negotiated over TLS).
pub(crate) fn compression_client() -> Result<reqwest::Client, StoreError> {
    reqwest::Client::builder()
        .gzip(true)
        .brotli(true)
        .zstd(true)
        .http2_adaptive_window(true)
        .build()
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))
}

/// GET a single blob with the right `Accept`, transparent decompression, and a
/// digest check over the decompressed bytes.
pub(crate) async fn fetch_blob(
    http: &reqwest::Client,
    blob_url: &str,
    accept: &str,
    digest: &str,
    token: Option<&str>,
) -> Result<Vec<u8>, StoreError> {
    let mut req = http.get(blob_url).header(reqwest::header::ACCEPT, accept);
    if let Some(t) = token {
        req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let resp = req
        .send()
        .await
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    if !resp.status().is_success() {
        return Err(StoreError::Io(std::io::Error::other(format!(
            "HTTP {} fetching {blob_url}",
            resp.status()
        ))));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?
        .to_vec();
    let got = crate::layout::sha256_hex(&bytes);
    if got != strip(digest) {
        return Err(StoreError::Digest(format!(
            "{digest} != sha256:{got} (from {blob_url})"
        )));
    }
    Ok(bytes)
}

/// Install a component from a local file path as a pinned `local` snapshot
/// (synthesized manifest). Records the source ref as `file://<absolute path>`.
pub fn install_local(store: &Store, path: &Path) -> Result<Stored, StoreError> {
    let bytes = std::fs::read(path)?;
    let provenance = Provenance {
        source: Source::Local {
            path: local_ref(path),
        },
        digest: format!("sha256:{}", crate::layout::sha256_hex(&bytes)),
        fetched_at: now_rfc3339(),
        name: None,
        version: None,
    };
    store.put_component(&bytes, None, &provenance)
}

/// The canonical `file://<absolute path>` ref string for a local file.
pub(crate) fn local_ref(path: &Path) -> String {
    let abs = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    format!("file://{}", abs.display())
}

/// Assemble HTTP provenance from already-downloaded bytes + optional caching
/// headers and store via a synthesized manifest. Offline — no network.
pub fn store_http_bytes(
    store: &Store,
    url: &str,
    bytes: &[u8],
    etag: Option<String>,
    last_modified: Option<String>,
) -> Result<Stored, StoreError> {
    let provenance = Provenance {
        source: Source::Http {
            url: url.to_string(),
            etag,
            last_modified,
        },
        digest: format!("sha256:{}", crate::layout::sha256_hex(bytes)),
        fetched_at: now_rfc3339(),
        name: None,
        version: None,
    };
    store.put_component(bytes, None, &provenance)
}

/// Download a `.wasm` from `url` and store it. Network wrapper.
pub async fn fetch_http(store: &Store, url: &str) -> Result<Stored, StoreError> {
    let http = compression_client()?;
    let resp = http
        .get(url)
        .header(reqwest::header::ACCEPT, "application/wasm")
        .send()
        .await
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    if !resp.status().is_success() {
        return Err(StoreError::Io(std::io::Error::other(format!(
            "HTTP {} fetching {url}",
            resp.status()
        ))));
    }
    let etag = header(&resp, reqwest::header::ETAG);
    let last_modified = header(&resp, reqwest::header::LAST_MODIFIED);
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    store_http_bytes(store, url, &bytes, etag, last_modified)
}

fn header(resp: &reqwest::Response, name: reqwest::header::HeaderName) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Offline OCI assembly: parse `manifest_bytes`, collect config + every layer
/// blob via `get_blob` (keyed by hex digest), store verbatim. `manifest_digest`
/// is the upstream digest (`sha256:...`).
pub fn assemble_oci(
    store: &Store,
    reference: &str,
    manifest_bytes: &[u8],
    manifest_digest: &str,
    get_blob: impl Fn(&str) -> Result<Vec<u8>, StoreError>,
) -> Result<Stored, StoreError> {
    let manifest: OciImageManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|e| StoreError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;

    let mut blobs: Vec<(String, Vec<u8>)> = Vec::new();
    let mut want = |digest: &str| -> Result<(), StoreError> {
        let hex = strip(digest);
        blobs.push((hex.clone(), get_blob(&hex)?));
        Ok(())
    };
    want(&manifest.config.digest)?;
    for layer in &manifest.layers {
        want(&layer.digest)?;
    }

    let provenance = Provenance {
        source: Source::Oci {
            reference: reference.to_string(),
        },
        digest: manifest_digest.to_string(),
        fetched_at: now_rfc3339(),
        name: None,
        version: None,
    };
    store.put_oci_artifact(manifest_bytes, &blobs, &provenance)
}

/// Pull an OCI component (manifest + blobs) and store it verbatim.
pub async fn fetch_oci(store: &Store, reference: &str) -> Result<Stored, StoreError> {
    use oci_client::client::{ClientConfig, ClientProtocol};
    use oci_client::manifest::{IMAGE_MANIFEST_MEDIA_TYPE, OCI_IMAGE_MEDIA_TYPE};
    use oci_client::secrets::RegistryAuth;
    use oci_client::{Client, Reference, RegistryOperation};

    let oci_ref: Reference = reference
        .strip_prefix("oci://")
        .unwrap_or(reference)
        .parse()
        .map_err(|e| {
            StoreError::Io(std::io::Error::other(format!(
                "bad OCI ref {reference}: {e}"
            )))
        })?;
    let client = Client::new(ClientConfig {
        protocol: ClientProtocol::Https,
        ..Default::default()
    });
    let auth = RegistryAuth::Anonymous;

    // pull_manifest_raw returns (bytes::Bytes, String) in oci-client 0.17
    let (manifest_raw, manifest_digest) = client
        .pull_manifest_raw(
            &oci_ref,
            &auth,
            &[OCI_IMAGE_MEDIA_TYPE, IMAGE_MANIFEST_MEDIA_TYPE],
        )
        .await
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    let manifest_bytes: Vec<u8> = manifest_raw.to_vec();

    let manifest: OciImageManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| StoreError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;

    // Acquire the registry token once; reuse it for every blob GET.
    // NOTE: oci-client 0.17 `auth` returns `Result<Option<String>>` directly.
    let token: Option<String> = client
        .auth(&oci_ref, &auth, RegistryOperation::Pull)
        .await
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?
        .map(|t| t.to_string());

    let http = compression_client()?;
    let registry = oci_ref.registry().to_string();
    let repository = oci_ref.repository().to_string();

    let mut descriptors = vec![manifest.config.clone()];
    descriptors.extend(manifest.layers.iter().cloned());

    // Fetch config + every layer concurrently over one HTTP/2 connection.
    let jobs = descriptors.iter().map(|desc| {
        let http = http.clone(); // cheap Arc clone; clones share the connection pool (h2 multiplexing preserved)
        let url = blob_url(&registry, &repository, &desc.digest);
        let accept = desc.media_type.clone();
        let digest = desc.digest.clone();
        let token = token.clone();
        async move {
            let bytes = fetch_blob(&http, &url, &accept, &digest, token.as_deref()).await?;
            Ok::<(String, Vec<u8>), StoreError>((strip(&digest), bytes))
        }
    });
    // Concurrency is intentionally unbounded — components are ~1 config + 1 layer over a single
    // h2 connection (server-capped MAX_CONCURRENT_STREAMS); revisit with buffer_unordered(N) if many-layer artifacts appear.
    let fetched: std::collections::HashMap<String, Vec<u8>> = futures::future::try_join_all(jobs)
        .await?
        .into_iter()
        .collect();

    let stored = assemble_oci(store, reference, &manifest_bytes, &manifest_digest, |hex| {
        fetched
            .get(hex)
            .cloned()
            .ok_or_else(|| StoreError::Digest(hex.into()))
    })?;
    collect_referrers(
        &client,
        &auth,
        &oci_ref,
        &manifest_digest,
        store,
        REFERRER_DEPTH,
    )
    .await;
    Ok(stored)
}

fn strip(digest: &str) -> String {
    digest.rsplit(':').next().unwrap_or(digest).to_string()
}

/// The blob download URL for a digest in `repo`'s registry/repository.
/// Assumes `https` and a verbatim registry host (e.g. ghcr.io, actpkg.dev) — does NOT
/// handle docker.io's `registry-1` normalization or plaintext `http` registries.
fn blob_url(registry: &str, repository: &str, digest: &str) -> String {
    format!("https://{registry}/v2/{repository}/blobs/{digest}")
}

/// Max depth for transitive referrer collection (referrer-of-a-referrer).
const REFERRER_DEPTH: u8 = 4;

/// Offline: store one referrer's manifest + blobs against `subject_digest`.
pub fn store_referrer(
    store: &Store,
    manifest_bytes: &[u8],
    blobs: &[(String, Vec<u8>)],
    subject_digest: &str,
    artifact_type: Option<&str>,
) -> Result<String, StoreError> {
    store.put_referrer(manifest_bytes, blobs, subject_digest, artifact_type)
}

/// Build a by-digest `Reference` in the same repo as `repo`.
fn digest_ref(
    repo: &oci_client::Reference,
    digest: &str,
) -> Result<oci_client::Reference, StoreError> {
    let d = if digest.contains(':') {
        digest.to_string()
    } else {
        format!("sha256:{digest}")
    };
    format!("{}/{}@{}", repo.registry(), repo.repository(), d)
        .parse()
        .map_err(|e| StoreError::Io(std::io::Error::other(format!("bad digest ref: {e}"))))
}

/// Pull a referrer manifest's config + layer blobs into `(hex, bytes)` pairs.
async fn referrer_blobs(
    client: &oci_client::Client,
    referrer_ref: &oci_client::Reference,
    manifest_bytes: &[u8],
) -> Result<Vec<(String, Vec<u8>)>, StoreError> {
    let manifest: OciImageManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|e| StoreError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
    let mut descriptors = vec![manifest.config.clone()];
    descriptors.extend(manifest.layers.iter().cloned());
    let mut out = Vec::new();
    for d in &descriptors {
        let mut buf: Vec<u8> = Vec::new();
        client
            .pull_blob(referrer_ref, d, &mut buf)
            .await
            .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
        out.push((strip(&d.digest), buf));
    }
    Ok(out)
}

/// Pull every connected artifact (referrer) of component manifest
/// `subject_digest` (`sha256:...`) in `repo`, store it, and recurse to the
/// transitive closure (depth-capped). Best-effort: a registry without the
/// referrers API yields nothing; per-referrer errors are logged and skipped so
/// referrer collection never fails the component pull.
async fn collect_referrers(
    client: &oci_client::Client,
    auth: &oci_client::secrets::RegistryAuth,
    repo: &oci_client::Reference,
    subject_digest: &str,
    store: &Store,
    depth: u8,
) {
    use oci_client::manifest::{IMAGE_MANIFEST_MEDIA_TYPE, OCI_IMAGE_MEDIA_TYPE};
    if depth == 0 {
        return;
    }
    let subject_ref = match digest_ref(repo, subject_digest) {
        Ok(r) => r,
        Err(_) => return,
    };
    let index = match client.pull_referrers(&subject_ref, None).await {
        Ok(idx) => idx,
        Err(e) => {
            tracing::debug!(%subject_digest, error = %e, "no referrers / referrers API unavailable");
            return;
        }
    };
    for desc in index.manifests {
        let ref_digest = desc.digest.clone();
        let referrer_ref = match digest_ref(repo, &ref_digest) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let pulled = client
            .pull_manifest_raw(
                &referrer_ref,
                auth,
                &[OCI_IMAGE_MEDIA_TYPE, IMAGE_MANIFEST_MEDIA_TYPE],
            )
            .await;
        let (m_bytes, m_digest) = match pulled {
            Ok((b, d)) => (b.to_vec(), d),
            Err(e) => {
                tracing::warn!(%ref_digest, error = %e, "failed to pull referrer manifest");
                continue;
            }
        };
        let blobs = match referrer_blobs(client, &referrer_ref, &m_bytes).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(%ref_digest, error = %e, "failed to pull referrer blobs");
                continue;
            }
        };
        let artifact_type = desc.artifact_type.clone();
        if let Err(e) =
            store.put_referrer(&m_bytes, &blobs, subject_digest, artifact_type.as_deref())
        {
            tracing::warn!(%ref_digest, error = %e, "failed to store referrer");
            continue;
        }
        Box::pin(collect_referrers(
            client,
            auth,
            repo,
            &m_digest,
            store,
            depth - 1,
        ))
        .await;
    }
}

/// Fetch `reference` into the store regardless of kind. Local files are
/// installed as pinned snapshots.
pub async fn pull(store: &Store, reference: &str) -> Result<Stored, StoreError> {
    let parsed: Ref = reference
        .parse()
        .map_err(|e| StoreError::Io(std::io::Error::other(format!("{e}"))))?;
    match parsed {
        Ref::Local(path) => install_local(store, &path),
        Ref::Http(url) => fetch_http(store, url.as_str()).await,
        Ref::Oci(r) => fetch_oci(store, &format!("oci://{r}")).await,
        Ref::Name(n) => Err(StoreError::Io(std::io::Error::other(format!(
            "registry name resolution not implemented: {n}"
        )))),
    }
}

/// The canonical store-lookup ref for a user-supplied reference. Must match the
/// ref that `pull` records when storing: local -> `file://<canonical>`,
/// oci -> `oci://<ref>`, http -> the URL string.
pub(crate) fn lookup_ref(reference: &str) -> String {
    match reference.parse::<Ref>() {
        Ok(Ref::Local(path)) => local_ref(&path),
        Ok(Ref::Oci(r)) => format!("oci://{r}"),
        Ok(Ref::Http(url)) => url.to_string(),
        _ => reference.to_string(),
    }
}

/// Read-through resolve: return the wasm blob path for `reference`, pulling it
/// into the store first if absent.
pub async fn ensure(store: &Store, reference: &str) -> Result<PathBuf, StoreError> {
    let key = lookup_ref(reference);
    if let Some(path) = store.resolve(&key)? {
        return Ok(path);
    }
    pull(store, reference).await?;
    store.resolve(&key)?.ok_or_else(|| {
        StoreError::Io(std::io::Error::other(format!(
            "resolve failed after pull: {reference}"
        )))
    })
}

/// Result of an [`update`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// The re-resolved digest matched the stored one; nothing changed.
    Unchanged,
    /// A newer artifact was pulled. Digests are `sha256:...`.
    Updated { from: String, to: String },
    /// The ref is not in the store.
    NotStored,
}

/// Re-resolve `reference` and re-pull if the digest moved.
pub async fn update(store: &Store, reference: &str) -> Result<UpdateOutcome, StoreError> {
    let key = lookup_ref(reference);
    let before = store
        .list()?
        .into_iter()
        .find(|s| source_ref(&s.provenance) == key)
        .map(|s| s.provenance.digest);
    let Some(before) = before else {
        return Ok(UpdateOutcome::NotStored);
    };
    let restored = pull(store, reference).await?;
    let after = restored.provenance.digest;
    if after == before {
        Ok(UpdateOutcome::Unchanged)
    } else {
        Ok(UpdateOutcome::Updated {
            from: before,
            to: after,
        })
    }
}

/// The `source.ref` (as stored) of a provenance, for matching against a key.
fn source_ref(p: &Provenance) -> &str {
    match &p.source {
        Source::Oci { reference } => reference,
        Source::Http { url, .. } => url,
        Source::Local { path } => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::StoreError;
    use tempfile::TempDir;

    #[tokio::test]
    async fn fetch_blob_decompresses_gzip_and_verifies_digest() {
        use flate2::{Compression, write::GzEncoder};
        use std::io::Write;
        use wiremock::matchers::{header, header_exists, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let original = b"\0asm\x01\0\0\0hello-wasm-body".to_vec();
        let hex = crate::layout::sha256_hex(&original);
        let digest = format!("sha256:{hex}");

        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&original).unwrap();
        let gz = enc.finish().unwrap();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v2/lib/x/blobs/{digest}")))
            .and(header("accept", "application/wasm"))
            .and(header_exists("accept-encoding"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(gz),
            )
            .mount(&server)
            .await;

        let url = format!("{}/v2/lib/x/blobs/{digest}", server.uri());
        let http = super::compression_client().unwrap();
        let got = super::fetch_blob(&http, &url, "application/wasm", &digest, None)
            .await
            .unwrap();
        assert_eq!(got, original); // decompressed back to the original bytes
    }

    #[tokio::test]
    async fn fetch_blob_rejects_digest_mismatch() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/lib/x/blobs/sha256:deadbeef"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(b"not-the-expected-bytes".to_vec()),
            )
            .mount(&server)
            .await;

        let url = format!("{}/v2/lib/x/blobs/sha256:deadbeef", server.uri());
        let http = super::compression_client().unwrap();
        let err = super::fetch_blob(&http, &url, "application/wasm", "sha256:deadbeef", None)
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Digest(_)));
    }

    #[tokio::test]
    async fn fetch_blob_sends_bearer_when_token_present() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let body = b"abc".to_vec();
        let digest = format!("sha256:{}", crate::layout::sha256_hex(&body));
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v2/lib/x/blobs/{digest}")))
            .and(header("authorization", "Bearer tok123"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;

        let url = format!("{}/v2/lib/x/blobs/{digest}", server.uri());
        let http = super::compression_client().unwrap();
        let got = super::fetch_blob(&http, &url, "application/wasm", &digest, Some("tok123"))
            .await
            .unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn install_local_then_resolve() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let wasm_path = dir.path().join("c.wasm");
        std::fs::write(&wasm_path, b"local-bytes").unwrap();
        let stored = install_local(&store, &wasm_path).unwrap();
        assert!(matches!(stored.provenance.source, Source::Local { .. }));
        let file_ref = match &stored.provenance.source {
            Source::Local { path } => path.clone(),
            _ => unreachable!(),
        };
        let resolved = store.resolve(&file_ref).unwrap().expect("hit");
        assert_eq!(std::fs::read(resolved).unwrap(), b"local-bytes");
    }

    #[test]
    fn store_http_bytes_records_http_provenance_with_headers() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let stored = store_http_bytes(
            &store,
            "https://cdn.example.com/x.wasm",
            b"http-bytes",
            Some("\"etag123\"".into()),
            Some("Wed, 21 May 2026 00:00:00 GMT".into()),
        )
        .unwrap();
        match stored.provenance.source {
            Source::Http {
                url,
                etag,
                last_modified,
            } => {
                assert_eq!(url, "https://cdn.example.com/x.wasm");
                assert_eq!(etag.as_deref(), Some("\"etag123\""));
                assert!(last_modified.is_some());
            }
            _ => panic!("expected Http source"),
        }
        assert!(
            store
                .resolve("https://cdn.example.com/x.wasm")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn assemble_oci_stores_verbatim_and_resolves() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let wasm = b"\0asm\x01\0\0\0oci";
        let wasm_hex = crate::layout::sha256_hex(wasm);
        let cfg = b"\xA0";
        let cfg_hex = crate::layout::sha256_hex(cfg);
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.actcore.component.config.v1+cbor","digest":"sha256:{cfg_hex}","size":{c}}},"layers":[{{"mediaType":"application/wasm","digest":"sha256:{wasm_hex}","size":{w}}}]}}"#,
            c = cfg.len(), w = wasm.len(),
        ).into_bytes();
        let upstream = crate::layout::sha256_hex(&manifest);
        let mut blobs = std::collections::HashMap::new();
        blobs.insert(wasm_hex.clone(), wasm.to_vec());
        blobs.insert(cfg_hex.clone(), cfg.to_vec());
        let stored = assemble_oci(
            &store,
            "oci://ghcr.io/x/oci:1",
            &manifest,
            &format!("sha256:{upstream}"),
            |hex| {
                blobs
                    .get(hex)
                    .cloned()
                    .ok_or_else(|| StoreError::Digest(hex.into()))
            },
        )
        .unwrap();
        assert_eq!(stored.manifest_digest, upstream);
        assert_eq!(stored.provenance.digest, format!("sha256:{upstream}"));
        assert_eq!(
            std::fs::read(store.resolve("oci://ghcr.io/x/oci:1").unwrap().unwrap()).unwrap(),
            wasm
        );
    }

    #[tokio::test]
    #[ignore = "network: fetches a real .wasm over HTTP"]
    async fn fetch_http_live() {
        let url = "https://github.com/actcore/act-cli/raw/main/README.md";
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let stored = fetch_http(&store, url).await.unwrap();
        assert!(stored.provenance.digest.starts_with("sha256:"));
        assert!(store.resolve(url).unwrap().is_some());
    }

    #[test]
    fn store_referrer_offline() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let subject = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let m = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.empty.v1+json","digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2},"layers":[]}"#.to_vec();
        let cfg = b"{}".to_vec();
        let cfg_hex = crate::layout::sha256_hex(&cfg);
        super::store_referrer(
            &store,
            &m,
            &[(cfg_hex, cfg)],
            subject,
            Some("application/spdx+json"),
        )
        .unwrap();
        assert_eq!(
            store
                .list_referrers_by_digest(
                    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
                )
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    #[ignore = "network: pulls a component AND its referrers from ghcr.io"]
    async fn fetch_oci_with_referrers_live() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let r = "oci://ghcr.io/actpkg/time:0.2.0";
        let stored = super::fetch_oci(&store, r).await.unwrap();
        assert!(store.resolve(r).unwrap().is_some());
        let refs = store
            .list_referrers_by_digest(&stored.manifest_digest)
            .unwrap();
        eprintln!("referrers collected for time:0.2.0: {}", refs.len());
    }

    #[tokio::test]
    async fn fetch_http_sends_accept_and_decompresses() {
        use flate2::{Compression, write::GzEncoder};
        use std::io::Write;
        use wiremock::matchers::{header, header_exists, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let original = b"\0asm\x01\0\0\0http-path".to_vec();
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&original).unwrap();
        let gz = enc.finish().unwrap();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/x.wasm"))
            .and(header("accept", "application/wasm"))
            .and(header_exists("accept-encoding"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(gz),
            )
            .mount(&server)
            .await;

        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let url = format!("{}/x.wasm", server.uri());
        let stored = super::fetch_http(&store, &url).await.unwrap();
        assert_eq!(
            stored.provenance.digest,
            format!("sha256:{}", crate::layout::sha256_hex(&original))
        );
        assert_eq!(
            std::fs::read(store.resolve(&url).unwrap().unwrap()).unwrap(),
            original
        );
    }

    #[test]
    fn blob_url_builds_distribution_url() {
        assert_eq!(
            super::blob_url("actpkg.dev", "library/random", "sha256:abc123"),
            "https://actpkg.dev/v2/library/random/blobs/sha256:abc123"
        );
    }

    #[tokio::test]
    #[ignore = "network: pulls a real component from ghcr.io"]
    async fn fetch_oci_live() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let r = "oci://ghcr.io/actpkg/time:0.2.0";
        let stored = fetch_oci(&store, r).await.unwrap();
        assert!(stored.provenance.digest.starts_with("sha256:"));
        assert!(store.resolve(r).unwrap().is_some());
    }

    #[tokio::test]
    async fn pull_dispatches_local_by_ref_kind() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let p = dir.path().join("d.wasm");
        std::fs::write(&p, b"dispatch").unwrap();
        let stored = super::pull(&store, &p.display().to_string()).await.unwrap();
        assert!(matches!(stored.provenance.source, Source::Local { .. }));
    }

    #[tokio::test]
    async fn ensure_local_by_bare_path_is_read_through() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let p = dir.path().join("f.wasm");
        std::fs::write(&p, b"bare").unwrap();
        let bare = p.display().to_string();
        let a = super::ensure(&store, &bare).await.unwrap(); // pulls
        let b = super::ensure(&store, &bare).await.unwrap(); // store hit
        assert_eq!(a, b);
        assert_eq!(std::fs::read(&a).unwrap(), b"bare");
    }

    #[tokio::test]
    async fn update_local_noop_then_changed() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let p = dir.path().join("u.wasm");
        std::fs::write(&p, b"v1").unwrap();
        let stored = super::pull(&store, &p.display().to_string()).await.unwrap();
        let r = match &stored.provenance.source {
            Source::Local { path } => path.clone(),
            _ => unreachable!(),
        };
        assert!(matches!(
            super::update(&store, &r).await.unwrap(),
            super::UpdateOutcome::Unchanged
        ));
        std::fs::write(&p, b"v2-bigger").unwrap();
        match super::update(&store, &r).await.unwrap() {
            super::UpdateOutcome::Updated { from, to } => assert_ne!(from, to),
            other => panic!("expected Updated, got {other:?}"),
        }
    }

    #[tokio::test]
    #[ignore = "network: pulls a real blob from actpkg.dev and checks compression"]
    async fn fetch_blob_live_actpkg_compresses() {
        // Resolve the random component's layer digest via the manifest, then fetch it.
        use oci_client::client::{Client, ClientConfig, ClientProtocol};
        use oci_client::manifest::{
            IMAGE_MANIFEST_MEDIA_TYPE, OCI_IMAGE_MEDIA_TYPE, OciImageManifest,
        };
        use oci_client::secrets::RegistryAuth;
        use oci_client::{Reference, RegistryOperation};

        let oci_ref: Reference = "actpkg.dev/library/random:latest".parse().unwrap();
        let client = Client::new(ClientConfig {
            protocol: ClientProtocol::Https,
            ..Default::default()
        });
        let (raw, _d) = client
            .pull_manifest_raw(
                &oci_ref,
                &RegistryAuth::Anonymous,
                &[OCI_IMAGE_MEDIA_TYPE, IMAGE_MANIFEST_MEDIA_TYPE],
            )
            .await
            .unwrap();
        let manifest: OciImageManifest = serde_json::from_slice(&raw).unwrap();
        let layer = &manifest.layers[0];
        let token = client
            .auth(&oci_ref, &RegistryAuth::Anonymous, RegistryOperation::Pull)
            .await
            .unwrap()
            .map(|t| t.to_string());

        let http = super::compression_client().unwrap();
        let url = super::blob_url("actpkg.dev", "library/random", &layer.digest);
        // Succeeds only if the digest verifies over decompressed bytes.
        let bytes = super::fetch_blob(
            &http,
            &url,
            &layer.media_type,
            &layer.digest,
            token.as_deref(),
        )
        .await
        .unwrap();
        eprintln!(
            "pulled+verified {} bytes (Accept={})",
            bytes.len(),
            layer.media_type
        );
        assert_eq!(bytes.len() as i64, layer.size);
    }
}
