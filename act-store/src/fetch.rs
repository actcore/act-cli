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
    let resp = reqwest::get(url)
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
    use oci_client::{Client, Reference};

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

    // Pre-fetch all blobs (config + layers) into a map keyed by hex digest.
    // pull_blob in oci-client 0.17 writes to T: AsyncWrite; use Vec<u8> as sink.
    let mut fetched: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
    let mut descriptors = vec![manifest.config.clone()];
    descriptors.extend(manifest.layers.iter().cloned());
    for desc in &descriptors {
        let mut buf: Vec<u8> = Vec::new();
        client
            .pull_blob(&oci_ref, desc, &mut buf)
            .await
            .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
        fetched.insert(strip(&desc.digest), buf);
    }

    assemble_oci(store, reference, &manifest_bytes, &manifest_digest, |hex| {
        fetched
            .get(hex)
            .cloned()
            .ok_or_else(|| StoreError::Digest(hex.into()))
    })
}

fn strip(digest: &str) -> String {
    digest.rsplit(':').next().unwrap_or(digest).to_string()
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
fn lookup_ref(reference: &str) -> String {
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
    use tempfile::TempDir;

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

    #[tokio::test]
    #[ignore = "network: pulls a real component from ghcr.io"]
    async fn fetch_oci_live() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let r = "oci://ghcr.io/actpkg/sqlite:0.1.0";
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
}
