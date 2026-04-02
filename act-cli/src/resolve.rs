//! Component reference parsing and resolution.
//!
//! Remote refs are always downloaded to cache first. `resolve()` returns a
//! local `PathBuf` that can be passed to `runtime::load_component`.

use anyhow::{Context, Result};
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::LazyLock;
use tokio::io::AsyncWriteExt;
use url::Url;

/// A parsed component reference.
#[derive(Debug, Clone)]
pub enum ComponentRef {
    /// Local filesystem path.
    Local(PathBuf),
    /// HTTP or HTTPS URL to a raw .wasm file.
    Http(Url),
    /// OCI registry reference (e.g. `ghcr.io/actcore/component-sqlite:latest`).
    Oci(String),
    /// Component name for future centralized registry lookup.
    Name(String),
}

/// OCI reference regex: `registry.host/path[:tag|@digest]`
/// Registry host must contain a dot or be `localhost`.
static OCI_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:localhost(?::\d+)?|[a-zA-Z0-9][\w.-]*\.[a-zA-Z]{2,}(?::\d+)?)/[a-zA-Z0-9][\w./-]*(?::[\w][\w.-]*|@sha256:[a-fA-F0-9]+)?$"
    ).unwrap()
});

/// Parsing never fails — unrecognized inputs become `Name`.
impl FromStr for ComponentRef {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        // HTTP/S URL
        if let Ok(url) = Url::parse(s) {
            if url.scheme() == "http" || url.scheme() == "https" {
                return Ok(Self::Http(url));
            }
            // oci:// prefix
            if url.scheme() == "oci" {
                // Reconstruct the reference without the oci:// prefix
                let rest = &s["oci://".len()..];
                return Ok(Self::Oci(rest.to_string()));
            }
        }

        // OCI reference by regex
        if OCI_RE.is_match(s) {
            return Ok(Self::Oci(s.to_string()));
        }

        // Local file path: has path separators or .wasm extension
        if s.contains('/') || s.contains('\\') || s.ends_with(".wasm") || s.starts_with('.') {
            return Ok(Self::Local(PathBuf::from(s)));
        }

        // Bare name — future registry
        Ok(Self::Name(s.to_string()))
    }
}

impl std::fmt::Display for ComponentRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local(p) => write!(f, "{}", p.display()),
            Self::Http(url) => write!(f, "{url}"),
            Self::Oci(r) => write!(f, "{r}"),
            Self::Name(n) => write!(f, "{n}"),
        }
    }
}

// ── Cache ────────────────────────────────────────────────────────────────────

/// Cache directory: ~/.cache/act/components/
async fn cache_dir() -> Result<PathBuf> {
    let dir = dirs::cache_dir()
        .context("cannot determine cache directory")?
        .join("act")
        .join("components");
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("creating cache dir: {}", dir.display()))?;
    Ok(dir)
}

/// SHA-256 based cache filename.
fn cache_key(input: &str) -> String {
    let hash = Sha256::digest(input.as_bytes());
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    format!("{hex}.wasm")
}

async fn cache_path(input: &str) -> Result<PathBuf> {
    Ok(cache_dir().await?.join(cache_key(input)))
}

// ── Resolution ───────────────────────────────────────────────────────────────

/// Resolve a component reference to a local file path.
///
/// Remote refs (HTTP, OCI) are downloaded to cache first.
/// If `fresh` is true, bypass cache and re-download.
/// Returns the path to the .wasm file.
pub async fn resolve(component_ref: &ComponentRef, fresh: bool) -> Result<PathBuf> {
    tracing::info!(ref = %component_ref, "Resolving component");
    match component_ref {
        ComponentRef::Local(path) => {
            anyhow::ensure!(
                tokio::fs::try_exists(path).await.unwrap_or(false),
                "component not found: {}",
                path.display()
            );
            tracing::debug!(path = %path.display(), "Using local component");
            Ok(path.clone())
        }
        ComponentRef::Http(url) => resolve_http(url.as_str(), fresh).await,
        ComponentRef::Oci(reference) => resolve_oci(reference, fresh).await,
        ComponentRef::Name(name) => {
            anyhow::bail!(
                "Component registry lookup is not yet implemented.\n\
                 Cannot resolve component name: {name}\n\
                 Use a local path, HTTP URL, or OCI reference instead."
            )
        }
    }
}

fn make_progress_bar(total: Option<u64>, message: &str) -> ProgressBar {
    let pb = match total {
        Some(len) => {
            let pb = ProgressBar::new(len);
            pb.set_style(
                ProgressStyle::with_template(
                    "{msg}\n  {wide_bar:.cyan/dim} {bytes}/{total_bytes} ({bytes_per_sec})",
                )
                .unwrap()
                .progress_chars("━╸─"),
            );
            pb
        }
        None => {
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::with_template("{msg}\n  {spinner} {bytes} ({bytes_per_sec})")
                    .unwrap(),
            );
            pb
        }
    };
    pb.set_message(message.to_string());
    pb
}

async fn resolve_http(url: &str, fresh: bool) -> Result<PathBuf> {
    let cached = cache_path(url).await?;
    if !fresh && tokio::fs::try_exists(&cached).await.unwrap_or(false) {
        tracing::info!(%url, path = %cached.display(), "Using cached component");
        return Ok(cached);
    }

    let response = reqwest::get(url)
        .await
        .with_context(|| format!("HTTP request to {url}"))?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("HTTP {status} fetching {url}");
    }

    let total = response.content_length();
    let pb = make_progress_bar(total, url);

    let mut file = tokio::fs::File::create(&cached)
        .await
        .with_context(|| format!("creating cache file: {}", cached.display()))?;

    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(|| format!("reading response from {url}"))?;
        file.write_all(&chunk).await?;
        pb.inc(chunk.len() as u64);
    }
    file.flush().await?;

    pb.finish_with_message("done");
    Ok(cached)
}

async fn resolve_oci(reference: &str, fresh: bool) -> Result<PathBuf> {
    let cached = cache_path(reference).await?;
    if !fresh && tokio::fs::try_exists(&cached).await.unwrap_or(false) {
        tracing::info!(%reference, path = %cached.display(), "Using cached component");
        return Ok(cached);
    }

    let oci_ref: oci_client::Reference = reference
        .parse()
        .with_context(|| format!("invalid OCI reference: {reference}"))?;

    let client_config = oci_client::client::ClientConfig {
        protocol: oci_client::client::ClientProtocol::Https,
        ..Default::default()
    };
    let oci = oci_client::Client::new(client_config);
    let auth = oci_client::secrets::RegistryAuth::Anonymous;

    // Pull manifest to find the wasm layer descriptor
    let (manifest, _digest) = oci
        .pull_image_manifest(&oci_ref, &auth)
        .await
        .with_context(|| format!("pulling manifest from OCI: {reference}"))?;

    let layer = manifest
        .layers
        .first()
        .context("no layers in OCI manifest")?;

    let total = if layer.size > 0 {
        Some(layer.size as u64)
    } else {
        None
    };
    let pb = make_progress_bar(total, reference);

    // Stream the layer blob to cache file
    let sized_stream = oci
        .pull_blob_stream(&oci_ref, layer)
        .await
        .with_context(|| format!("streaming blob from OCI: {reference}"))?;

    let mut file = tokio::fs::File::create(&cached)
        .await
        .with_context(|| format!("creating cache file: {}", cached.display()))?;

    let mut stream = sized_stream.stream;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(|| format!("reading OCI blob: {reference}"))?;
        file.write_all(&chunk).await?;
        pb.inc(chunk.len() as u64);
    }
    file.flush().await?;

    pb.finish_with_message("done");
    Ok(cached)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper — parse and unwrap (infallible).
    fn parse(s: &str) -> ComponentRef {
        s.parse().unwrap()
    }

    #[test]
    fn parse_https_url() {
        assert!(matches!(
            parse("https://example.com/comp.wasm"),
            ComponentRef::Http(_)
        ));
    }

    #[test]
    fn parse_http_url() {
        assert!(matches!(
            parse("http://localhost:8080/comp.wasm"),
            ComponentRef::Http(_)
        ));
    }

    #[test]
    fn parse_explicit_oci() {
        assert!(
            matches!(parse("oci://ghcr.io/actcore/sqlite:latest"), ComponentRef::Oci(r) if r == "ghcr.io/actcore/sqlite:latest")
        );
    }

    #[test]
    fn parse_oci_with_tag() {
        assert!(matches!(
            parse("ghcr.io/actcore/component-sqlite:latest"),
            ComponentRef::Oci(_)
        ));
    }

    #[test]
    fn parse_oci_with_digest() {
        assert!(matches!(
            parse("ghcr.io/actcore/sqlite@sha256:abc123"),
            ComponentRef::Oci(_)
        ));
    }

    #[test]
    fn parse_oci_no_tag() {
        assert!(matches!(
            parse("ghcr.io/actcore/sqlite"),
            ComponentRef::Oci(_)
        ));
    }

    #[test]
    fn parse_oci_semver_tag() {
        assert!(matches!(
            parse("ghcr.io/actpkg/sqlite:0.1.0"),
            ComponentRef::Oci(_)
        ));
    }

    #[test]
    fn parse_local_relative() {
        assert!(matches!(parse("./component.wasm"), ComponentRef::Local(_)));
    }

    #[test]
    fn parse_local_absolute() {
        assert!(matches!(
            parse("/tmp/component.wasm"),
            ComponentRef::Local(_)
        ));
    }

    #[test]
    fn parse_local_wasm_extension() {
        assert!(matches!(parse("component.wasm"), ComponentRef::Local(_)));
    }

    #[test]
    fn parse_bare_name() {
        assert!(
            matches!(parse("component-sqlite"), ComponentRef::Name(n) if n == "component-sqlite")
        );
    }

    #[test]
    fn parse_bare_name_simple() {
        assert!(matches!(parse("sqlite"), ComponentRef::Name(n) if n == "sqlite"));
    }
}
