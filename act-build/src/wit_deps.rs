use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use tar::Archive;
use tracing::info;

#[derive(Debug, serde::Deserialize)]
struct DepsFile(BTreeMap<String, DepEntry>);

#[derive(Debug, serde::Deserialize)]
struct DepEntry {
    url: String,
    prefix: String,
    #[serde(default)]
    sha256: Option<String>,
}

/// Resolve `wit/deps/<name>/` directories declared in `wit/deps.toml`.
///
/// Same on-disk format as `wit-deps` so existing component trees keep working.
/// Tarballs are fetched once per URL even when multiple packages share an
/// archive (act-core + act-tools both come from act-spec/main.tar.gz).
pub fn sync(wit_dir: &Path) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime for WIT fetch")?;
    rt.block_on(sync_async(wit_dir))
}

async fn sync_async(wit_dir: &Path) -> Result<()> {
    let deps_toml = wit_dir.join("deps.toml");
    if !deps_toml.exists() {
        return Ok(());
    }
    let raw = fs::read_to_string(&deps_toml)
        .with_context(|| format!("reading {}", deps_toml.display()))?;
    let parsed: DepsFile =
        toml::from_str(&raw).with_context(|| format!("parsing {}", deps_toml.display()))?;

    let deps_dir = wit_dir.join("deps");
    fs::create_dir_all(&deps_dir).with_context(|| format!("creating {}", deps_dir.display()))?;

    let client = http_client().context("building the HTTP client")?;

    let mut tarball_cache: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    for (name, dep) in &parsed.0 {
        let bytes = if let Some(b) = tarball_cache.get(&dep.url) {
            b.clone()
        } else {
            info!(url = %dep.url, "fetching wit tarball");
            let b = fetch_tarball(&client, &dep.url)
                .await
                .with_context(|| format!("fetching {}", dep.url))?;
            if let Some(expected) = &dep.sha256 {
                verify_sha256(&b, expected)
                    .with_context(|| format!("verifying sha256 for {}", dep.url))?;
            }
            tarball_cache.insert(dep.url.clone(), b.clone());
            b
        };

        let target = deps_dir.join(name);
        if target.exists() {
            fs::remove_dir_all(&target)
                .with_context(|| format!("removing stale {}", target.display()))?;
        }
        fs::create_dir_all(&target).with_context(|| format!("creating {}", target.display()))?;
        extract_prefix(&bytes, &dep.prefix, &target)
            .with_context(|| format!("extracting prefix {} -> {}", dep.prefix, target.display()))?;
        info!(name = %name, target = %target.display(), "extracted wit package");
    }
    Ok(())
}

/// The host's outbound HTTP stack.
///
/// `hclient` keeps the runtime, the TLS stack and the resolver as separate
/// seams rather than picking for you, so this is where `act-build` picks.
/// Webpki roots rather than the platform store: a WIT tarball comes from a
/// registry on the public web, and the bundled set is identical on every
/// machine — a CI image with an empty system store would otherwise fail here
/// and nowhere else.
fn http_client() -> Result<hclient::Client> {
    let transport = hclient_native::Native::new(
        hclient_rt_tokio::Tokio,
        hclient_tls_rustls::Rustls::with_webpki_roots(),
        hclient_dns_system::SystemDns::new(hclient_rt_tokio::Tokio),
    );
    // `build` returns a `Result`: `hclient` refuses to hand back a client whose
    // configuration the backend cannot honour rather than silently dropping the
    // part it cannot do.
    hclient::Client::builder(transport)
        .user_agent(http::HeaderValue::from_static(concat!(
            "act-build/",
            env!("CARGO_PKG_VERSION")
        )))
        .build()
        .map_err(|e| anyhow::anyhow!("the HTTP backend cannot serve this configuration: {e}"))
}

async fn fetch_tarball(client: &hclient::Client, url: &str) -> Result<Vec<u8>> {
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("HTTP GET {url}"))?
        .error_for_status()
        .with_context(|| format!("HTTP status error for {url}"))?;
    // `collect` reads the whole body; the tarball is hashed and unpacked in one
    // piece anyway, so there is nothing to stream it into.
    let body = resp
        .collect()
        .await
        .with_context(|| format!("reading response body for {url}"))?;
    Ok(body.bytes().to_vec())
}

fn verify_sha256(bytes: &[u8], expected: &str) -> Result<()> {
    let mut h = Sha256::new();
    h.update(bytes);
    let got = hex_lower(&h.finalize());
    if got != expected.to_lowercase() {
        bail!("sha256 mismatch: expected {}, got {}", expected, got);
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

fn extract_prefix(gz_bytes: &[u8], prefix: &str, target_dir: &Path) -> Result<()> {
    let normalized_prefix = format!("{}/", prefix.trim_end_matches('/'));
    let dec = GzDecoder::new(gz_bytes);
    let mut archive = Archive::new(dec);
    let mut written = 0usize;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        let path_str = path.to_string_lossy();
        let Some(rel) = path_str.strip_prefix(normalized_prefix.as_str()) else {
            continue;
        };
        if rel.is_empty() {
            continue;
        }
        if rel.split('/').any(|c| c == "..") {
            bail!("refusing to extract entry with '..': {:?}", path);
        }
        let out = target_dir.join(rel);
        if entry.header().entry_type().is_dir() {
            fs::create_dir_all(&out).with_context(|| format!("creating {}", out.display()))?;
            continue;
        }
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        entry
            .unpack(&out)
            .with_context(|| format!("unpacking {} -> {}", path.display(), out.display()))?;
        written += 1;
    }
    if written == 0 {
        bail!("no entries matched prefix {:?}", prefix);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_gz_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            for (path, data) in files {
                let mut header = tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append(&header, *data).unwrap();
            }
            builder.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar_buf).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn extracts_only_matching_prefix() {
        let gz = make_gz_tar(&[
            ("repo-main/wit/act-core/types.wit", b"package act:core;"),
            ("repo-main/wit/act-core/nested/x.wit", b"// nested"),
            ("repo-main/wit/act-tools/world.wit", b"// other pkg"),
            ("repo-main/README.md", b"# unrelated"),
        ]);
        let tmp = tempfile::tempdir().unwrap();
        extract_prefix(&gz, "repo-main/wit/act-core", tmp.path()).unwrap();
        assert!(tmp.path().join("types.wit").exists());
        assert!(tmp.path().join("nested/x.wit").exists());
        assert!(!tmp.path().join("world.wit").exists());
        assert!(!tmp.path().join("README.md").exists());
    }

    #[test]
    fn sha256_match() {
        let bytes = b"hello";
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        verify_sha256(bytes, expected).unwrap();
        assert!(verify_sha256(bytes, "deadbeef").is_err());
    }

    #[test]
    fn errors_when_prefix_matches_nothing() {
        let gz = make_gz_tar(&[("repo-main/README.md", b"hi")]);
        let tmp = tempfile::tempdir().unwrap();
        assert!(extract_prefix(&gz, "repo-main/wit/act-core", tmp.path()).is_err());
    }
}
