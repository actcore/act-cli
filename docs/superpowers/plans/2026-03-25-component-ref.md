# Component Reference Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** All commands (`run`, `call`, `info`, `pull`) accept component references as local paths, HTTP/S URLs, OCI registry refs, or names (future registry stub) — not just local `PathBuf`.

**Architecture:** A new `resolve` module parses a string into a `ComponentRef` enum and resolves it to a local `PathBuf`. Remote refs (HTTP, OCI) are always downloaded to cache first (`~/.cache/act/components/`), then the cached path is returned. Local paths pass through. This means `runtime::load_component` stays unchanged — it always loads from a file path. The `pull` command is just `resolve` + optional copy to user-specified output. No `load_component_from_bytes` needed.

**Tech Stack:** reqwest (HTTP), oci-wasm + oci-client (OCI), regex (OCI ref parsing), url (HTTP URL parsing), sha2 (cache key hashing), dirs (cache dir)

---

## File Structure

- **Create:** `src/resolve.rs` — `ComponentRef` enum, parsing, `resolve()` → `PathBuf` (downloads to cache for remote refs)
- **Modify:** `src/main.rs` — Change `component: PathBuf` → `component: String` in CLI enum, resolve to path before passing to handlers
- **Modify:** `Cargo.toml` — Add `reqwest`, `oci-wasm`, `sha2` dependencies
- **No changes:** `src/runtime.rs` — `load_component(engine, path)` stays as-is

---

### Task 1: Add dependencies

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add dependencies to Cargo.toml**

Add to `[dependencies]`:

```toml
regex = "1"
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }
oci-wasm = "0.2"
sha2 = "0.10"
url = "2"
```

`reqwest` uses `rustls-tls` to avoid OpenSSL dependency. `oci-wasm` pulls in `oci-client` transitively.

- [ ] **Step 2: Verify it compiles**

Run: `cd /mnt/devenv/workspace/act/act-cli && cargo check`

Expected: compiles (new deps download, unused for now).

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
bash ~/unwork.sh git commit -m "chore: add reqwest, oci-wasm, sha2 dependencies"
```

---

### Task 2: Create `resolve.rs` — ComponentRef parsing and resolution

**Files:**
- Create: `src/resolve.rs`
- Modify: `src/main.rs:1-5` (add `mod resolve;`)

- [ ] **Step 1: Create resolve.rs**

```rust
//! Component reference parsing and resolution.
//!
//! Remote refs are always downloaded to cache first. `resolve()` returns a
//! local `PathBuf` that can be passed to `runtime::load_component`.

use anyhow::{Context, Result};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::LazyLock;
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
        r"^(?:localhost(?::\d+)?|[a-zA-Z0-9][\w.-]*\.[a-zA-Z]{2,}(?::\d+)?)/[a-zA-Z0-9][\w./-]*(?::[a-zA-Z][\w.-]*|@sha256:[a-fA-F0-9]+)?$"
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
    format!("{:x}.wasm", hash)
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
    match component_ref {
        ComponentRef::Local(path) => {
            anyhow::ensure!(
                tokio::fs::try_exists(path).await.unwrap_or(false),
                "component not found: {}",
                path.display()
            );
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

async fn resolve_http(url: &str, fresh: bool) -> Result<PathBuf> {
    let cached = cache_path(url).await?;
    if !fresh && tokio::fs::try_exists(&cached).await.unwrap_or(false) {
        tracing::debug!(%url, path = %cached.display(), "Using cached component");
        return Ok(cached);
    }

    tracing::info!(%url, "Downloading component");
    let response = reqwest::get(url)
        .await
        .with_context(|| format!("HTTP request to {url}"))?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("HTTP {status} fetching {url}");
    }
    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("reading response body from {url}"))?;
    tracing::info!(size = bytes.len(), "Downloaded component");

    tokio::fs::write(&cached, &bytes)
        .await
        .with_context(|| format!("writing cache file: {}", cached.display()))?;
    Ok(cached)
}

async fn resolve_oci(reference: &str, fresh: bool) -> Result<PathBuf> {
    let cached = cache_path(reference).await?;
    if !fresh && tokio::fs::try_exists(&cached).await.unwrap_or(false) {
        tracing::debug!(%reference, path = %cached.display(), "Using cached component");
        return Ok(cached);
    }

    tracing::info!(%reference, "Pulling component from OCI registry");

    let oci_ref: oci_client::Reference = reference
        .parse()
        .with_context(|| format!("invalid OCI reference: {reference}"))?;

    let client_config = oci_client::client::ClientConfig {
        protocol: oci_client::client::ClientProtocol::Https,
        ..Default::default()
    };
    let oci = oci_client::Client::new(client_config);
    let wasm_client = oci_wasm::WasmClient::new(oci);

    let auth = oci_client::secrets::RegistryAuth::Anonymous;
    let data = wasm_client
        .pull(&oci_ref, &auth)
        .await
        .with_context(|| format!("pulling from OCI: {reference}"))?;

    let bytes = data
        .layers
        .into_iter()
        .find(|l| {
            l.media_type == oci_wasm::WASM_LAYER_MEDIA_TYPE
                || l.media_type == oci_wasm::WASM_MANIFEST_MEDIA_TYPE
        })
        .map(|l| l.data)
        .context("no wasm layer found in OCI artifact")?;

    tracing::info!(size = bytes.len(), "Pulled component from OCI");

    tokio::fs::write(&cached, &bytes)
        .await
        .with_context(|| format!("writing cache file: {}", cached.display()))?;
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
        assert!(matches!(parse("https://example.com/comp.wasm"), ComponentRef::Http(_)));
    }

    #[test]
    fn parse_http_url() {
        assert!(matches!(parse("http://localhost:8080/comp.wasm"), ComponentRef::Http(_)));
    }

    #[test]
    fn parse_explicit_oci() {
        assert!(matches!(parse("oci://ghcr.io/actcore/sqlite:latest"), ComponentRef::Oci(r) if r == "ghcr.io/actcore/sqlite:latest"));
    }

    #[test]
    fn parse_oci_with_tag() {
        assert!(matches!(parse("ghcr.io/actcore/component-sqlite:latest"), ComponentRef::Oci(_)));
    }

    #[test]
    fn parse_oci_with_digest() {
        assert!(matches!(parse("ghcr.io/actcore/sqlite@sha256:abc123"), ComponentRef::Oci(_)));
    }

    #[test]
    fn parse_oci_no_tag() {
        assert!(matches!(parse("ghcr.io/actcore/sqlite"), ComponentRef::Oci(_)));
    }

    #[test]
    fn parse_local_relative() {
        assert!(matches!(parse("./component.wasm"), ComponentRef::Local(_)));
    }

    #[test]
    fn parse_local_absolute() {
        assert!(matches!(parse("/tmp/component.wasm"), ComponentRef::Local(_)));
    }

    #[test]
    fn parse_local_wasm_extension() {
        assert!(matches!(parse("component.wasm"), ComponentRef::Local(_)));
    }

    #[test]
    fn parse_bare_name() {
        assert!(matches!(parse("component-sqlite"), ComponentRef::Name(n) if n == "component-sqlite"));
    }

    #[test]
    fn parse_bare_name_simple() {
        assert!(matches!(parse("sqlite"), ComponentRef::Name(n) if n == "sqlite"));
    }
}
```

- [ ] **Step 2: Add `mod resolve;` to main.rs**

Add after `mod mcp;`:

```rust
mod resolve;
```

- [ ] **Step 3: Verify compilation and run parse tests**

Run: `cd /mnt/devenv/workspace/act/act-cli && cargo check && cargo test --target x86_64-unknown-linux-gnu resolve`

Expected: compiles, all 11 parse tests pass. OCI resolution code compiles but isn't called yet.

- [ ] **Step 4: Commit**

```bash
git add src/resolve.rs src/main.rs
bash ~/unwork.sh git commit -m "feat: add ComponentRef parsing and resolution module

Supports local paths, HTTP/S URLs, OCI registry refs, and names (stub).
Remote refs download to ~/.cache/act/components/ before returning path."
```

---

### Task 3: Wire ComponentRef into CLI commands

**Files:**
- Modify: `src/main.rs` — change `component: PathBuf` → `component: String`, add resolve step, implement `cmd_pull`

- [ ] **Step 1: Change CLI enum fields from PathBuf to String**

In the `Cli` enum, change `component: PathBuf` to `component: String` in `Run`, `Call`, and `Info` variants. Update doc comments to:

```
/// Component reference (path, URL, OCI ref, or name)
component: String,
```

- [ ] **Step 2: Add resolve_component helper**

Add after `resolve_opts` (around line 211):

```rust
/// Parse and resolve a component reference string to a local path.
async fn resolve_component(component: &str) -> Result<PathBuf> {
    let component_ref = component.parse::<resolve::ComponentRef>().unwrap();
    resolve::resolve(&component_ref, false).await
}
```

- [ ] **Step 3: Update cmd_run**

Change signature: `component_path: PathBuf` → `component: String`.

At the start of each branch (mcp and http), replace:
```rust
let wasm_bytes = std::fs::read(&component_path).context("reading component file")?;
let component_info = runtime::read_component_info(&wasm_bytes)?;
```
with:
```rust
let component_path = resolve_component(&component).await?;
let wasm_bytes = std::fs::read(&component_path).context("reading component file")?;
let component_info = runtime::read_component_info(&wasm_bytes)?;
```

`runtime::load_component(&engine, &component_path)` stays unchanged — it still takes a `&Path`.

- [ ] **Step 4: Update cmd_call**

Same pattern — change signature to `component: String`, add `resolve_component` at the top:

```rust
async fn cmd_call(component: String, tool: String, args: String, opts: CommonOpts) -> Result<()> {
    let (_config, mut fs_config, metadata_value) = resolve_opts(&opts)?;
    let component_path = resolve_component(&component).await?;
    let wasm_bytes = std::fs::read(&component_path).context("reading component file")?;
    // ... rest unchanged, still uses component_path for load_component ...
```

- [ ] **Step 5: Update cmd_info**

Same pattern:

```rust
async fn cmd_info(component: String, show_tools: bool, output_format: OutputFormat, opts: CommonOpts) -> Result<()> {
    let component_path = resolve_component(&component).await?;
    let wasm_bytes = std::fs::read(&component_path).context("reading component file")?;
    // ... rest unchanged ...
```

- [ ] **Step 6: Implement cmd_pull**

Replace the stub:

```rust
async fn cmd_pull(
    reference: String,
    output: Option<PathBuf>,
    output_from_ref: bool,
) -> Result<()> {
    let component_ref = reference.parse::<resolve::ComponentRef>().unwrap();

    // Resolve to local path (downloads to cache for remote refs)
    // Always download fresh — pull is explicit user action
    let cached_path = resolve::resolve(&component_ref, true).await?;

    if let Some(out) = output {
        tokio::fs::copy(&cached_path, &out).await
            .with_context(|| format!("copying to {}", out.display()))?;
        println!("{}", out.display());
    } else if output_from_ref {
        let filename = reference
            .rsplit('/')
            .next()
            .unwrap_or(&reference)
            .split(':')
            .next()
            .unwrap_or(&reference);
        let filename = if filename.ends_with(".wasm") {
            filename.to_string()
        } else {
            format!("{filename}.wasm")
        };
        let out = PathBuf::from(&filename);
        tokio::fs::copy(&cached_path, &out).await
            .with_context(|| format!("copying to {}", out.display()))?;
        println!("{}", out.display());
    } else {
        // No output flag — print cached path
        println!("{}", cached_path.display());
    }

    Ok(())
}
```

- [ ] **Step 7: Verify compilation and tests**

Run: `cd /mnt/devenv/workspace/act/act-cli && cargo check && cargo test --target x86_64-unknown-linux-gnu`

Expected: all tests pass.

- [ ] **Step 8: Commit**

```bash
git add src/main.rs
bash ~/unwork.sh git commit -m "feat: wire ComponentRef resolution into all CLI commands

All commands (run, call, info, pull) now accept:
- Local paths: ./component.wasm, /abs/path.wasm
- HTTP/S URLs: https://example.com/component.wasm
- OCI refs: ghcr.io/actcore/component-sqlite:latest
- Names: component-sqlite (stub, not yet implemented)

Remote refs are cached in ~/.cache/act/components/.
pull command outputs cached path, or copies to -o/-O target."
```

---

### Task 4: Verify OCI resolution compiles with correct API

**Files:**
- Possibly modify: `src/resolve.rs` — adjust if `oci-wasm` API differs from docs

- [ ] **Step 1: Check oci-wasm actual API**

Run: `cd /mnt/devenv/workspace/act/act-cli && cargo doc -p oci-wasm 2>&1 | tail -10`

Then check the generated docs or source for:
- `WasmClient::new()` — does it take `oci_client::Client` by value?
- `WasmClient::pull()` — what's the return type? `PullResponse`? What fields?
- `WASM_LAYER_MEDIA_TYPE` — exact constant name?
- Layer data — is it `Vec<u8>` or `Bytes`?

- [ ] **Step 2: Fix any API mismatches in resolve_oci**

Adjust the code to match actual API. Common differences:
- Constructor might be different
- Pull return type fields might differ
- Media type constants might have different names/paths

- [ ] **Step 3: Verify compilation**

Run: `cd /mnt/devenv/workspace/act/act-cli && cargo check`

- [ ] **Step 4: Commit if changes were needed**

```bash
git add src/resolve.rs
bash ~/unwork.sh git commit -m "fix: adjust OCI resolution to match oci-wasm API"
```

Skip if no changes needed.
