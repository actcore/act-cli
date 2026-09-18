//! `act-build push` — publish a packed WASM component as a CNCF-conformant
//! Wasm OCI Artifact.
//!
//! Manifest layout per <https://tag-runtime.cncf.io/wgs/wasm/deliverables/wasm-oci-artifact/>:
//! - config: `application/vnd.wasm.config.v0+json` with `architecture`, `os`,
//!   `layerDigests`, and `component.{exports, imports, target}` for wasip2
//! - layer 0: `application/wasm` (the component bytes)
//! - annotations: `org.opencontainers.image.{version, description, source}`
//!   from the `act:component` custom section, with CLI overrides

use act_store::registry::reference::ParsedRef;
use anyhow::{Context, Result, bail};
use oci_spec::image::{
    Descriptor, DescriptorBuilder, ImageManifest, ImageManifestBuilder, MediaType, SCHEMA_VERSION,
};
use olpc_cjson::CanonicalFormatter;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

/// Outcome of a `push` run, rendered as the minimal `--format json` document.
/// `digest` is the manifest digest — the headline value for
/// `act-build push … --format json | jq -r .digest`.
#[derive(Debug, Serialize)]
pub struct PushReport {
    /// The (repository-lowercased) OCI reference acted upon.
    pub reference: String,
    pub status: PushStatus,
    /// Manifest digest (`sha256:…`).
    pub digest: String,
    /// Additional tags applied to the same manifest.
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PushStatus {
    /// Manifest + blobs were pushed.
    Pushed,
    /// `--dry-run`: nothing was sent.
    DryRun,
    /// `--skip-if-exists` / `--skip-if-identical` matched; nothing was sent.
    Skipped,
}

use crate::oci_config::{
    WASM_CONFIG_MEDIA_TYPE, WASM_LAYER_MEDIA_TYPE, build_config, sha256_digest,
};
use crate::wasm::read_custom_section;

const ACT_COMPONENT_SECTION: &str = "act:component";

#[derive(Debug, Default)]
pub struct PushOptions {
    pub also_tags: Vec<String>,
    pub annotations: Vec<(String, String)>,
    pub source: Option<String>,
    pub description: Option<String>,
    pub dry_run: bool,
    /// Skip push if a tag with the same content (matching layer digest) is
    /// already published; error if the tag exists with different content.
    pub skip_if_identical: bool,
    /// Skip push unconditionally if any manifest exists for this tag,
    /// regardless of content. For non-reproducible builds where layer
    /// digests legitimately differ between runs.
    pub skip_if_exists: bool,
    /// Output format. `Json` suppresses the human-readable lines and emits a
    /// single [`PushReport`] document on stdout instead.
    pub format: crate::OutputFormat,
}

/// Parse a `key=value` annotation argument.
pub fn parse_annotation(s: &str) -> Result<(String, String), String> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| format!("annotation must be 'key=value', got '{s}'"))?;
    if k.is_empty() {
        return Err(format!("annotation key must be non-empty: '{s}'"));
    }
    Ok((k.to_string(), v.to_string()))
}

/// Serialize an OCI manifest to its canonical JSON byte form — sorted keys, no
/// insignificant whitespace, per the OCI image-spec canonical-JSON rules. These
/// are the exact bytes we transmit (via `push_manifest_raw`) and digest, so our
/// `manifest_digest` is the digest of what the registry stores. Canonical form
/// also matches what other OCI tooling (incl. `oci-client`'s own `push_manifest`)
/// emits, keeping digests stable across toolchains.
fn canonical_manifest_bytes(manifest: &ImageManifest) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut bytes, CanonicalFormatter::new());
    manifest
        .serialize(&mut ser)
        .context("serializing manifest to canonical JSON")?;
    Ok(bytes)
}

/// Lowercase the repository portion of an OCI reference (registry host + path)
/// while leaving the tag and digest untouched. OCI requires lowercase
/// repository names, but tags are case-sensitive — so a GitHub-cased namespace
/// like `GamePad64` becomes `gamepad64`, yet `:V1-RC1` stays as written.
fn lowercase_repository(reference: &str) -> String {
    // Peel off an optional `@digest` (kept verbatim).
    let (name_and_tag, digest) = match reference.split_once('@') {
        Some((head, dig)) => (head, Some(dig)),
        None => (reference, None),
    };
    // A ':' after the last '/' (or when there is no '/') delimits the tag; a
    // ':' before the first '/' is a host port, not a tag.
    let last_slash = name_and_tag.rfind('/');
    let tag_sep = name_and_tag.rfind(':').filter(|&c| match last_slash {
        Some(s) => c > s,
        None => true,
    });
    let (name, tag) = match tag_sep {
        Some(c) => (&name_and_tag[..c], Some(&name_and_tag[c + 1..])),
        None => (name_and_tag, None),
    };
    let mut out = name.to_ascii_lowercase();
    if let Some(tag) = tag {
        out.push(':');
        out.push_str(tag);
    }
    if let Some(digest) = digest {
        out.push('@');
        out.push_str(digest);
    }
    out
}

pub fn run(wasm_path: &Path, reference: &str, opts: PushOptions) -> Result<()> {
    let format = opts.format;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    let report = runtime.block_on(run_async(wasm_path, reference, opts))?;
    if matches!(format, crate::OutputFormat::Json) {
        // The only thing on stdout in JSON mode (logs are on stderr), so it
        // stays a single parseable document for `jq`.
        println!(
            "{}",
            serde_json::to_string_pretty(&report).context("serializing push report to JSON")?
        );
    }
    Ok(())
}

async fn run_async(wasm_path: &Path, reference: &str, opts: PushOptions) -> Result<PushReport> {
    // In JSON mode the human-readable lines are suppressed; `run` prints the
    // returned `PushReport` as the sole stdout document instead.
    let json = matches!(opts.format, crate::OutputFormat::Json);

    // 1. Read WASM bytes.
    let wasm = tokio::fs::read(wasm_path)
        .await
        .with_context(|| format!("reading WASM file {}", wasm_path.display()))?;
    tracing::info!(bytes = wasm.len(), "read WASM file");

    // 2. Pull description from act:component section if present.
    let component_info: Option<act_types::ComponentInfo> =
        read_custom_section(&wasm, ACT_COMPONENT_SECTION)
            .ok()
            .flatten()
            .and_then(|data| ciborium::from_reader(data).ok());
    if let Some(info) = &component_info {
        tracing::info!(
            name = %info.std.name,
            version = %info.std.version,
            "found act:component metadata"
        );
    }

    // 3. Parse OCI reference. OCI requires lowercase repository names (tags are
    //    case-sensitive and preserved); lowercase the repository so a GitHub-cased
    //    namespace such as `GamePad64` becomes `gamepad64` before pushing.
    let normalized = lowercase_repository(reference);
    if normalized != reference {
        tracing::info!(from = %reference, to = %normalized, "lowercased OCI repository");
    }
    let oci_ref = ParsedRef::parse(&normalized)
        .with_context(|| format!("invalid OCI reference: {normalized}"))?;

    // 4. Build vnd.wasm.config.v0+json blob.
    let config = build_config(&wasm).context("building Wasm OCI config blob")?;
    let config_json = serde_json::to_vec(&config).context("serializing config to JSON")?;
    let config_digest = sha256_digest(&config_json);
    tracing::debug!(%config_digest, bytes = config_json.len(), "built config blob");

    let layer_digest = sha256_digest(&wasm);
    tracing::debug!(%layer_digest, "computed layer digest");

    // 5. Build annotations + manifest and digest the canonical bytes up front,
    //    before the skip probes, so `manifest_digest` is reported on every
    //    outcome (pushed, skipped, dry-run) and `--format json` always carries a
    //    digest.
    let annotations = build_annotations(&component_info, &opts);

    let descriptor = |media: &str, digest: &str, size: usize| -> Result<Descriptor> {
        DescriptorBuilder::default()
            .media_type(MediaType::Other(media.to_string()))
            .digest(digest.parse::<oci_spec::image::Digest>()?)
            .size(size as u64)
            .build()
            .map_err(Into::into)
    };
    let layer = descriptor(WASM_LAYER_MEDIA_TYPE, &layer_digest, wasm.len())?;
    let oci_config = descriptor(WASM_CONFIG_MEDIA_TYPE, &config_digest, config_json.len())?;

    let mut builder = ImageManifestBuilder::default()
        .schema_version(SCHEMA_VERSION)
        .media_type(MediaType::ImageManifest)
        .config(oci_config)
        .layers(vec![layer]);
    if !annotations.is_empty() {
        builder = builder.annotations(
            annotations
                .clone()
                .into_iter()
                .collect::<std::collections::HashMap<_, _>>(),
        );
    }
    let manifest: ImageManifest = builder.build()?;

    // Serialize the manifest ONCE, to canonical JSON (sorted keys, no
    // insignificant whitespace, per the OCI image-spec rules), and digest those
    // exact bytes. We then transmit these same bytes via `push_manifest_raw`
    // (below) rather than letting `oci-client` re-serialize internally — so the
    // bytes we hash, the bytes we push, and the bytes the registry stores are all
    // identical. That makes `manifest_digest` authoritative on our side by
    // construction; there is no second serialization that could disagree (the
    // earlier bug: a plain `serde_json::to_vec` reordered keys and produced a
    // digest the registry never stored — unpullable, 404).
    let manifest_content_type = "application/vnd.oci.image.manifest.v1+json".to_string();
    let manifest_bytes = canonical_manifest_bytes(&manifest)?;
    let manifest_digest = sha256_digest(&manifest_bytes);

    // 6a. Skip-if-exists: skip unconditionally when any tag is already published.
    if opts.skip_if_exists {
        match probe_existing_layer_digest(&oci_ref).await {
            Ok(Some(_)) => {
                if !json {
                    println!("{reference} already published, skipping");
                }
                return Ok(PushReport {
                    reference: normalized,
                    status: PushStatus::Skipped,
                    digest: manifest_digest,
                    tags: opts.also_tags,
                });
            }
            Ok(None) | Err(_) => {
                tracing::debug!("remote tag not found, proceeding with push");
            }
        }
    }

    // 6b. Skip-if-identical: skip when remote layer digest matches local;
    //     error when remote exists with a different digest.
    if opts.skip_if_identical {
        match probe_existing_layer_digest(&oci_ref).await {
            Ok(Some(remote)) if remote == layer_digest => {
                if !json {
                    println!(
                        "{reference} already published with identical content (digest {layer_digest}), skipping"
                    );
                }
                return Ok(PushReport {
                    reference: normalized,
                    status: PushStatus::Skipped,
                    digest: manifest_digest,
                    tags: opts.also_tags,
                });
            }
            Ok(Some(remote)) => {
                bail!(
                    "{reference} is already published with a different layer digest.\n\
                     Bump the version — a metadata-only change still requires a version bump.\n  \
                     local:  {layer_digest}\n  remote: {remote}"
                );
            }
            Ok(None) => {
                tracing::debug!("remote tag not found, proceeding with push");
            }
            Err(e) => {
                tracing::debug!(error = %e, "probe failed (likely 404), proceeding with push");
            }
        }
    }

    if opts.dry_run {
        if !json {
            println!("DRY RUN — would push to {reference}");
            println!(
                "  manifest: {manifest_digest} ({} bytes)",
                manifest_bytes.len()
            );
            println!(
                "  layer:    {} ({} bytes, application/wasm)",
                layer_digest,
                wasm.len()
            );
            println!(
                "  config:   {} ({} bytes, {})",
                config_digest,
                config_json.len(),
                WASM_CONFIG_MEDIA_TYPE
            );
            if !annotations.is_empty() {
                println!("  annotations:");
                for (k, v) in &annotations {
                    println!("    {k} = {v}");
                }
            }
            for tag in &opts.also_tags {
                println!("  + tag: {tag}");
            }
            // oras-compatible trailing digest line for `grep "^Digest:"`.
            println!("Digest: {manifest_digest}");
        }
        return Ok(PushReport {
            reference: normalized,
            status: PushStatus::DryRun,
            digest: manifest_digest,
            tags: opts.also_tags,
        });
    }

    // 7. Authenticate.
    let registry = &oci_ref.registry;
    let creds = crate::oci_auth::resolve(registry).context("resolving registry auth")?;
    let http = registry_client()?;
    let reg = oci_ref.clone();
    // One token for the whole push: the blob uploads and the manifest PUT share
    // it, and it is scoped `pull,push` because the manifest is read back after
    // it is written.
    let token = act_store::registry::push::push_token(&http, &reg, &creds)
        .await
        .context("acquiring a push token")?;

    // Push the layer + config blobs, then push the manifest as the EXACT canonical
    // bytes we digested above (`push_manifest_raw`, not `push`/`push_manifest`,
    // which would re-serialize). The registry stores manifest bytes verbatim per
    // the OCI Distribution Spec, so the stored digest equals `manifest_digest`.
    act_store::registry::push::push_blob(
        &http,
        &reg,
        &layer_digest,
        wasm.clone(),
        token.as_deref(),
    )
    .await
    .with_context(|| format!("pushing layer blob for {reference}"))?;
    act_store::registry::push::push_blob(
        &http,
        &reg,
        &config_digest,
        config_json.clone(),
        token.as_deref(),
    )
    .await
    .with_context(|| format!("pushing config blob for {reference}"))?;
    let server_digest = act_store::registry::push::push_manifest(
        &http,
        &reg,
        &reg.reference,
        manifest_bytes.clone(),
        &manifest_content_type,
        token.as_deref(),
    )
    .await
    .with_context(|| format!("pushing manifest for {reference}"))?;
    let manifest_url = format!(
        "https://{}/v2/{}/manifests/{}",
        reg.registry, reg.repository, manifest_digest
    );

    // Defensive integrity check: we are the source of truth for the digest, but if
    // a non-conformant registry mangled our bytes its returned digest won't match.
    // Warn loudly rather than silently — we still report the digest we pushed.
    if !server_digest.is_empty() && server_digest != manifest_digest {
        let server = server_digest.as_str();
        tracing::warn!(
            pushed = %manifest_digest,
            server = %server,
            "registry stored a different manifest digest than the bytes we pushed"
        );
    }

    if !json {
        println!("Pushed {reference}");
        println!("  manifest_url: {manifest_url}");
        println!("  manifest:     {manifest_digest}");
        println!("  config:       {config_digest}");
        println!("  layer:        {layer_digest}");
    }

    // 9. Apply additional tags by re-pushing the same canonical bytes under each tag.
    for tag in &opts.also_tags {
        let tag_ref = retag(&oci_ref, tag);
        act_store::registry::push::push_manifest(
            &http,
            &reg,
            tag,
            manifest_bytes.clone(),
            &manifest_content_type,
            token.as_deref(),
        )
        .await
        .with_context(|| format!("tagging {tag_ref}"))?;
        if !json {
            println!("Tagged {tag_ref}");
        }
    }

    if !json {
        // oras-compatible trailing line for `grep "^Digest:"`.
        println!("Digest: {manifest_digest}");
    }
    Ok(PushReport {
        reference: normalized,
        status: PushStatus::Pushed,
        digest: manifest_digest,
        tags: opts.also_tags,
    })
}

/// Compose annotations: defaults from `act:component`, overrides from CLI.
fn build_annotations(
    info: &Option<act_types::ComponentInfo>,
    opts: &PushOptions,
) -> BTreeMap<String, String> {
    let mut a = BTreeMap::new();
    if let Some(info) = info {
        if !info.std.version.is_empty() {
            a.insert(
                "org.opencontainers.image.version".into(),
                info.std.version.clone(),
            );
        }
        if !info.std.description.is_empty() {
            a.insert(
                "org.opencontainers.image.description".into(),
                info.std.description.clone(),
            );
        }
    }
    if let Some(d) = &opts.description {
        a.insert("org.opencontainers.image.description".into(), d.clone());
    }
    if let Some(s) = &opts.source {
        a.insert("org.opencontainers.image.source".into(), s.clone());
    }
    for (k, v) in &opts.annotations {
        a.insert(k.clone(), v.clone());
    }
    a
}

/// Build a new Reference identical to `base` but with `tag` instead of the
/// existing tag/digest.
fn retag(base: &ParsedRef, tag: &str) -> ParsedRef {
    ParsedRef {
        registry: base.registry.clone(),
        repository: base.repository.clone(),
        reference: tag.to_string(),
    }
}

/// Best-effort probe: pull the existing manifest and return the first layer's
/// digest. Returns `Ok(None)` if the manifest doesn't exist (or any non-fatal
/// error — let the caller decide what "missing" means).
/// The HTTP client every registry call in this file shares.
///
/// Same seams the store picks — tokio, rustls over the webpki roots, the
/// system resolver — so a push and a pull of the same artifact go over the
/// same stack rather than two that could disagree about TLS or DNS.
fn registry_client() -> Result<hclient::Client> {
    // **The platform's trust store, not the bundled roots.** Pushing is the one
    // place a private registry is normal — a corporate mirror behind an
    // internal CA — and `oci-client` honoured that CA because reqwest reads the
    // system store. Dropping to webpki-only would have broken every such push
    // with `UnknownIssuer`, silently, on upgrade. Falling back to webpki keeps
    // a machine with no usable system store working.
    let tls = hclient_tls_rustls::Rustls::with_platform_verifier()
        .unwrap_or_else(|_| hclient_tls_rustls::Rustls::with_webpki_roots());
    let transport = hclient_native::Native::new(
        hclient_rt_tokio::Tokio,
        tls,
        hclient_dns_system::SystemDns::new(hclient_rt_tokio::Tokio),
    );
    hclient::Client::builder(transport)
        .build()
        .map_err(|e| anyhow::anyhow!("the HTTP backend cannot serve this configuration: {e}"))
}

async fn probe_existing_layer_digest(oci_ref: &ParsedRef) -> Result<Option<String>> {
    let creds = crate::oci_auth::resolve(&oci_ref.registry)?;
    let reg = oci_ref.clone();
    let http = registry_client()?;
    let (bytes, _digest, _token) = act_store::registry::client::fetch_manifest_as(
        &http,
        &reg.registry,
        &reg.repository,
        &reg.reference,
        &creds,
    )
    .await?;
    let manifest: oci_spec::image::ImageManifest = serde_json::from_slice(&bytes)?;
    Ok(manifest.layers().first().map(|l| l.digest().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_report_serializes_minimal_flat_json() {
        let report = PushReport {
            reference: "ghcr.io/actpkg/sqlite:0.1.0".into(),
            status: PushStatus::Pushed,
            digest: "sha256:abc123".into(),
            tags: vec!["latest".into()],
        };
        let v = serde_json::to_value(&report).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "reference": "ghcr.io/actpkg/sqlite:0.1.0",
                "status": "pushed",
                "digest": "sha256:abc123",
                "tags": ["latest"],
            })
        );
    }

    #[test]
    fn push_status_renders_kebab_case() {
        assert_eq!(
            serde_json::to_value(PushStatus::Pushed).unwrap(),
            serde_json::json!("pushed")
        );
        assert_eq!(
            serde_json::to_value(PushStatus::DryRun).unwrap(),
            serde_json::json!("dry-run")
        );
        assert_eq!(
            serde_json::to_value(PushStatus::Skipped).unwrap(),
            serde_json::json!("skipped")
        );
    }

    #[test]
    fn parse_annotation_ok() {
        assert_eq!(
            parse_annotation("foo=bar").unwrap(),
            ("foo".to_string(), "bar".to_string())
        );
    }

    #[test]
    fn parse_annotation_with_equals_in_value() {
        assert_eq!(
            parse_annotation("k=a=b").unwrap(),
            ("k".to_string(), "a=b".to_string())
        );
    }

    #[test]
    fn parse_annotation_rejects_no_equals() {
        assert!(parse_annotation("nope").is_err());
    }

    #[test]
    fn parse_annotation_rejects_empty_key() {
        assert!(parse_annotation("=value").is_err());
    }

    #[test]
    fn build_annotations_takes_from_component_info() {
        let mut info = act_types::ComponentInfo::default();
        info.std.version = "1.2.3".into();
        info.std.description = "test desc".into();
        let opts = PushOptions::default();
        let a = build_annotations(&Some(info), &opts);
        assert_eq!(
            a.get("org.opencontainers.image.version"),
            Some(&"1.2.3".to_string())
        );
        assert_eq!(
            a.get("org.opencontainers.image.description"),
            Some(&"test desc".to_string())
        );
    }

    #[test]
    fn build_annotations_cli_overrides_component_info() {
        let mut info = act_types::ComponentInfo::default();
        info.std.description = "original".into();
        let opts = PushOptions {
            description: Some("override".into()),
            source: Some("https://example.com/repo".into()),
            ..Default::default()
        };
        let a = build_annotations(&Some(info), &opts);
        assert_eq!(
            a.get("org.opencontainers.image.description"),
            Some(&"override".to_string())
        );
        assert_eq!(
            a.get("org.opencontainers.image.source"),
            Some(&"https://example.com/repo".to_string())
        );
    }

    #[test]
    fn build_annotations_custom_kv_pairs() {
        let opts = PushOptions {
            annotations: vec![("custom.key".into(), "custom-value".into())],
            ..Default::default()
        };
        let a = build_annotations(&None, &opts);
        assert_eq!(a.get("custom.key"), Some(&"custom-value".to_string()));
    }

    #[test]
    fn retag_preserves_registry_and_repository() {
        let base = ParsedRef::parse("ghcr.io/actpkg/sqlite:0.1.0").unwrap();
        let tagged = retag(&base, "latest");
        assert_eq!(tagged.registry, "ghcr.io");
        assert_eq!(tagged.repository, "actpkg/sqlite");
        assert_eq!(tagged.reference, "latest");
    }

    #[test]
    fn lowercase_repository_lowercases_path_keeps_tag() {
        assert_eq!(
            lowercase_repository("actpkg.dev/GamePad64/filesystem:0.3.0"),
            "actpkg.dev/gamepad64/filesystem:0.3.0"
        );
    }

    #[test]
    fn lowercase_repository_preserves_tag_case() {
        assert_eq!(
            lowercase_repository("actpkg.dev/Foo/Bar:V1.2-RC1"),
            "actpkg.dev/foo/bar:V1.2-RC1"
        );
    }

    #[test]
    fn lowercase_repository_preserves_digest() {
        assert_eq!(
            lowercase_repository("actpkg.dev/Foo/Bar@sha256:DEAD"),
            "actpkg.dev/foo/bar@sha256:DEAD"
        );
    }

    #[test]
    fn lowercase_repository_handles_host_port_and_no_tag() {
        assert_eq!(
            lowercase_repository("localhost:5000/Foo/Bar"),
            "localhost:5000/foo/bar"
        );
    }

    /// Build a representative manifest the way `run_async` does.
    fn sample_manifest() -> ImageManifest {
        let d = |media: &str, hex: &str, size: u64| {
            DescriptorBuilder::default()
                .media_type(MediaType::Other(media.to_string()))
                .digest(
                    format!("sha256:{hex}")
                        .parse::<oci_spec::image::Digest>()
                        .unwrap(),
                )
                .size(size)
                .build()
                .unwrap()
        };
        let mut annotations = std::collections::HashMap::new();
        annotations.insert(
            "org.opencontainers.image.version".to_string(),
            "0.3.0".to_string(),
        );
        ImageManifestBuilder::default()
            .schema_version(SCHEMA_VERSION)
            .media_type(MediaType::ImageManifest)
            .config(d(WASM_CONFIG_MEDIA_TYPE, &"a".repeat(64), 2))
            .layers(vec![d(WASM_LAYER_MEDIA_TYPE, &"b".repeat(64), 3)])
            .annotations(annotations)
            .build()
            .unwrap()
    }

    #[test]
    fn canonical_manifest_bytes_sorts_top_level_keys() {
        let manifest = sample_manifest();
        let bytes = canonical_manifest_bytes(&manifest).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        // Canonical JSON orders keys lexicographically:
        // annotations < config < layers < mediaType < schemaVersion.
        // `mediaType` also occurs *nested* (in config and each layer), so match
        // the top-level one by its distinctive manifest media-type value.
        let ann = s.find("\"annotations\"").unwrap();
        let cfg = s.find("\"config\"").unwrap();
        let lay = s.find("\"layers\"").unwrap();
        let mt = s
            .find("\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\"")
            .unwrap();
        let sv = s.find("\"schemaVersion\"").unwrap();
        assert!(
            ann < cfg && cfg < lay && lay < mt && mt < sv,
            "keys not in canonical order: {s}"
        );
    }

    #[test]
    fn canonical_manifest_bytes_differ_from_plain_serde() {
        // This is the bug: plain `serde_json` emits struct field order
        // (schemaVersion, mediaType, config, layers, annotations), which hashes
        // to a digest the registry never stores. Canonical output must differ.
        let manifest = sample_manifest();
        let canonical = canonical_manifest_bytes(&manifest).unwrap();
        let plain = serde_json::to_vec(&manifest).unwrap();
        assert_ne!(
            canonical, plain,
            "canonical serialization must differ from plain serde_json field order"
        );
    }
}
