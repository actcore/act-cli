//! `act-build push` — publish a packed WASM component as a CNCF-conformant
//! Wasm OCI Artifact.
//!
//! Manifest layout per <https://tag-runtime.cncf.io/wgs/wasm/deliverables/wasm-oci-artifact/>:
//! - config: `application/vnd.wasm.config.v0+json` with `architecture`, `os`,
//!   `layerDigests`, and `component.{exports, imports, target}` for wasip2
//! - layer 0: `application/wasm` (the component bytes)
//! - annotations: `org.opencontainers.image.{version, description, source}`
//!   from the `act:component` custom section, with CLI overrides

use anyhow::{Context, Result, bail};
use oci_client::Reference;
use oci_client::client::{ClientConfig, ClientProtocol, Config, ImageLayer};
use oci_client::manifest::{OciImageManifest, OciManifest};
use std::collections::BTreeMap;
use std::path::Path;

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
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    runtime.block_on(run_async(wasm_path, reference, opts))
}

async fn run_async(wasm_path: &Path, reference: &str, opts: PushOptions) -> Result<()> {
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
    let oci_ref: Reference = normalized
        .parse()
        .with_context(|| format!("invalid OCI reference: {normalized}"))?;

    // 4. Build vnd.wasm.config.v0+json blob.
    let config = build_config(&wasm).context("building Wasm OCI config blob")?;
    let config_json = serde_json::to_vec(&config).context("serializing config to JSON")?;
    let config_digest = sha256_digest(&config_json);
    tracing::debug!(%config_digest, bytes = config_json.len(), "built config blob");

    let layer_digest = sha256_digest(&wasm);
    tracing::debug!(%layer_digest, "computed layer digest");

    // 5a. Skip-if-exists: skip unconditionally when any tag is already published.
    if opts.skip_if_exists {
        match probe_existing_layer_digest(&oci_ref).await {
            Ok(Some(_)) => {
                println!("{reference} already published, skipping");
                return Ok(());
            }
            Ok(None) | Err(_) => {
                tracing::debug!("remote tag not found, proceeding with push");
            }
        }
    }

    // 5b. Skip-if-identical: skip when remote layer digest matches local;
    //     error when remote exists with a different digest.
    if opts.skip_if_identical {
        match probe_existing_layer_digest(&oci_ref).await {
            Ok(Some(remote)) if remote == layer_digest => {
                println!(
                    "{} already published with identical content (digest {}), skipping",
                    reference, layer_digest
                );
                return Ok(());
            }
            Ok(Some(remote)) => {
                bail!(
                    "{} is already published with a different layer digest.\n\
                     Bump the version — a metadata-only change still requires a version bump.\n  \
                     local:  {}\n  remote: {}",
                    reference,
                    layer_digest,
                    remote
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

    // 6. Build annotations.
    let annotations = build_annotations(&component_info, &opts);

    // 7. Construct OCI ImageLayer + Config + manifest.
    let layer = ImageLayer::new(wasm.clone(), WASM_LAYER_MEDIA_TYPE.to_string(), None);
    let oci_config = Config::new(
        config_json.clone(),
        WASM_CONFIG_MEDIA_TYPE.to_string(),
        None,
    );

    let mut manifest = OciImageManifest::build(std::slice::from_ref(&layer), &oci_config, None);
    manifest.media_type = Some("application/vnd.oci.image.manifest.v1+json".to_string());
    if !annotations.is_empty() {
        manifest.annotations = Some(annotations.clone());
    }

    // Compute the manifest digest from the canonical JSON serialization that
    // we will actually push. This matches what the registry will return as
    // `Docker-Content-Digest` and what `actions/attest` signs.
    let manifest_bytes = serde_json::to_vec(&OciManifest::Image(manifest.clone()))
        .context("serializing manifest to JSON")?;
    let manifest_digest = sha256_digest(&manifest_bytes);

    if opts.dry_run {
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
        return Ok(());
    }

    // 8. Authenticate and push.
    let registry = oci_ref.resolve_registry();
    let auth = crate::oci_auth::resolve(registry).context("resolving registry auth")?;
    let client = oci_client::Client::new(ClientConfig {
        protocol: ClientProtocol::Https,
        ..Default::default()
    });

    let response = client
        .push(
            &oci_ref,
            std::slice::from_ref(&layer),
            oci_config.clone(),
            &auth,
            Some(manifest.clone()),
        )
        .await
        .with_context(|| format!("pushing {reference}"))?;

    println!("Pushed {reference}");
    println!("  manifest_url: {}", response.manifest_url);
    println!("  manifest:     {manifest_digest}");
    println!("  config:       {config_digest}");
    println!("  layer:        {layer_digest}");

    // 9. Apply additional tags by re-pushing the manifest under each tag.
    for tag in &opts.also_tags {
        let tag_ref = retag(&oci_ref, tag);
        client
            .push_manifest(&tag_ref, &OciManifest::Image(manifest.clone()))
            .await
            .with_context(|| format!("tagging {tag_ref}"))?;
        println!("Tagged {tag_ref}");
    }

    // oras-compatible trailing line for `grep "^Digest:"`.
    println!("Digest: {manifest_digest}");
    Ok(())
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
fn retag(base: &Reference, tag: &str) -> Reference {
    Reference::with_tag(
        base.registry().to_string(),
        base.repository().to_string(),
        tag.to_string(),
    )
}

/// Best-effort probe: pull the existing manifest and return the first layer's
/// digest. Returns `Ok(None)` if the manifest doesn't exist (or any non-fatal
/// error — let the caller decide what "missing" means).
async fn probe_existing_layer_digest(oci_ref: &Reference) -> Result<Option<String>> {
    let auth = crate::oci_auth::resolve(oci_ref.resolve_registry())?;
    let client = oci_client::Client::new(ClientConfig {
        protocol: ClientProtocol::Https,
        ..Default::default()
    });
    let (manifest, _) = client.pull_image_manifest(oci_ref, &auth).await?;
    Ok(manifest.layers.first().map(|l| l.digest.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let base: Reference = "ghcr.io/actpkg/sqlite:0.1.0".parse().unwrap();
        let tagged = retag(&base, "latest");
        assert_eq!(tagged.registry(), "ghcr.io");
        assert_eq!(tagged.repository(), "actpkg/sqlite");
        assert_eq!(tagged.tag(), Some("latest"));
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
}
