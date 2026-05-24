//! `index.json` (OCI image index) load/save plus pure descriptor helpers.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::str::FromStr;

use oci_spec::image::{
    Descriptor, DescriptorBuilder, ImageIndex, ImageIndexBuilder, ImageManifest, MediaType,
    SCHEMA_VERSION, Sha256Digest,
};

use crate::layout;

const K_REF: &str = "dev.actcore.source.ref";

/// Errors from index manipulation.
#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error("oci-spec error: {0}")]
    Oci(#[from] oci_spec::OciSpecError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid digest `{0}`")]
    Digest(String),
}

/// Load the index, or an empty index if `index.json` is absent.
pub fn load(root: &Path) -> Result<ImageIndex, IndexError> {
    let path = layout::index_path(root);
    if !path.exists() {
        return Ok(build_index(Vec::new()));
    }
    Ok(ImageIndex::from_file(&path)?)
}

/// Write the index atomically (temp + rename) to `index.json`.
pub fn save(root: &Path, index: &ImageIndex) -> Result<(), IndexError> {
    let dest = layout::index_path(root);
    let tmp = root.join(format!(".index.json.{}.tmp", std::process::id()));
    index.to_file_pretty(&tmp)?;
    std::fs::rename(&tmp, &dest)?;
    Ok(())
}

/// Build an image index over the given manifest descriptors.
pub fn build_index(manifests: Vec<Descriptor>) -> ImageIndex {
    ImageIndexBuilder::default()
        .schema_version(SCHEMA_VERSION)
        .media_type(MediaType::ImageIndex)
        .manifests(manifests)
        .build()
        .expect("image index with valid fields always builds")
}

/// Build a manifest descriptor for `index.json.manifests[]`.
pub fn manifest_descriptor(
    hex: &str,
    size: u64,
    annotations: HashMap<String, String>,
) -> Result<Descriptor, IndexError> {
    let digest = Sha256Digest::from_str(hex).map_err(|_| IndexError::Digest(hex.to_string()))?;
    Ok(DescriptorBuilder::default()
        .media_type(MediaType::ImageManifest)
        .digest(digest)
        .size(size)
        .annotations(annotations)
        .build()?)
}

/// Hex digest (no `sha256:` prefix) of a descriptor's target blob.
pub fn digest_hex(d: &Descriptor) -> String {
    let s = d.digest().to_string();
    s.rsplit(':').next().unwrap_or(&s).to_string()
}

fn ref_of(d: &Descriptor) -> Option<&str> {
    d.annotations().as_ref()?.get(K_REF).map(String::as_str)
}

/// Insert `desc`, replacing any existing descriptor whose
/// `dev.actcore.source.ref` matches (i.e. the same logical ref / tag).
pub fn upsert(manifests: &mut Vec<Descriptor>, desc: Descriptor) {
    let new_ref = ref_of(&desc).map(str::to_string);
    if let Some(r) = &new_ref {
        manifests.retain(|d| ref_of(d) != Some(r.as_str()));
    }
    manifests.push(desc);
}

/// Find a stored descriptor by its source ref (as typed).
pub fn find_by_ref<'a>(manifests: &'a [Descriptor], reference: &str) -> Option<&'a Descriptor> {
    manifests.iter().find(|d| ref_of(d) == Some(reference))
}

/// Compute every blob hex digest reachable from the index: each manifest
/// descriptor, plus that manifest's config and layer digests. Requires a
/// reader to fetch manifest bytes by hex digest.
pub fn reachable_digests(
    index: &ImageIndex,
    read_manifest: impl Fn(&str) -> Result<Vec<u8>, IndexError>,
) -> Result<HashSet<String>, IndexError> {
    let mut set = HashSet::new();
    for desc in index.manifests() {
        let manifest_hex = digest_hex(desc);
        set.insert(manifest_hex.clone());
        let bytes = read_manifest(&manifest_hex)?;
        if let Ok(manifest) = serde_json::from_slice::<ImageManifest>(&bytes) {
            set.insert(strip_algo(manifest.config().digest().as_ref()));
            for layer in manifest.layers() {
                set.insert(strip_algo(layer.digest().as_ref()));
            }
        }
    }
    Ok(set)
}

fn strip_algo(digest: &str) -> String {
    digest.rsplit(':').next().unwrap_or(digest).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout;
    use crate::provenance::{Provenance, Source};
    use tempfile::TempDir;

    #[test]
    fn missing_index_loads_as_empty() {
        let dir = TempDir::new().unwrap();
        layout::init(dir.path()).unwrap();
        let idx = load(dir.path()).unwrap();
        assert!(idx.manifests().is_empty());
    }

    #[test]
    fn save_then_load_roundtrips_a_descriptor() {
        let dir = TempDir::new().unwrap();
        layout::init(dir.path()).unwrap();
        let desc = manifest_descriptor(
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            123,
            std::collections::HashMap::new(),
        )
        .unwrap();
        let idx = build_index(vec![desc]);
        save(dir.path(), &idx).unwrap();
        let back = load(dir.path()).unwrap();
        assert_eq!(back.manifests().len(), 1);
    }

    fn prov(reference: &str, digest_hex: &str) -> std::collections::HashMap<String, String> {
        Provenance {
            source: Source::Oci {
                reference: format!("oci://{reference}"),
            },
            digest: format!("sha256:{digest_hex}"),
            fetched_at: "2026-05-26T00:00:00Z".into(),
            name: None,
            version: None,
        }
        .to_annotations()
    }

    #[test]
    fn upsert_inserts_then_replaces_same_ref_name() {
        let a = manifest_descriptor(
            "1111111111111111111111111111111111111111111111111111111111111111",
            1,
            prov(
                "ghcr.io/x/c:0.1",
                "1111111111111111111111111111111111111111111111111111111111111111",
            ),
        )
        .unwrap();
        let b = manifest_descriptor(
            "2222222222222222222222222222222222222222222222222222222222222222",
            2,
            prov(
                "ghcr.io/x/c:0.1",
                "2222222222222222222222222222222222222222222222222222222222222222",
            ),
        )
        .unwrap();

        let mut manifests = vec![a];
        upsert(&mut manifests, b);
        assert_eq!(manifests.len(), 1, "same ref.name replaces, not appends");
        assert_eq!(
            digest_hex(&manifests[0]),
            "2222222222222222222222222222222222222222222222222222222222222222"
        );
    }

    #[test]
    fn find_by_ref_works() {
        let a = manifest_descriptor(
            "1111111111111111111111111111111111111111111111111111111111111111",
            1,
            prov(
                "ghcr.io/x/c:0.1",
                "1111111111111111111111111111111111111111111111111111111111111111",
            ),
        )
        .unwrap();
        let manifests = vec![a];
        assert!(find_by_ref(&manifests, "oci://ghcr.io/x/c:0.1").is_some());
        assert!(find_by_ref(&manifests, "oci://ghcr.io/x/nope:0.1").is_none());
    }
}
