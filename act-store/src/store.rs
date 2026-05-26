//! `Store` orchestrator: composes layout + index + provenance under a lock.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use oci_spec::image::{
    Descriptor, DescriptorBuilder, ImageManifest, ImageManifestBuilder, MediaType, SCHEMA_VERSION,
    Sha256Digest,
};

use crate::index::{self, IndexError};
use crate::layout;
use crate::lock::StoreLock;
use crate::provenance::{Provenance, ProvenanceError};

const WASM_MEDIA_TYPE: &str = "application/wasm";
const CONFIG_MEDIA_TYPE: &str = "application/vnd.actcore.component.config.v1+cbor";
// CBOR empty map (0xA0) — valid CBOR matching CONFIG_MEDIA_TYPE, used when a
// component carries no `act:component` metadata.
const EMPTY_CONFIG: &[u8] = &[0xA0];

/// A component as recorded in the store.
#[derive(Debug, Clone)]
pub struct Stored {
    /// Hex digest of the OCI manifest in `index.json`.
    pub manifest_digest: String,
    /// Hex digest of the wasm layer blob.
    pub wasm_digest: String,
    pub provenance: Provenance,
}

/// Handle to an on-disk OCI-layout store.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Provenance(#[from] ProvenanceError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("oci-spec error: {0}")]
    Oci(#[from] oci_spec::OciSpecError),
    #[error("invalid digest `{0}`")]
    Digest(String),
}

impl Store {
    /// Open (and initialize) a store at `root`.
    pub fn open(root: &Path) -> Result<Self, StoreError> {
        layout::init(root)?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn descriptor_for(
        &self,
        hex: &str,
        size: u64,
        media_type: &str,
    ) -> Result<Descriptor, StoreError> {
        let digest = Sha256Digest::from_str(hex).map_err(|_| StoreError::Digest(hex.into()))?;
        Ok(DescriptorBuilder::default()
            .media_type(MediaType::Other(media_type.to_string()))
            .digest(digest)
            .size(size)
            .build()?)
    }

    /// Store a component: write the wasm layer + config blobs, synthesize the
    /// OCI manifest, and upsert its descriptor (with provenance annotations)
    /// into `index.json`. `config_bytes` is the `act:component` CBOR metadata
    /// (or `None` for an empty config). Holds the exclusive lock.
    pub fn put_component(
        &self,
        wasm: &[u8],
        config_bytes: Option<&[u8]>,
        provenance: &Provenance,
    ) -> Result<Stored, StoreError> {
        let _lock = StoreLock::exclusive(&self.root)?;

        let wasm_hex = layout::write_blob(&self.root, wasm)?;
        let wasm_desc = self.descriptor_for(&wasm_hex, wasm.len() as u64, WASM_MEDIA_TYPE)?;

        let cfg = config_bytes.unwrap_or(EMPTY_CONFIG);
        let cfg_hex = layout::write_blob(&self.root, cfg)?;
        let cfg_desc = self.descriptor_for(&cfg_hex, cfg.len() as u64, CONFIG_MEDIA_TYPE)?;

        let manifest: ImageManifest = ImageManifestBuilder::default()
            .schema_version(SCHEMA_VERSION)
            .media_type(MediaType::ImageManifest)
            .config(cfg_desc)
            .layers(vec![wasm_desc])
            .build()?;
        let manifest_json = serde_json::to_vec(&manifest)
            .map_err(|e| StoreError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
        let manifest_hex = layout::write_blob(&self.root, &manifest_json)?;

        let annotations: HashMap<String, String> = provenance.to_annotations();
        let desc =
            index::manifest_descriptor(&manifest_hex, manifest_json.len() as u64, annotations)?;

        let idx = index::load(&self.root)?;
        let mut manifests = idx.manifests().clone();
        index::upsert(&mut manifests, desc);
        let idx = index::build_index(manifests);
        index::save(&self.root, &idx)?;

        Ok(Stored {
            manifest_digest: manifest_hex,
            wasm_digest: wasm_hex,
            provenance: provenance.clone(),
        })
    }

    /// Store an OCI artifact whose manifest already exists upstream, **verbatim**:
    /// write `manifest_bytes` and every blob in `blobs` content-addressed, then
    /// upsert an index descriptor pointing at the manifest's own digest (so the
    /// upstream digest — which signatures are computed over — is preserved).
    /// `blobs` are `(expected_hex, bytes)` for the config and every layer.
    /// Holds the exclusive lock.
    pub fn put_oci_artifact(
        &self,
        manifest_bytes: &[u8],
        blobs: &[(String, Vec<u8>)],
        provenance: &Provenance,
    ) -> Result<Stored, StoreError> {
        let _lock = StoreLock::exclusive(&self.root)?;

        for (expected_hex, bytes) in blobs {
            let got = layout::write_blob(&self.root, bytes)?;
            if &got != expected_hex {
                return Err(StoreError::Digest(format!(
                    "blob digest mismatch: expected {expected_hex}, got {got}"
                )));
            }
        }
        let manifest_hex = layout::write_blob(&self.root, manifest_bytes)?;

        let manifest: ImageManifest = serde_json::from_slice(manifest_bytes)
            .map_err(|e| StoreError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
        let wasm_digest = manifest
            .layers()
            .first()
            .map(index::digest_hex)
            .unwrap_or_default();

        let annotations: HashMap<String, String> = provenance.to_annotations();
        let desc =
            index::manifest_descriptor(&manifest_hex, manifest_bytes.len() as u64, annotations)?;

        let idx = index::load(&self.root)?;
        let mut manifests = idx.manifests().clone();
        index::upsert(&mut manifests, desc);
        let idx = index::build_index(manifests);
        index::save(&self.root, &idx)?;

        Ok(Stored {
            manifest_digest: manifest_hex,
            wasm_digest,
            provenance: provenance.clone(),
        })
    }

    /// Resolve a stored component by its source ref to the path of its wasm
    /// layer blob. Returns `Ok(None)` if not present. Holds a shared lock.
    pub fn resolve(&self, reference: &str) -> Result<Option<PathBuf>, StoreError> {
        let _lock = StoreLock::shared(&self.root)?;
        let idx = index::load(&self.root)?;
        let manifests = idx.manifests();
        let Some(desc) = index::find_by_ref(manifests, reference) else {
            return Ok(None);
        };
        let manifest_hex = index::digest_hex(desc);
        let manifest_bytes = layout::read_blob(&self.root, &manifest_hex)?;
        let manifest: ImageManifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| StoreError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
        let layer = manifest.layers().first().ok_or_else(|| {
            StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "manifest has no layers",
            ))
        })?;
        let wasm_hex = index::digest_hex(layer);
        Ok(Some(layout::blob_path(&self.root, &wasm_hex)))
    }

    /// List every stored component with its provenance. Holds a shared lock.
    /// Descriptors with unparseable annotations are skipped (defensive).
    pub fn list(&self) -> Result<Vec<Stored>, StoreError> {
        let _lock = StoreLock::shared(&self.root)?;
        let idx = index::load(&self.root)?;
        let mut out = Vec::new();
        for desc in idx.manifests() {
            let Some(ann) = desc.annotations() else {
                continue;
            };
            let Ok(provenance) = Provenance::from_annotations(ann) else {
                continue;
            };
            let manifest_hex = index::digest_hex(desc);
            let wasm_digest = self.wasm_digest_of(&manifest_hex).unwrap_or_default();
            out.push(Stored {
                manifest_digest: manifest_hex,
                wasm_digest,
                provenance,
            });
        }
        Ok(out)
    }

    /// Hex digest of the first layer of the manifest blob `manifest_hex`.
    fn wasm_digest_of(&self, manifest_hex: &str) -> Result<String, StoreError> {
        let bytes = layout::read_blob(&self.root, manifest_hex)?;
        let manifest: ImageManifest = serde_json::from_slice(&bytes)
            .map_err(|e| StoreError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
        Ok(manifest
            .layers()
            .first()
            .map(index::digest_hex)
            .unwrap_or_default())
    }

    /// Delete blobs not reachable from `index.json`. Returns the count
    /// removed. Holds the exclusive lock.
    pub fn gc(&self) -> Result<usize, StoreError> {
        let _lock = StoreLock::exclusive(&self.root)?;
        let idx = index::load(&self.root)?;
        let root = self.root.clone();
        let reachable = index::reachable_digests(&idx, move |hex| {
            layout::read_blob(&root, hex).map_err(IndexError::Io)
        })?;

        let mut removed = 0;
        let blobs = layout::blobs_dir(&self.root);
        if blobs.is_dir() {
            for entry in std::fs::read_dir(&blobs)? {
                let entry = entry?;
                let name = entry.file_name();
                let Some(hex) = name.to_str() else {
                    continue;
                };
                if hex.starts_with('.') {
                    continue;
                }
                if !reachable.contains(hex) {
                    std::fs::remove_file(entry.path())?;
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::{Provenance, Source};
    use tempfile::TempDir;

    fn prov(reference: &str, wasm: &[u8]) -> Provenance {
        Provenance {
            source: Source::Oci {
                reference: reference.into(),
            },
            digest: format!("sha256:{}", crate::layout::sha256_hex(wasm)),
            fetched_at: "2026-05-26T00:00:00Z".into(),
            name: Some("demo".into()),
            version: Some("0.1.0".into()),
        }
    }

    #[test]
    fn put_component_writes_blobs_and_indexes_it() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let wasm = b"\0asm\x01\0\0\0fake-component";
        let stored = store
            .put_component(wasm, None, &prov("oci://ghcr.io/x/demo:0.1.0", wasm))
            .unwrap();
        assert!(crate::layout::has_blob(
            dir.path(),
            &crate::layout::sha256_hex(wasm)
        ));
        assert_eq!(crate::index::load(dir.path()).unwrap().manifests().len(), 1);
        assert_eq!(stored.provenance.name.as_deref(), Some("demo"));
    }

    #[test]
    fn put_same_ref_twice_replaces_not_duplicates() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let v1 = b"component-v1";
        let v2 = b"component-v2";
        store
            .put_component(v1, None, &prov("oci://ghcr.io/x/demo:latest", v1))
            .unwrap();
        store
            .put_component(v2, None, &prov("oci://ghcr.io/x/demo:latest", v2))
            .unwrap();
        assert_eq!(
            crate::index::load(dir.path()).unwrap().manifests().len(),
            1,
            "same ref repointed, not duplicated"
        );
    }

    #[test]
    fn resolve_returns_wasm_blob_path_for_known_ref() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let wasm = b"resolvable-component";
        store
            .put_component(wasm, None, &prov("oci://ghcr.io/x/demo:0.1.0", wasm))
            .unwrap();
        let path = store
            .resolve("oci://ghcr.io/x/demo:0.1.0")
            .unwrap()
            .expect("hit");
        assert_eq!(std::fs::read(path).unwrap(), wasm);
        assert!(
            store
                .resolve("oci://ghcr.io/x/missing:0.1.0")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn list_returns_provenance_for_each_stored_component() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let a = b"comp-a";
        let b = b"comp-b";
        store
            .put_component(a, None, &prov("oci://ghcr.io/x/a:1", a))
            .unwrap();
        store
            .put_component(b, None, &prov("oci://ghcr.io/x/b:1", b))
            .unwrap();
        let mut refs: Vec<String> = store
            .list()
            .unwrap()
            .into_iter()
            .map(|s| match s.provenance.source {
                crate::provenance::Source::Oci { reference } => reference,
                _ => unreachable!(),
            })
            .collect();
        refs.sort();
        assert_eq!(refs, vec!["oci://ghcr.io/x/a:1", "oci://ghcr.io/x/b:1"]);
    }

    #[test]
    fn put_oci_artifact_stores_manifest_verbatim_and_resolves() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let wasm = b"\0asm\x01\0\0\0verbatim";
        let wasm_hex = crate::layout::sha256_hex(wasm);
        let cfg = b"\xA0"; // CBOR empty map
        let cfg_hex = crate::layout::sha256_hex(cfg);
        let manifest_json = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.actcore.component.config.v1+cbor","digest":"sha256:{cfg_hex}","size":{cfg_len}}},"layers":[{{"mediaType":"application/wasm","digest":"sha256:{wasm_hex}","size":{wasm_len}}}]}}"#,
            cfg_len = cfg.len(),
            wasm_len = wasm.len(),
        );
        let manifest_bytes = manifest_json.into_bytes();
        let upstream_digest = crate::layout::sha256_hex(&manifest_bytes);

        let prov = Provenance {
            source: Source::Oci {
                reference: "oci://ghcr.io/x/verb:1".into(),
            },
            digest: format!("sha256:{upstream_digest}"),
            fetched_at: "2026-05-26T00:00:00Z".into(),
            name: Some("verb".into()),
            version: Some("1".into()),
        };

        let stored = store
            .put_oci_artifact(
                &manifest_bytes,
                &[
                    (wasm_hex.clone(), wasm.to_vec()),
                    (cfg_hex.clone(), cfg.to_vec()),
                ],
                &prov,
            )
            .unwrap();

        assert_eq!(stored.manifest_digest, upstream_digest);
        let path = store
            .resolve("oci://ghcr.io/x/verb:1")
            .unwrap()
            .expect("hit");
        assert_eq!(std::fs::read(path).unwrap(), wasm);
    }

    #[test]
    fn gc_deletes_orphan_blobs_keeps_referenced() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let wasm = b"kept-component";
        store
            .put_component(wasm, None, &prov("oci://ghcr.io/x/keep:1", wasm))
            .unwrap();
        let orphan = crate::layout::write_blob(dir.path(), b"orphan-bytes").unwrap();
        assert!(crate::layout::has_blob(dir.path(), &orphan));
        let reclaimed = store.gc().unwrap();
        assert_eq!(reclaimed, 1, "exactly one orphan blob removed");
        assert!(!crate::layout::has_blob(dir.path(), &orphan));
        assert!(store.resolve("oci://ghcr.io/x/keep:1").unwrap().is_some());
    }
}
