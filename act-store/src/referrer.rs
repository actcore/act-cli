//! Connected-artifact (referrer) classification and annotation keys. See spec §9.

use std::path::PathBuf;

/// Annotation on a referrer's `index.json` descriptor: the hex digest
/// (`sha256:<hex>`) of the component manifest it is attached to.
pub const K_SUBJECT: &str = "dev.actcore.referrer.subject";
/// Annotation: the classified kind (see [`referrer_kind`]).
pub const K_KIND: &str = "dev.actcore.referrer.kind";

/// A stored connected artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferrerInfo {
    /// Hex digest (no `sha256:` prefix) of the referrer manifest.
    pub digest: String,
    /// OCI `artifactType`, if known.
    pub artifact_type: Option<String>,
    /// Classified kind (`sigstore-bundle` | `cosign-signature` | `sbom` |
    /// `slsa-provenance` | `other`).
    pub kind: String,
    /// Path to the referrer manifest blob on disk.
    pub manifest_path: PathBuf,
}

/// Classify a referrer by its OCI `artifactType` (or manifest media/config type).
pub fn referrer_kind(artifact_type: Option<&str>) -> &'static str {
    match artifact_type {
        Some(t) if t.contains("sigstore.bundle") => "sigstore-bundle",
        Some(t) if t.contains("cosign") => "cosign-signature",
        Some(t) if t.contains("spdx") || t.contains("cyclonedx") || t.contains("sbom") => "sbom",
        Some(t) if t.contains("in-toto") || t.contains("slsa") || t.contains("provenance") => {
            "slsa-provenance"
        }
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_artifact_types() {
        assert_eq!(
            referrer_kind(Some("application/vnd.dev.sigstore.bundle.v0.3+json")),
            "sigstore-bundle"
        );
        assert_eq!(
            referrer_kind(Some("application/vnd.dev.cosign.simplesigning.v1+json")),
            "cosign-signature"
        );
        assert_eq!(referrer_kind(Some("application/spdx+json")), "sbom");
        assert_eq!(
            referrer_kind(Some("application/vnd.cyclonedx+json")),
            "sbom"
        );
        assert_eq!(
            referrer_kind(Some("application/vnd.in-toto+json")),
            "slsa-provenance"
        );
        assert_eq!(referrer_kind(Some("application/octet-stream")), "other");
        assert_eq!(referrer_kind(None), "other");
    }
}
