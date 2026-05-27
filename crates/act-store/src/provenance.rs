//! Provenance of a stored component, carried as OCI annotations.
//! See spec §3.

use std::collections::HashMap;

/// Where a stored component came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// Pulled from an OCI registry. `reference` is the ref exactly as typed.
    Oci { reference: String },
    /// Fetched from an HTTP(S) URL (synthesized manifest). Optional caching
    /// headers support cheap update checks later.
    Http {
        url: String,
        etag: Option<String>,
        last_modified: Option<String>,
    },
    /// Installed from a local file (pinned snapshot). `path` is the file URI.
    Local { path: String },
}

/// Full provenance for one stored component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    pub source: Source,
    /// Resolved content digest the source pulled (`sha256:...`).
    pub digest: String,
    /// RFC 3339 timestamp. Supplied by the caller (the pull layer).
    pub fetched_at: String,
    pub name: Option<String>,
    pub version: Option<String>,
}

const K_REF_NAME: &str = "org.opencontainers.image.ref.name";
const K_KIND: &str = "dev.actcore.source.kind";
const K_REF: &str = "dev.actcore.source.ref";
const K_DIGEST: &str = "dev.actcore.source.digest";
const K_ETAG: &str = "dev.actcore.source.etag";
const K_LAST_MOD: &str = "dev.actcore.source.last-modified";
const K_FETCHED: &str = "dev.actcore.fetched-at";
const K_NAME: &str = "dev.actcore.name";
const K_VERSION: &str = "dev.actcore.version";

/// Error parsing provenance back from annotations.
#[derive(Debug, thiserror::Error)]
pub enum ProvenanceError {
    #[error("annotation `{0}` is missing")]
    Missing(&'static str),
    #[error("unknown source kind `{0}`")]
    UnknownKind(String),
}

/// Strip the `oci://` scheme from an OCI ref for the standard ref.name slot.
fn oci_ref_name(reference: &str) -> &str {
    reference.strip_prefix("oci://").unwrap_or(reference)
}

impl Provenance {
    pub fn to_annotations(&self) -> HashMap<String, String> {
        let mut a = HashMap::new();
        a.insert(K_DIGEST.into(), self.digest.clone());
        a.insert(K_FETCHED.into(), self.fetched_at.clone());
        if let Some(n) = &self.name {
            a.insert(K_NAME.into(), n.clone());
        }
        if let Some(v) = &self.version {
            a.insert(K_VERSION.into(), v.clone());
        }
        match &self.source {
            Source::Oci { reference } => {
                a.insert(K_KIND.into(), "oci".into());
                a.insert(K_REF.into(), reference.clone());
                a.insert(K_REF_NAME.into(), oci_ref_name(reference).to_string());
            }
            Source::Http {
                url,
                etag,
                last_modified,
            } => {
                a.insert(K_KIND.into(), "http".into());
                a.insert(K_REF.into(), url.clone());
                if let Some(e) = etag {
                    a.insert(K_ETAG.into(), e.clone());
                }
                if let Some(lm) = last_modified {
                    a.insert(K_LAST_MOD.into(), lm.clone());
                }
            }
            Source::Local { path } => {
                a.insert(K_KIND.into(), "local".into());
                a.insert(K_REF.into(), path.clone());
            }
        }
        a
    }

    pub fn from_annotations(a: &HashMap<String, String>) -> Result<Self, ProvenanceError> {
        let get = |k: &'static str| a.get(k).cloned().ok_or(ProvenanceError::Missing(k));
        let kind = get(K_KIND)?;
        let reference = get(K_REF)?;
        let source = match kind.as_str() {
            "oci" => Source::Oci { reference },
            "http" => Source::Http {
                url: reference,
                etag: a.get(K_ETAG).cloned(),
                last_modified: a.get(K_LAST_MOD).cloned(),
            },
            "local" => Source::Local { path: reference },
            other => return Err(ProvenanceError::UnknownKind(other.to_string())),
        };
        Ok(Self {
            source,
            digest: get(K_DIGEST)?,
            fetched_at: get(K_FETCHED)?,
            name: a.get(K_NAME).cloned(),
            version: a.get(K_VERSION).cloned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oci_source_round_trips_through_annotations() {
        let prov = Provenance {
            source: Source::Oci {
                reference: "oci://ghcr.io/actpkg/sqlite:0.1.0".into(),
            },
            digest: "sha256:9f86d08".into(),
            fetched_at: "2026-05-26T14:03:21Z".into(),
            name: Some("sqlite".into()),
            version: Some("0.1.0".into()),
        };
        let ann = prov.to_annotations();
        assert_eq!(
            ann.get("dev.actcore.source.kind").map(String::as_str),
            Some("oci")
        );
        assert_eq!(
            ann.get("org.opencontainers.image.ref.name")
                .map(String::as_str),
            Some("ghcr.io/actpkg/sqlite:0.1.0"),
        );
        let back = Provenance::from_annotations(&ann).unwrap();
        assert_eq!(back, prov);
    }

    #[test]
    fn http_source_round_trips_with_optional_fields() {
        let prov = Provenance {
            source: Source::Http {
                url: "https://cdn.example.com/x.wasm".into(),
                etag: Some("\"abc\"".into()),
                last_modified: None,
            },
            digest: "sha256:b1946ac".into(),
            fetched_at: "2026-05-26T14:05:00Z".into(),
            name: None,
            version: None,
        };
        let back = Provenance::from_annotations(&prov.to_annotations()).unwrap();
        assert_eq!(back, prov);
    }

    #[test]
    fn missing_kind_is_an_error() {
        let ann = std::collections::HashMap::new();
        assert!(Provenance::from_annotations(&ann).is_err());
    }
}
