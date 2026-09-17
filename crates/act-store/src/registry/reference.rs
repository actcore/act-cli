//! Splitting `registry/repository:tag` into the three parts a request needs.

use crate::store::StoreError;

/// A parsed registry reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRef {
    pub registry: String,
    pub repository: String,
    /// A tag, or a `sha256:…` digest. Whichever it is goes in the same place
    /// in the URL, which is why one field holds both.
    pub reference: String,
}

impl ParsedRef {
    /// Parse `registry/repository[:tag|@digest]`.
    ///
    /// **The registry host must be explicit**, which the previous
    /// `oci-client`-based path also required: `blob_url` has always assumed a
    /// verbatim host and https, so a bare `time:latest` was never going to
    /// resolve against Docker Hub here. Refusing it says so instead of
    /// building a URL to a host that does not exist.
    pub fn parse(reference: &str) -> Result<Self, StoreError> {
        let s = reference.strip_prefix("oci://").unwrap_or(reference);

        // `@` before `:` — a digest contains a colon, so splitting on the
        // colon first would cut `sha256:…` in half.
        let (name, tail) = if let Some((n, d)) = s.split_once('@') {
            (n, format!("@{d}"))
        } else {
            match s.rsplit_once(':') {
                // A colon in the host is a port, not a tag: `localhost:5000/x`
                // has no tag at all.
                Some((n, t)) if !t.contains('/') => (n, format!(":{t}")),
                _ => (s, String::new()),
            }
        };

        let (registry, repository) = name.split_once('/').ok_or_else(|| {
            StoreError::Io(std::io::Error::other(format!(
                "{reference} names no registry; write it as <registry>/<repository>[:tag]"
            )))
        })?;

        if registry.is_empty() || repository.is_empty() {
            return Err(StoreError::Io(std::io::Error::other(format!(
                "{reference} has an empty registry or repository"
            ))));
        }

        let reference = match tail.as_str() {
            "" => "latest".to_string(),
            t => t[1..].to_string(),
        };

        Ok(Self {
            registry: registry.to_string(),
            repository: repository.to_string(),
            reference,
        })
    }

    /// The same repository, addressed by digest.
    pub fn at_digest(&self, digest: &str) -> Self {
        let d = if digest.contains(':') {
            digest.to_string()
        } else {
            format!("sha256:{digest}")
        };
        Self {
            registry: self.registry.clone(),
            repository: self.repository.clone(),
            reference: d,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_the_forms_this_host_actually_pulls() {
        let r = ParsedRef::parse("actpkg.dev/library/time:0.3.2").expect("parses");
        assert_eq!(r.registry, "actpkg.dev");
        assert_eq!(r.repository, "library/time");
        assert_eq!(r.reference, "0.3.2");

        // A multi-segment repository, which ghcr.io uses.
        let g = ParsedRef::parse("ghcr.io/actcore/act/shim-tools-sync:0.1.0").expect("parses");
        assert_eq!(g.repository, "actcore/act/shim-tools-sync");

        // The `oci://` scheme is accepted and stripped.
        assert_eq!(
            ParsedRef::parse("oci://actpkg.dev/library/time:1")
                .unwrap()
                .repository,
            "library/time"
        );
    }

    /// **A digest contains a colon.** Splitting on the last colon first would
    /// leave `sha256` as the repository's tail and `…` as the tag, and the
    /// request would go to a manifest that does not exist.
    #[test]
    fn a_digest_reference_is_not_cut_at_its_colon() {
        let r = ParsedRef::parse(
            "actpkg.dev/library/time@sha256:84370542c13b56a34df9c551eb694400441da0ae799e40b17867877cb901e5fb",
        )
        .expect("parses");
        assert_eq!(r.repository, "library/time");
        assert_eq!(
            r.reference,
            "sha256:84370542c13b56a34df9c551eb694400441da0ae799e40b17867877cb901e5fb"
        );
    }

    /// **A colon in the host is a port.** `localhost:5000/x` has no tag, and
    /// reading `5000/x` as one would lose the registry.
    #[test]
    fn a_port_is_not_a_tag() {
        let r = ParsedRef::parse("localhost:5000/library/time").expect("parses");
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.repository, "library/time");
        assert_eq!(r.reference, "latest");
    }

    #[test]
    fn a_missing_tag_defaults_to_latest() {
        assert_eq!(
            ParsedRef::parse("actpkg.dev/library/time")
                .unwrap()
                .reference,
            "latest"
        );
    }

    /// The host has never resolved bare names against Docker Hub — `blob_url`
    /// assumes a verbatim host — so this refuses rather than building a URL to
    /// a registry nobody named.
    #[test]
    fn a_reference_with_no_registry_is_refused() {
        let err = ParsedRef::parse("time:latest").expect_err("must refuse");
        assert!(
            err.to_string().contains("names no registry"),
            "the error has to say what to write instead: {err}"
        );
    }

    #[test]
    fn at_digest_keeps_the_repository_and_normalises_the_prefix() {
        let r = ParsedRef::parse("actpkg.dev/library/time:latest").unwrap();
        assert_eq!(r.at_digest("sha256:abc").reference, "sha256:abc");
        // A bare hex digest gains the algorithm it implies.
        assert_eq!(r.at_digest("abc").reference, "sha256:abc");
        assert_eq!(r.at_digest("abc").repository, "library/time");
    }
}
