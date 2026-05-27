//! Component reference parsing. The shared source of truth for act-cli and
//! act-toolserver. Ported from act-cli's resolve.rs (parsing half only).

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::LazyLock;

use regex::Regex;
use url::Url;

#[derive(Debug, Clone)]
pub enum Ref {
    Local(PathBuf),
    Http(Url),
    Oci(String),
    Name(String),
}

static OCI_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:localhost(?::\d+)?|[a-zA-Z0-9][\w.-]*\.[a-zA-Z]{2,}(?::\d+)?)/[a-zA-Z0-9][\w./-]*(?::[\w][\w.-]*|@sha256:[a-fA-F0-9]+)?$"
    ).unwrap()
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseRefError(String);

impl std::fmt::Display for ParseRefError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ParseRefError {}

impl FromStr for Ref {
    type Err = ParseRefError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(url) = Url::parse(s) {
            match url.scheme() {
                "file" => {
                    let path = url.to_file_path().map_err(|()| {
                        ParseRefError(format!(
                            "invalid file:// URI: {s}\nuse an absolute path, e.g. file:///path/to/component.wasm"
                        ))
                    })?;
                    return Ok(Self::Local(path));
                }
                "oci" => return Ok(Self::Oci(s["oci://".len()..].to_string())),
                "http" | "https" => return Ok(Self::Http(url)),
                _ => {}
            }
        }
        if OCI_RE.is_match(s) {
            return Ok(Self::Oci(s.to_string()));
        }
        if s.contains('/') || s.contains('\\') || s.ends_with(".wasm") || s.starts_with('.') {
            return Ok(Self::Local(PathBuf::from(s)));
        }
        Ok(Self::Name(s.to_string()))
    }
}

impl std::fmt::Display for Ref {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local(p) => write!(f, "{}", p.display()),
            Self::Http(u) => write!(f, "{u}"),
            Self::Oci(r) => write!(f, "{r}"),
            Self::Name(n) => write!(f, "{n}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper — parse and unwrap (infallible).
    fn parse(s: &str) -> Ref {
        s.parse().unwrap()
    }

    #[test]
    fn parse_https_url() {
        assert!(matches!(
            parse("https://example.com/comp.wasm"),
            Ref::Http(_)
        ));
    }

    #[test]
    fn parse_http_url() {
        assert!(matches!(
            parse("http://localhost:8080/comp.wasm"),
            Ref::Http(_)
        ));
    }

    #[test]
    fn parse_explicit_oci() {
        assert!(
            matches!(parse("oci://ghcr.io/actcore/sqlite:latest"), Ref::Oci(r) if r == "ghcr.io/actcore/sqlite:latest")
        );
    }

    #[test]
    fn parse_oci_with_tag() {
        assert!(matches!(
            parse("ghcr.io/actcore/component-sqlite:latest"),
            Ref::Oci(_)
        ));
    }

    #[test]
    fn parse_oci_with_digest() {
        assert!(matches!(
            parse("ghcr.io/actcore/sqlite@sha256:abc123"),
            Ref::Oci(_)
        ));
    }

    #[test]
    fn parse_oci_no_tag() {
        assert!(matches!(parse("ghcr.io/actcore/sqlite"), Ref::Oci(_)));
    }

    #[test]
    fn parse_oci_semver_tag() {
        assert!(matches!(parse("ghcr.io/actpkg/sqlite:0.1.0"), Ref::Oci(_)));
    }

    #[test]
    fn parse_local_relative() {
        assert!(matches!(parse("./component.wasm"), Ref::Local(_)));
    }

    #[test]
    fn parse_local_absolute() {
        assert!(matches!(parse("/tmp/component.wasm"), Ref::Local(_)));
    }

    #[test]
    fn parse_local_wasm_extension() {
        assert!(matches!(parse("component.wasm"), Ref::Local(_)));
    }

    #[test]
    fn parse_bare_name() {
        assert!(matches!(parse("component-sqlite"), Ref::Name(n) if n == "component-sqlite"));
    }

    #[test]
    fn parse_bare_name_simple() {
        assert!(matches!(parse("sqlite"), Ref::Name(n) if n == "sqlite"));
    }

    #[test]
    fn parse_file_uri_absolute() {
        match parse("file:///abs/x.wasm") {
            Ref::Local(p) => assert_eq!(p, std::path::Path::new("/abs/x.wasm")),
            other => panic!("expected Local, got {other:?}"),
        }
    }

    #[test]
    fn parse_file_uri_relative_errors() {
        assert!("file://./x.wasm".parse::<Ref>().is_err());
    }

    #[test]
    fn parse_file_uri_opaque_errors() {
        assert!("file://x.wasm".parse::<Ref>().is_err());
    }

    /// Regression guard: a registry ref with a port is `Url::parse`-able with a
    /// non-owned scheme (`localhost`) and must still resolve via the OCI regex.
    #[test]
    fn parse_oci_with_registry_port() {
        assert!(matches!(parse("localhost:5000/foo:tag"), Ref::Oci(_)));
    }
}
