//! The Docker/OCI token dance: read a `401`'s challenge, exchange it, reuse
//! the token.

/// What a registry's `WWW-Authenticate: Bearer …` asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// Where to exchange it. The only field without a default.
    pub realm: String,
    pub service: Option<String>,
    pub scope: Option<String>,
}

impl Challenge {
    /// Parse a `WWW-Authenticate` header value.
    ///
    /// Returns `None` for anything that is not a `Bearer` challenge, including
    /// `Basic` — a registry offering only Basic is not doing the token dance,
    /// and pretending otherwise would send a token request to a realm that
    /// does not exist.
    ///
    /// The parameter order is not fixed by RFC 7235 and registries differ, so
    /// this reads them by name rather than by position.
    pub fn parse(header: &str) -> Option<Self> {
        let rest = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))?;

        let mut realm = None;
        let mut service = None;
        let mut scope = None;

        for part in split_params(rest) {
            let (k, v) = part.split_once('=')?;
            // Values are quoted in practice, but the grammar allows a bare
            // token; trimming quotes handles both without a second branch.
            let v = v.trim().trim_matches('"').to_string();
            match k.trim() {
                "realm" => realm = Some(v),
                "service" => service = Some(v),
                "scope" => scope = Some(v),
                // Unknown parameters are ignored rather than refused: a
                // registry adding one must not stop us authenticating.
                _ => {}
            }
        }

        Some(Self {
            realm: realm?,
            service,
            scope,
        })
    }

    /// The URL to GET for a token.
    pub fn token_url(&self) -> String {
        let mut q: Vec<String> = Vec::new();
        if let Some(s) = &self.service {
            q.push(format!("service={}", urlencode(s)));
        }
        if let Some(s) = &self.scope {
            q.push(format!("scope={}", urlencode(s)));
        }
        if q.is_empty() {
            self.realm.clone()
        } else {
            let sep = if self.realm.contains('?') { '&' } else { '?' };
            format!("{}{sep}{}", self.realm, q.join("&"))
        }
    }
}

/// Split on commas that are not inside a quoted value.
///
/// A `scope` can carry commas — `repository:a:pull,push` is one parameter, and
/// splitting naively turns it into two and loses the `push`.
fn split_params(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for c in s.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                cur.push(c);
            }
            ',' if !in_quotes => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// Percent-encode a query parameter value.
///
/// Deliberately minimal and deliberately not a dependency: the only values
/// that reach it are a registry's own `service` and a `scope` this code built,
/// so the unreserved set plus the few characters a scope actually contains is
/// the whole requirement.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The scope a pull of `repository` needs.
pub fn pull_scope(repository: &str) -> String {
    format!("repository:{repository}:pull")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both registries this project actually talks to, verbatim off the wire.
    #[test]
    fn parses_the_challenges_real_registries_send() {
        let actpkg = Challenge::parse(
            r#"Bearer realm="https://actpkg.dev/api/v1/token",service="actpkg.dev",scope="repository:library/time:pull""#,
        )
        .expect("actpkg.dev challenge parses");
        assert_eq!(actpkg.realm, "https://actpkg.dev/api/v1/token");
        assert_eq!(actpkg.service.as_deref(), Some("actpkg.dev"));
        assert_eq!(
            actpkg.scope.as_deref(),
            Some("repository:library/time:pull")
        );

        let ghcr = Challenge::parse(
            r#"Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:actcore/act/shim-tools-sync:pull""#,
        )
        .expect("ghcr.io challenge parses");
        assert_eq!(ghcr.realm, "https://ghcr.io/token");
        assert_eq!(
            ghcr.scope.as_deref(),
            Some("repository:actcore/act/shim-tools-sync:pull")
        );
    }

    /// **The comma that is not a separator.** A push scope carries one inside
    /// its value; splitting on every comma drops the `push` and the token comes
    /// back valid for a pull the caller did not ask for.
    #[test]
    fn a_comma_inside_a_scope_is_not_a_parameter_boundary() {
        let c = Challenge::parse(
            r#"Bearer realm="https://r.example/token",service="r",scope="repository:a/b:pull,push""#,
        )
        .expect("parses");
        assert_eq!(c.scope.as_deref(), Some("repository:a/b:pull,push"));
    }

    #[test]
    fn parameter_order_does_not_matter() {
        let c = Challenge::parse(
            r#"Bearer scope="repository:x:pull",realm="https://r.example/token",service="r""#,
        )
        .expect("parses");
        assert_eq!(c.realm, "https://r.example/token");
        assert_eq!(c.scope.as_deref(), Some("repository:x:pull"));
    }

    /// A realm alone is enough: `service` and `scope` are optional in the
    /// grammar and some registries omit them.
    #[test]
    fn a_realm_alone_is_a_usable_challenge() {
        let c = Challenge::parse(r#"Bearer realm="https://r.example/token""#).expect("parses");
        assert_eq!(c.token_url(), "https://r.example/token");
        assert!(c.service.is_none() && c.scope.is_none());
    }

    /// Without a realm there is nowhere to go, so it is not a challenge this
    /// code can act on.
    #[test]
    fn a_bearer_challenge_without_a_realm_is_refused() {
        assert!(Challenge::parse(r#"Bearer service="r",scope="repository:x:pull""#).is_none());
    }

    /// `Basic` is not the token dance. Treating it as one would GET a token
    /// from a realm that was never offered.
    #[test]
    fn a_non_bearer_scheme_is_not_a_challenge() {
        assert!(Challenge::parse(r#"Basic realm="https://r.example/""#).is_none());
        assert!(Challenge::parse("").is_none());
    }

    #[test]
    fn the_token_url_carries_service_and_scope_encoded() {
        let c = Challenge::parse(
            r#"Bearer realm="https://actpkg.dev/api/v1/token",service="actpkg.dev",scope="repository:library/time:pull""#,
        )
        .expect("parses");
        // `:` and `/` must be encoded in a query value; a registry that decodes
        // leniently would accept them raw, and one that does not would 400.
        assert_eq!(
            c.token_url(),
            "https://actpkg.dev/api/v1/token?service=actpkg.dev&scope=repository%3Alibrary%2Ftime%3Apull"
        );
    }

    /// A realm that already has a query keeps it.
    #[test]
    fn a_realm_with_an_existing_query_gets_an_ampersand() {
        let c = Challenge::parse(r#"Bearer realm="https://r.example/token?a=1",service="r""#)
            .expect("parses");
        assert_eq!(c.token_url(), "https://r.example/token?a=1&service=r");
    }

    #[test]
    fn pull_scope_is_the_spelling_registries_expect() {
        assert_eq!(pull_scope("library/time"), "repository:library/time:pull");
    }
}
