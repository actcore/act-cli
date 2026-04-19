//! Network-policy primitives shared between HTTP and (upcoming) raw TCP/UDP
//! policy paths. Keep this module free of HTTP- or socket-specific config
//! types so it can be consumed from any direction — the `HttpConfig` matcher
//! and a future `SocketConfig` matcher both end up calling the same
//! `cidr_contains` / `host_matches` logic.

use std::net::IpAddr;

/// Does `cidr` (e.g. `"10.0.0.0/8"` or `"fc00::/7"`) contain `ip`? Parses via
/// the `cidr` crate; returns `false` for malformed specs rather than
/// panicking. Family mismatch (v4 rule vs v6 ip) is also `false`.
pub fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    cidr.parse::<cidr::IpCidr>()
        .map(|c| c.contains(&ip))
        .unwrap_or(false)
}

/// Host-pattern match. Supports exact match (case-insensitive) and
/// `*.suffix` wildcards. `*.example.com` matches both `example.com` and any
/// subdomain `foo.example.com` / `a.b.example.com`.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host.eq_ignore_ascii_case(suffix)
            || host
                .to_ascii_lowercase()
                .ends_with(&format!(".{}", suffix.to_ascii_lowercase()));
    }
    host.eq_ignore_ascii_case(pattern)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_basic_ipv4() {
        assert!(cidr_contains("10.0.0.0/8", "10.1.2.3".parse().unwrap()));
        assert!(!cidr_contains("10.0.0.0/8", "11.0.0.0".parse().unwrap()));
        assert!(cidr_contains("0.0.0.0/0", "8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn cidr_basic_ipv6() {
        assert!(cidr_contains("fc00::/7", "fc00::1".parse().unwrap()));
        assert!(!cidr_contains("fc00::/7", "2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn cidr_malformed_is_no_match() {
        assert!(!cidr_contains("not-a-cidr", "10.0.0.1".parse().unwrap()));
        assert!(!cidr_contains("10.0.0.0/99", "10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn cidr_family_mismatch_is_no_match() {
        assert!(!cidr_contains("10.0.0.0/8", "::1".parse().unwrap()));
        assert!(!cidr_contains("fc00::/7", "10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn host_exact_case_insensitive() {
        assert!(host_matches("api.example.com", "api.example.com"));
        assert!(host_matches("api.example.com", "API.EXAMPLE.COM"));
        assert!(!host_matches("api.example.com", "api2.example.com"));
    }

    #[test]
    fn host_wildcard_matches_apex_and_subdomains() {
        assert!(host_matches("*.example.com", "example.com"));
        assert!(host_matches("*.example.com", "api.example.com"));
        assert!(host_matches("*.example.com", "a.b.example.com"));
    }

    #[test]
    fn host_wildcard_rejects_unrelated_and_confusable_suffixes() {
        assert!(!host_matches("*.example.com", "api.other.com"));
        // Confusable: "evil.com" ending literally with ".example.com" shouldn't
        // match if it's "notexample.com", but "evil.example.com" should.
        assert!(!host_matches("*.example.com", "notexample.com"));
        assert!(!host_matches("*.example.com", "example.com.evil.com"));
    }
}
