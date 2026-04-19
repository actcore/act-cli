//! Network-policy primitives and rule checker. This module is strictly about
//! IPs, hostnames, CIDRs, and ports — it has no HTTP awareness. HTTP adds
//! scheme + method filtering as its own layer before delegating the
//! network-level parts here; upcoming raw TCP/UDP policy will reuse the same
//! rule shape and checker directly.
//!
//! Layers:
//! 1. **Primitives** (`cidr_contains`, `host_matches`) — pure functions.
//! 2. **Rule type** (`NetworkRule`) — deserialisable rule shape shared by
//!    every network-dimension policy.
//! 3. **Checker** (`NetworkCheck`, `rule_matches`, `decide`) — given a
//!    target and a rule set, decide allow/deny.
//! 4. **DNS helper** (`resolve_host`) — tokio-backed lookup that upper
//!    layers use before calling `decide` with `resolved_ips` populated.

use std::net::{IpAddr, SocketAddr};

use serde::Deserialize;

use crate::config::PolicyMode;

/// Network-dimension rule: host pattern or CIDR, plus optional port
/// narrowing. Shared by HTTP policy (via `HttpRule` flattening this in) and
/// future raw-socket policy.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct NetworkRule {
    /// Exact host (case-insensitive) or `*.suffix` wildcard.
    #[serde(default)]
    pub host: Option<String>,
    /// Destination ports this rule applies to. None means "any port".
    #[serde(default)]
    pub ports: Option<Vec<u16>>,
    /// CIDR spec (IPv4 or IPv6). Matches against URI IP literals and / or
    /// DNS-resolved IPs populated by the caller.
    #[serde(default)]
    pub cidr: Option<String>,
    /// Ports carved out of a CIDR match. Useful for deny rules like
    /// "deny 127.0.0.0/8 except port 3000".
    #[serde(default, rename = "except-ports")]
    pub except_ports: Option<Vec<u16>>,
}

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

// ── Rule checker ─────────────────────────────────────────────────────────

/// Outcome of checking a set of network rules against a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

/// A network operation the rule checker inspects. Fields a raw socket
/// path won't populate (scheme, method) are left `None`; fields an HTTP
/// path doesn't know yet (resolved_ips, when DNS hasn't run) are empty.
#[derive(Debug, Clone, Copy)]
pub struct NetworkCheck<'a> {
    /// The hostname or IP literal the guest asked for. Empty string is
    /// allowed if only IPs are known.
    pub host: &'a str,
    /// Destination port. Required for all checks.
    pub port: u16,
    /// Pre-resolved destination IPs, if DNS has already run. Empty slice
    /// means "not resolved yet" — CIDR rules then only match IP-literal
    /// hosts.
    pub resolved_ips: &'a [IpAddr],
}

impl<'a> NetworkCheck<'a> {
    /// Bare target — no pre-resolved IPs.
    pub fn new(host: &'a str, port: u16) -> Self {
        Self {
            host,
            port,
            resolved_ips: &[],
        }
    }

    /// Target with DNS-resolved peers already known.
    pub fn with_resolved(host: &'a str, port: u16, resolved_ips: &'a [IpAddr]) -> Self {
        Self {
            host,
            port,
            resolved_ips,
        }
    }
}

/// Does a single rule match the target?
///
/// Matching is conjunction: every populated rule field must match. A rule
/// with neither `host` nor `cidr` is treated as unmatched (it has nothing
/// to anchor on).
pub fn rule_matches(rule: &NetworkRule, check: &NetworkCheck) -> bool {
    // Either a CIDR or a host anchor — at least one must be present and match.
    if let Some(cidr_spec) = rule.cidr.as_deref() {
        let ip_literal_match = check
            .host
            .parse::<IpAddr>()
            .ok()
            .map(|ip| cidr_contains(cidr_spec, ip))
            .unwrap_or(false);
        let resolved_match = check
            .resolved_ips
            .iter()
            .any(|ip| cidr_contains(cidr_spec, *ip));
        if !ip_literal_match && !resolved_match {
            return false;
        }
        if let Some(except) = &rule.except_ports
            && except.contains(&check.port)
        {
            return false;
        }
    } else if let Some(want_host) = rule.host.as_deref() {
        if !host_matches(want_host, check.host) {
            return false;
        }
    } else {
        return false;
    }

    if let Some(want_ports) = rule.ports.as_deref()
        && !want_ports.contains(&check.port)
    {
        return false;
    }

    true
}

/// Apply mode + allow/deny rule lists to a target.
///
/// - `Deny` / `Open` modes short-circuit.
/// - `Allowlist`: any deny match → `Deny`; else any allow match → `Allow`;
///   else `Deny`.
///
/// HTTP policy doesn't call this directly (it interleaves scheme/method
/// filters with network matching). Raw TCP/UDP policy will.
#[allow(dead_code)] // used by upcoming raw TCP/UDP policy path
pub fn decide(
    mode: PolicyMode,
    allow: &[NetworkRule],
    deny: &[NetworkRule],
    check: &NetworkCheck,
) -> Decision {
    match mode {
        PolicyMode::Deny => Decision::Deny,
        PolicyMode::Open => Decision::Allow,
        PolicyMode::Allowlist => {
            if deny.iter().any(|r| rule_matches(r, check)) {
                return Decision::Deny;
            }
            if allow.iter().any(|r| rule_matches(r, check)) {
                Decision::Allow
            } else {
                Decision::Deny
            }
        }
    }
}

// ── DNS helper ─────────────────────────────────────────────────────────────

/// Resolve `host:port` to zero or more socket addresses using tokio's async
/// resolver. Returns an empty Vec on lookup failure (callers decide whether
/// to treat that as "defer to downstream" or "deny"). `host` may be an IP
/// literal, in which case the returned Vec contains exactly that IP.
pub async fn resolve_host(host: &str, port: u16) -> Vec<SocketAddr> {
    let target = format!("{host}:{port}");
    match tokio::net::lookup_host(&target).await {
        Ok(addrs) => addrs.collect(),
        Err(_) => Vec::new(),
    }
}

// ── CIDR deny helpers ──────────────────────────────────────────────────────

/// Returns `true` if any rule in `deny_rules` has a CIDR that matches `ip`
/// (respecting `except_ports`). Used both at HTTP-layer after DNS resolution
/// and by future raw-socket connect checks.
pub fn any_deny_cidr_matches(deny_rules: &[NetworkRule], ip: IpAddr, port: u16) -> bool {
    let ips = [ip];
    let check = NetworkCheck::with_resolved("", port, &ips);
    deny_rules
        .iter()
        .any(|rule| rule.cidr.is_some() && rule_matches(rule, &check))
}

/// Resolve `host:port` via DNS and return the first resolved IP that is
/// denied by any of the `deny_rules`, or `None` if no match / lookup fails
/// / no rule uses CIDR.
pub async fn first_cidr_deny_hit(
    deny_rules: &[NetworkRule],
    host: &str,
    port: u16,
) -> Option<SocketAddr> {
    if deny_rules.iter().all(|r| r.cidr.is_none()) {
        return None;
    }
    for addr in resolve_host(host, port).await {
        if any_deny_cidr_matches(deny_rules, addr.ip(), addr.port()) {
            return Some(addr);
        }
    }
    None
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

    // ── Rule checker ──

    fn rule(
        host: Option<&str>,
        ports: Option<Vec<u16>>,
        cidr: Option<&str>,
        except_ports: Option<Vec<u16>>,
    ) -> NetworkRule {
        NetworkRule {
            host: host.map(String::from),
            ports,
            cidr: cidr.map(String::from),
            except_ports,
        }
    }

    #[test]
    fn rule_requires_host_or_cidr() {
        let r = rule(None, None, None, None);
        assert!(!rule_matches(&r, &NetworkCheck::new("example.com", 443)));
    }

    #[test]
    fn host_rule_with_port_narrowing() {
        let r = rule(Some("*.example.com"), Some(vec![443]), None, None);
        assert!(rule_matches(&r, &NetworkCheck::new("api.example.com", 443)));
        assert!(!rule_matches(
            &r,
            &NetworkCheck::new("api.example.com", 8443)
        ));
        assert!(!rule_matches(&r, &NetworkCheck::new("api.other.com", 443)));
    }

    #[test]
    fn cidr_rule_matches_ip_literal_host() {
        let r = rule(None, None, Some("10.0.0.0/8"), None);
        assert!(rule_matches(&r, &NetworkCheck::new("10.1.2.3", 80)));
        assert!(!rule_matches(&r, &NetworkCheck::new("11.1.2.3", 80)));
    }

    #[test]
    fn cidr_rule_matches_resolved_ip_when_host_is_name() {
        let r = rule(None, None, Some("10.0.0.0/8"), None);
        let ips = ["10.1.2.3".parse().unwrap()];
        let check = NetworkCheck::with_resolved("internal.example.com", 443, &ips);
        assert!(rule_matches(&r, &check));
    }

    #[test]
    fn cidr_except_ports_carves_exceptions() {
        let r = rule(None, None, Some("127.0.0.0/8"), Some(vec![3000]));
        assert!(rule_matches(&r, &NetworkCheck::new("127.0.0.1", 80)));
        assert!(!rule_matches(&r, &NetworkCheck::new("127.0.0.1", 3000)));
    }

    #[test]
    fn decide_allowlist_deny_beats_allow() {
        let allow = vec![rule(Some("*.example.com"), None, None, None)];
        let deny = vec![rule(Some("admin.example.com"), None, None, None)];
        let good = NetworkCheck::new("api.example.com", 443);
        let bad = NetworkCheck::new("admin.example.com", 443);
        assert_eq!(
            decide(PolicyMode::Allowlist, &allow, &deny, &good),
            Decision::Allow
        );
        assert_eq!(
            decide(PolicyMode::Allowlist, &allow, &deny, &bad),
            Decision::Deny
        );
    }

    #[test]
    fn decide_modes_short_circuit() {
        let allow = vec![rule(Some("example.com"), None, None, None)];
        let deny = vec![];
        let check = NetworkCheck::new("example.com", 443);
        assert_eq!(
            decide(PolicyMode::Open, &allow, &deny, &check),
            Decision::Allow
        );
        assert_eq!(
            decide(PolicyMode::Deny, &allow, &deny, &check),
            Decision::Deny
        );
    }

    #[test]
    fn any_deny_cidr_matches_ip() {
        let deny = vec![rule(None, None, Some("10.0.0.0/8"), None)];
        assert!(any_deny_cidr_matches(
            &deny,
            "10.1.2.3".parse().unwrap(),
            443
        ));
        assert!(!any_deny_cidr_matches(
            &deny,
            "8.8.8.8".parse().unwrap(),
            443
        ));
    }

    #[test]
    fn any_deny_cidr_respects_except_ports() {
        let deny = vec![rule(None, None, Some("127.0.0.0/8"), Some(vec![3000]))];
        assert!(any_deny_cidr_matches(
            &deny,
            "127.0.0.1".parse().unwrap(),
            80
        ));
        assert!(!any_deny_cidr_matches(
            &deny,
            "127.0.0.1".parse().unwrap(),
            3000
        ));
    }

    #[test]
    fn any_deny_cidr_ignores_host_only_rules() {
        // A rule with only a host (no cidr) must not count as a CIDR
        // deny-match when we're only given an IP.
        let deny = vec![rule(Some("example.com"), None, None, None)];
        assert!(!any_deny_cidr_matches(
            &deny,
            "10.1.2.3".parse().unwrap(),
            443
        ));
    }
}
