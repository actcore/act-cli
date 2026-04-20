//! Compute the effective host policy for one component invocation.
//!
//! The component's `act:component` manifest declares (via
//! `[std.capabilities.*]`) which filesystem paths and HTTP requests it
//! needs. The host's resolved `FsConfig` / `HttpConfig` describes what
//! the *user* has granted. Effective policy = declaration ∩ user grant,
//! with undeclared capability classes (and declared-but-empty allow
//! arrays) hard-denied regardless of user grant ("ceiling" model).

use act_types::{Capabilities, HttpAllow};

use crate::config::{FsConfig, HttpConfig, HttpRule, PolicyMode};
use crate::runtime::network::NetworkRule;

/// Wraps a resolved config with a flag indicating whether the component
/// declared the relevant capability class at all. Undeclared classes get
/// `mode = Deny`; callers may still read other fields (they'll be
/// ignored by the matchers in Deny mode).
#[derive(Debug, Clone)]
#[allow(dead_code)] // wired in Task 4; module exists for tests now
pub struct EffectivePolicy<T> {
    pub config: T,
    pub declared: bool,
}

#[allow(dead_code)] // wired in Task 4; module exists for tests now
pub fn effective_fs(user: &FsConfig, caps: &Capabilities) -> EffectivePolicy<FsConfig> {
    let Some(fs_cap) = caps.filesystem.as_ref() else {
        // Undeclared → hard deny
        return EffectivePolicy {
            config: FsConfig {
                mode: PolicyMode::Deny,
                ..user.clone()
            },
            declared: false,
        };
    };

    // Empty allow = no filesystem access. Components wanting broad access
    // declare allow = [{ path = "**", mode = "rw" }] explicitly.
    let declared_paths: Vec<String> = fs_cap.allow.iter().map(|p| p.path.clone()).collect();
    if declared_paths.is_empty() {
        return EffectivePolicy {
            config: FsConfig {
                mode: PolicyMode::Deny,
                ..user.clone()
            },
            declared: true,
        };
    }

    // Intersection: user's allow ∩ declaration ceiling.
    //
    // Declaration only narrows. If user denies, user wins (deny always
    // wins — their deny list passes through unchanged). If user allows
    // path P but P is not covered by any declared path, P is dropped
    // from the effective allow.
    let mut effective = user.clone();
    match effective.mode {
        PolicyMode::Deny => {} // user has denied everything; leave it
        PolicyMode::Allowlist => {
            effective.allow.retain(|allow_pat| {
                declared_paths
                    .iter()
                    .any(|decl| globs_overlap(decl, allow_pat))
            });
        }
        PolicyMode::Open => {
            // Open + declaration → treat as allowlist over declared paths.
            effective.mode = PolicyMode::Allowlist;
            effective.allow = declared_paths;
        }
    }

    EffectivePolicy {
        config: effective,
        declared: true,
    }
}

#[allow(dead_code)] // wired in Task 4; module exists for tests now
pub fn effective_http(user: &HttpConfig, caps: &Capabilities) -> EffectivePolicy<HttpConfig> {
    let Some(http_cap) = caps.http.as_ref() else {
        return EffectivePolicy {
            config: HttpConfig {
                mode: PolicyMode::Deny,
                ..user.clone()
            },
            declared: false,
        };
    };

    // Empty allow = no HTTP access. Components wanting broad access
    // declare allow = [{ host = "*" }] explicitly.
    let declared_rules: Vec<HttpRule> = http_cap.allow.iter().map(rule_from_declaration).collect();
    if declared_rules.is_empty() {
        return EffectivePolicy {
            config: HttpConfig {
                mode: PolicyMode::Deny,
                ..user.clone()
            },
            declared: true,
        };
    }

    let mut effective = user.clone();
    match effective.mode {
        PolicyMode::Deny => {} // user has denied everything; leave it
        PolicyMode::Allowlist => {
            effective.allow.retain(|user_rule| {
                declared_rules
                    .iter()
                    .any(|decl| rule_covers(decl, user_rule))
            });
        }
        PolicyMode::Open => {
            effective.mode = PolicyMode::Allowlist;
            effective.allow = declared_rules;
        }
    }

    EffectivePolicy {
        config: effective,
        declared: true,
    }
}

#[allow(dead_code)] // wired in Task 4
fn rule_from_declaration(d: &HttpAllow) -> HttpRule {
    HttpRule {
        net: NetworkRule {
            host: Some(d.host.clone()),
            ports: d.ports.clone(),
            cidr: None,
            except_ports: None,
        },
        scheme: d.scheme.clone(),
        methods: d.methods.clone(),
    }
}

/// Does a user's `allow` glob pattern intersect with a declared glob pattern?
///
/// Both are glob strings; "intersection" here is structural (either is a
/// prefix of the other, or they're both subtree wildcards of a common root).
/// Exact semantic intersection needs a glob-intersection library; this
/// approximation is conservative — it accepts overlap when either side
/// could plausibly cover the other. We rely on the downstream `FsMatcher`
/// glob compile step to be the authority on actual matches; this predicate
/// is only used to decide which user-allow patterns survive the declaration
/// filter.
#[allow(dead_code)] // wired in Task 4
fn globs_overlap(a: &str, b: &str) -> bool {
    // Normalise: strip trailing /** and /* so prefixes compare cleanly.
    // Also treat bare "**" as "everything".
    fn root(s: &str) -> &str {
        if s == "**" {
            return "";
        }
        s.trim_end_matches("/**").trim_end_matches("/*")
    }
    let (ra, rb) = (root(a), root(b));
    // Empty root means "match everything".
    ra.is_empty() || rb.is_empty() || ra == rb || ra.starts_with(rb) || rb.starts_with(ra)
}

/// Does declared rule D "cover" user rule U? D covers U when every
/// request matching U would also match D. Conservative: checks host
/// equality or wildcard-superset, scheme equality or declared-wildcard,
/// method-superset, port-superset. Declarations never carry cidr, so
/// a user rule with cidr-only (no host) is never covered.
#[allow(dead_code)] // wired in Task 4
fn rule_covers(decl: &HttpRule, user: &HttpRule) -> bool {
    // Host: declared host must cover user host. Declarations always
    // have a host (required by HttpAllow); user rules may omit host
    // if they're CIDR-only, in which case the declaration can't
    // cover them.
    let decl_host = decl.net.host.as_deref().expect("declaration host required");
    match user.net.host.as_deref() {
        Some(u) => {
            if !host_covers(decl_host, u) {
                return false;
            }
        }
        None => return false, // user rule is CIDR-only; no declaration match possible
    }
    // Scheme: declared must match user (or be unset = any).
    if let (Some(d), Some(u)) = (&decl.scheme, &user.scheme)
        && !d.eq_ignore_ascii_case(u)
    {
        return false;
    }
    // Methods: every user method must be in declared list.
    if let (Some(d), Some(u)) = (&decl.methods, &user.methods)
        && !u
            .iter()
            .all(|um| d.iter().any(|dm| dm.eq_ignore_ascii_case(um)))
    {
        return false;
    }
    // Ports: every user port must be in declared list.
    if let (Some(d), Some(u)) = (&decl.net.ports, &user.net.ports)
        && !u.iter().all(|up| d.contains(up))
    {
        return false;
    }
    true
}

#[allow(dead_code)] // wired in Task 4
fn host_covers(decl: &str, user: &str) -> bool {
    if decl == "*" {
        return true;
    }
    if decl.eq_ignore_ascii_case(user) {
        return true;
    }
    if let Some(suffix) = decl.strip_prefix("*.") {
        return user
            .to_ascii_lowercase()
            .ends_with(&format!(".{}", suffix.to_ascii_lowercase()))
            || user.eq_ignore_ascii_case(suffix);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use act_types::{FilesystemAllow, FilesystemCap, FsMode, HttpCap};

    fn caps_fs(paths: Vec<(&str, FsMode)>) -> Capabilities {
        Capabilities {
            filesystem: Some(FilesystemCap {
                allow: paths
                    .into_iter()
                    .map(|(p, m)| FilesystemAllow {
                        path: p.to_string(),
                        mode: m,
                    })
                    .collect(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn caps_http(allow: Vec<HttpAllow>) -> Capabilities {
        Capabilities {
            http: Some(HttpCap { allow }),
            ..Default::default()
        }
    }

    #[test]
    fn fs_undeclared_forces_deny() {
        let user = FsConfig {
            mode: PolicyMode::Allowlist,
            allow: vec!["/tmp/**".into()],
            ..Default::default()
        };
        let eff = effective_fs(&user, &Capabilities::default());
        assert!(!eff.declared);
        assert_eq!(eff.config.mode, PolicyMode::Deny);
    }

    #[test]
    fn fs_empty_allow_forces_deny() {
        // Declared but with empty allow → hard deny.
        let caps = Capabilities {
            filesystem: Some(FilesystemCap::default()),
            ..Default::default()
        };
        let user = FsConfig {
            mode: PolicyMode::Allowlist,
            allow: vec!["/tmp/**".into()],
            ..Default::default()
        };
        let eff = effective_fs(&user, &caps);
        assert!(eff.declared);
        assert_eq!(eff.config.mode, PolicyMode::Deny);
    }

    #[test]
    fn fs_declared_narrows_user_allow() {
        // Component declares /tmp/** ro. User allows /tmp/** + /home/**.
        // Effective allow: only /tmp/** (/home isn't declared).
        let caps = caps_fs(vec![("/tmp/**", FsMode::Ro)]);
        let user = FsConfig {
            mode: PolicyMode::Allowlist,
            allow: vec!["/tmp/**".into(), "/home/**".into()],
            ..Default::default()
        };
        let eff = effective_fs(&user, &caps);
        assert!(eff.declared);
        assert_eq!(eff.config.allow, vec!["/tmp/**".to_string()]);
    }

    #[test]
    fn fs_open_becomes_allowlist_over_declared_paths() {
        let caps = caps_fs(vec![("/tmp/**", FsMode::Rw)]);
        let user = FsConfig {
            mode: PolicyMode::Open,
            ..Default::default()
        };
        let eff = effective_fs(&user, &caps);
        assert_eq!(eff.config.mode, PolicyMode::Allowlist);
        assert_eq!(eff.config.allow, vec!["/tmp/**".to_string()]);
    }

    #[test]
    fn fs_wildcard_declaration_permits_broad_user_grant() {
        // Component declares ** rw — the "broad" shape.
        let caps = caps_fs(vec![("**", FsMode::Rw)]);
        let user = FsConfig {
            mode: PolicyMode::Allowlist,
            allow: vec!["/tmp/**".into(), "/home/alice/**".into()],
            ..Default::default()
        };
        let eff = effective_fs(&user, &caps);
        assert_eq!(eff.config.allow.len(), 2, "both user paths survive");
    }

    #[test]
    fn http_undeclared_forces_deny() {
        let user = HttpConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![HttpRule {
                net: NetworkRule {
                    host: Some("example.com".into()),
                    ..Default::default()
                },
                ..Default::default()
            }],
            ..Default::default()
        };
        let eff = effective_http(&user, &Capabilities::default());
        assert!(!eff.declared);
        assert_eq!(eff.config.mode, PolicyMode::Deny);
    }

    #[test]
    fn http_empty_allow_forces_deny() {
        let caps = Capabilities {
            http: Some(HttpCap::default()),
            ..Default::default()
        };
        let user = HttpConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![HttpRule {
                net: NetworkRule {
                    host: Some("example.com".into()),
                    ..Default::default()
                },
                ..Default::default()
            }],
            ..Default::default()
        };
        let eff = effective_http(&user, &caps);
        assert!(eff.declared);
        assert_eq!(eff.config.mode, PolicyMode::Deny);
    }

    #[test]
    fn http_declared_narrows_user_allow() {
        // Component declares api.openai.com only. User allows openai.com
        // AND example.com. Effective: only api.openai.com.
        let caps = caps_http(vec![HttpAllow {
            host: "api.openai.com".into(),
            scheme: Some("https".into()),
            methods: None,
            ports: None,
        }]);
        let user = HttpConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![
                HttpRule {
                    net: NetworkRule {
                        host: Some("api.openai.com".into()),
                        ..Default::default()
                    },
                    scheme: Some("https".into()),
                    ..Default::default()
                },
                HttpRule {
                    net: NetworkRule {
                        host: Some("example.com".into()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let eff = effective_http(&user, &caps);
        assert_eq!(eff.config.allow.len(), 1);
        assert_eq!(
            eff.config.allow[0].net.host.as_deref(),
            Some("api.openai.com")
        );
    }

    #[test]
    fn http_suffix_wildcard_declaration_covers_subdomains() {
        let caps = caps_http(vec![HttpAllow {
            host: "*.github.com".into(),
            scheme: None,
            methods: None,
            ports: None,
        }]);
        let user = HttpConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![HttpRule {
                net: NetworkRule {
                    host: Some("api.github.com".into()),
                    ..Default::default()
                },
                ..Default::default()
            }],
            ..Default::default()
        };
        let eff = effective_http(&user, &caps);
        assert_eq!(eff.config.allow.len(), 1);
    }

    #[test]
    fn http_star_wildcard_declaration_covers_anything() {
        let caps = caps_http(vec![HttpAllow {
            host: "*".into(),
            scheme: None,
            methods: None,
            ports: None,
        }]);
        let user = HttpConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![
                HttpRule {
                    net: NetworkRule {
                        host: Some("anything.example".into()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                HttpRule {
                    net: NetworkRule {
                        host: Some("another.host.org".into()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let eff = effective_http(&user, &caps);
        assert_eq!(eff.config.allow.len(), 2, "both survive under *");
    }

    #[test]
    fn http_user_cidr_only_rule_is_dropped_by_declaration() {
        // Declarations always have a host. A user rule that's CIDR-only
        // (no host) can never match a declaration's host and must be
        // dropped from the effective allow.
        let caps = caps_http(vec![HttpAllow {
            host: "*".into(),
            scheme: None,
            methods: None,
            ports: None,
        }]);
        let user = HttpConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![HttpRule {
                net: NetworkRule {
                    cidr: Some("10.0.0.0/8".into()),
                    ..Default::default()
                },
                ..Default::default()
            }],
            ..Default::default()
        };
        let eff = effective_http(&user, &caps);
        assert_eq!(eff.config.allow.len(), 0);
    }
}
