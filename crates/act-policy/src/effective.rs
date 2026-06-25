//! Compute the effective host policy for one component invocation.
//!
//! The component's `act:component` manifest declares (via
//! `[std.capabilities.*]`) which filesystem paths and HTTP requests it
//! needs. The host's resolved `FsConfig` / `HttpConfig` describes what
//! the *user* has granted. Effective policy = declaration ∩ user grant,
//! with undeclared capability classes (and declared-but-empty allow
//! arrays) hard-denied regardless of user grant ("ceiling" model).

use act_types::constants::{CAP_FILESYSTEM, CAP_HTTP, CAP_SOCKETS};
use act_types::{Capabilities, FilesystemAllow, HttpAllow, SocketsAllow};

use crate::grant::{
    FsAllow, FsConfig, HttpConfig, HttpRule, PolicyMode, SocketsConfig, SocketsRule,
};
use crate::net::NetworkRule;

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
    let Some(req) = caps.get(CAP_FILESYSTEM) else {
        return EffectivePolicy {
            config: FsConfig {
                mode: PolicyMode::Deny,
                ..user.clone()
            },
            declared: false,
        };
    };
    let declared = req.constraints_as::<FilesystemAllow>().unwrap_or_else(|e| {
        tracing::warn!(cap = CAP_FILESYSTEM, error = %e, "ignoring malformed fs constraint");
        Vec::new()
    });
    let declared: Vec<FsAllow> = declared
        .iter()
        .map(|p| FsAllow {
            glob: p.path.clone(),
            mode: p.mode,
        })
        .collect();
    if declared.is_empty() {
        return EffectivePolicy {
            config: FsConfig {
                mode: PolicyMode::Deny,
                ..user.clone()
            },
            declared: true,
        };
    }
    // ↓↓↓ from here, the existing intersection `match effective.mode { … }` block is UPDATED ↓↓↓
    let mut effective = user.clone();
    match effective.mode {
        PolicyMode::Deny => {}
        // Ask is a per-op gate, but it MUST stay bounded by the declared
        // ceiling: set the effective allow list to the declaration (the upper
        // bound) while keeping `mode = Ask` so the matcher still prompts for
        // in-ceiling targets and hard-denies out-of-ceiling ones (no prompt).
        PolicyMode::Ask => {
            effective.allow = declared;
        }
        PolicyMode::Allowlist => {
            effective.allow.retain(|allow_entry| {
                declared
                    .iter()
                    .any(|decl| globs_overlap(&decl.glob, &allow_entry.glob))
            });
            // Intersect mode: take the minimum (most restrictive) of declared vs user.
            for entry in &mut effective.allow {
                if let Some(decl) = declared
                    .iter()
                    .find(|d| globs_overlap(&d.glob, &entry.glob))
                {
                    entry.mode = min_mode(decl.mode, entry.mode);
                }
            }
        }
        PolicyMode::Open => {
            effective.mode = PolicyMode::Allowlist;
            effective.allow = declared;
        }
    }
    EffectivePolicy {
        config: effective,
        declared: true,
    }
}

#[allow(dead_code)] // wired in Task 4; module exists for tests now
pub fn effective_http(user: &HttpConfig, caps: &Capabilities) -> EffectivePolicy<HttpConfig> {
    let Some(req) = caps.get(CAP_HTTP) else {
        return EffectivePolicy {
            config: HttpConfig {
                mode: PolicyMode::Deny,
                ..user.clone()
            },
            declared: false,
        };
    };
    let declared_rules: Vec<HttpRule> = req
        .constraints_as::<HttpAllow>()
        .unwrap_or_else(|e| {
            tracing::warn!(cap = CAP_HTTP, error = %e, "ignoring malformed http constraint");
            Vec::new()
        })
        .iter()
        .map(rule_from_declaration)
        .collect();
    if declared_rules.is_empty() {
        return EffectivePolicy {
            config: HttpConfig {
                mode: PolicyMode::Deny,
                ..user.clone()
            },
            declared: true,
        };
    }
    // ↓↓↓ existing http intersection `match` block UNCHANGED ↓↓↓
    let mut effective = user.clone();
    match effective.mode {
        PolicyMode::Deny => {}
        // Ask stays bounded by the declared ceiling (see `effective_fs`):
        // set the effective allow list to the declaration but keep `mode = Ask`
        // so the matcher prompts in-ceiling and hard-denies out-of-ceiling.
        PolicyMode::Ask => {
            effective.allow = declared_rules;
        }
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

#[allow(dead_code)] // wired in Task 5
pub fn effective_sockets(
    user: &SocketsConfig,
    caps: &Capabilities,
) -> EffectivePolicy<SocketsConfig> {
    let Some(req) = caps.get(CAP_SOCKETS) else {
        return EffectivePolicy {
            config: SocketsConfig {
                mode: PolicyMode::Deny,
                ..user.clone()
            },
            declared: false,
        };
    };
    let declared_rules: Vec<SocketsRule> = req
        .constraints_as::<SocketsAllow>()
        .unwrap_or_else(|e| {
            tracing::warn!(cap = CAP_SOCKETS, error = %e, "ignoring malformed sockets constraint");
            Vec::new()
        })
        .iter()
        .map(sockets_rule_from_declaration)
        .collect();
    if declared_rules.is_empty() {
        return EffectivePolicy {
            config: SocketsConfig {
                mode: PolicyMode::Deny,
                ..user.clone()
            },
            declared: true,
        };
    }
    // ↓↓↓ existing sockets intersection `match` block UNCHANGED ↓↓↓
    let mut effective = user.clone();
    match effective.mode {
        PolicyMode::Deny => {}
        // Ask stays bounded by the declared ceiling (see `effective_fs`):
        // set the effective allow list to the declaration but keep `mode = Ask`
        // so the matcher prompts in-ceiling and hard-denies out-of-ceiling.
        PolicyMode::Ask => {
            effective.allow = declared_rules;
        }
        PolicyMode::Allowlist => {
            effective.allow.retain(|user_rule| {
                declared_rules
                    .iter()
                    .any(|decl| sockets_rule_covers(decl, user_rule))
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

#[allow(dead_code)] // wired in Task 5
fn sockets_rule_from_declaration(d: &act_types::SocketsAllow) -> SocketsRule {
    SocketsRule {
        net: NetworkRule {
            host: d.host.clone(),
            cidr: d.cidr.clone(),
            ports: d.ports.clone(),
            except_ports: None,
        },
        protocols: Some(d.protocols.clone()),
    }
}

/// Declared rule D covers user rule U when every connection matching U
/// would also match D. Host/CIDR/port/protocol — each user dimension must
/// fit inside declared.
#[allow(dead_code)] // wired in Task 5
fn sockets_rule_covers(decl: &SocketsRule, user: &SocketsRule) -> bool {
    let host_or_cidr_covered = match (&decl.net.host, &decl.net.cidr) {
        (Some(decl_host), _) => match (&user.net.host, &user.net.cidr) {
            (Some(u_host), _) => host_covers(decl_host, u_host),
            (None, Some(_)) => false,
            (None, None) => false,
        },
        (None, Some(decl_cidr)) => match (&user.net.host, &user.net.cidr) {
            (Some(_), None) => false,
            (None, Some(u_cidr)) => decl_cidr == u_cidr,
            (None, None) => false,
            (Some(_), Some(_)) => false,
        },
        (None, None) => false,
    };
    if !host_or_cidr_covered {
        return false;
    }

    if let (Some(d_ports), Some(u_ports)) = (&decl.net.ports, &user.net.ports)
        && !u_ports.iter().all(|p| d_ports.contains(p))
    {
        return false;
    }

    if let Some(d_protos) = &decl.protocols
        && let Some(u_protos) = &user.protocols
        && !u_protos.iter().all(|p| d_protos.contains(p))
    {
        return false;
    }

    true
}

/// Return the more restrictive of two `FsMode` values.
/// `Ro` beats `Rw` (read-only is more restrictive than read-write).
fn min_mode(a: act_types::FsMode, b: act_types::FsMode) -> act_types::FsMode {
    use act_types::FsMode::*;
    if a == Ro || b == Ro { Ro } else { Rw }
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
    use crate::grant::FsAllow;
    use act_types::{CapabilityRequest, FilesystemAllow, FsMode, HttpAllow};
    use std::collections::BTreeMap;

    fn caps_fs(paths: Vec<(&str, FsMode)>) -> Capabilities {
        let constraints = paths
            .into_iter()
            .map(|(p, m)| {
                serde_json::to_value(FilesystemAllow {
                    path: p.to_string(),
                    mode: m,
                })
                .unwrap()
            })
            .collect();
        Capabilities(BTreeMap::from([(
            "wasi:filesystem".to_string(),
            CapabilityRequest {
                constraints,
                ..Default::default()
            },
        )]))
    }

    fn caps_http(allow: Vec<HttpAllow>) -> Capabilities {
        let constraints = allow
            .into_iter()
            .map(|a| serde_json::to_value(a).unwrap())
            .collect();
        Capabilities(BTreeMap::from([(
            "wasi:http".to_string(),
            CapabilityRequest {
                constraints,
                ..Default::default()
            },
        )]))
    }

    #[test]
    fn fs_undeclared_forces_deny() {
        let user = FsConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![FsAllow {
                glob: "/tmp/**".into(),
                mode: FsMode::Rw,
            }],
            ..Default::default()
        };
        let eff = effective_fs(&user, &Capabilities::default());
        assert!(!eff.declared);
        assert_eq!(eff.config.mode, PolicyMode::Deny);
    }

    #[test]
    fn fs_empty_allow_forces_deny() {
        // Declared but with empty allow → hard deny.
        let caps = Capabilities(BTreeMap::from([(
            "wasi:filesystem".to_string(),
            CapabilityRequest::default(),
        )]));
        let user = FsConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![FsAllow {
                glob: "/tmp/**".into(),
                mode: FsMode::Rw,
            }],
            ..Default::default()
        };
        let eff = effective_fs(&user, &caps);
        assert!(eff.declared);
        assert_eq!(eff.config.mode, PolicyMode::Deny);
    }

    #[test]
    fn fs_declared_narrows_user_allow() {
        // Component declares /tmp/** ro. User allows /tmp/** rw + /home/** rw.
        // Effective allow: only /tmp/** (intersected to ro — component declared ro).
        let caps = caps_fs(vec![("/tmp/**", FsMode::Ro)]);
        let user = FsConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![
                FsAllow {
                    glob: "/tmp/**".into(),
                    mode: FsMode::Rw,
                },
                FsAllow {
                    glob: "/home/**".into(),
                    mode: FsMode::Rw,
                },
            ],
            ..Default::default()
        };
        let eff = effective_fs(&user, &caps);
        assert!(eff.declared);
        assert_eq!(
            eff.config.allow,
            vec![FsAllow {
                glob: "/tmp/**".into(),
                mode: FsMode::Ro
            }]
        );
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
        assert_eq!(
            eff.config.allow,
            vec![FsAllow {
                glob: "/tmp/**".into(),
                mode: FsMode::Rw
            }]
        );
    }

    #[test]
    fn fs_ask_is_bounded_by_declared_ceiling() {
        // User mode = Ask, component declares /data/**. Effective policy must
        // keep mode = Ask (so per-op prompts still fire) but set the allow
        // list to the declared ceiling so out-of-ceiling paths are denied
        // without prompting.
        let caps = caps_fs(vec![("/data/**", FsMode::Rw)]);
        let user = FsConfig {
            mode: PolicyMode::Ask,
            ..Default::default()
        };
        let eff = effective_fs(&user, &caps);
        assert_eq!(eff.config.mode, PolicyMode::Ask);
        assert_eq!(
            eff.config.allow,
            vec![FsAllow {
                glob: "/data/**".into(),
                mode: FsMode::Rw
            }]
        );
    }

    #[test]
    fn http_ask_is_bounded_by_declared_ceiling() {
        let caps = caps_http(vec![HttpAllow {
            host: "api.openai.com".into(),
            scheme: Some("https".into()),
            methods: None,
            ports: None,
        }]);
        let user = HttpConfig {
            mode: PolicyMode::Ask,
            ..Default::default()
        };
        let eff = effective_http(&user, &caps);
        assert_eq!(eff.config.mode, PolicyMode::Ask);
        assert_eq!(eff.config.allow.len(), 1);
        assert_eq!(
            eff.config.allow[0].net.host.as_deref(),
            Some("api.openai.com")
        );
    }

    #[test]
    fn fs_wildcard_declaration_permits_broad_user_grant() {
        // Component declares ** rw — the "broad" shape.
        let caps = caps_fs(vec![("**", FsMode::Rw)]);
        let user = FsConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![
                FsAllow {
                    glob: "/tmp/**".into(),
                    mode: FsMode::Rw,
                },
                FsAllow {
                    glob: "/home/alice/**".into(),
                    mode: FsMode::Rw,
                },
            ],
            ..Default::default()
        };
        let eff = effective_fs(&user, &caps);
        assert_eq!(eff.config.allow.len(), 2, "both user paths survive");
    }

    #[test]
    fn effective_fs_intersects_mode_to_minimum() {
        use act_types::FsMode;
        // declared rw, user grants ro → effective ro
        let caps = caps_fs(vec![("/data/**", FsMode::Rw)]);
        let user = FsConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![FsAllow {
                glob: "/data/**".into(),
                mode: FsMode::Ro,
            }],
            deny: vec![],
        };
        let eff = effective_fs(&user, &caps).config;
        assert_eq!(
            eff.allow,
            vec![FsAllow {
                glob: "/data/**".into(),
                mode: FsMode::Ro
            }]
        );

        // declared ro, user grants rw → effective ro
        let caps = caps_fs(vec![("/data/**", FsMode::Ro)]);
        let user = FsConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![FsAllow {
                glob: "/data/**".into(),
                mode: FsMode::Rw,
            }],
            deny: vec![],
        };
        let eff = effective_fs(&user, &caps).config;
        assert_eq!(eff.allow[0].mode, FsMode::Ro);
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
        let caps = Capabilities(BTreeMap::from([(
            "wasi:http".to_string(),
            CapabilityRequest::default(),
        )]));
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

    fn caps_sockets(allow: Vec<act_types::SocketsAllow>) -> Capabilities {
        let constraints = allow
            .into_iter()
            .map(|a| serde_json::to_value(a).unwrap())
            .collect();
        Capabilities(BTreeMap::from([(
            "wasi:sockets".to_string(),
            CapabilityRequest {
                constraints,
                ..Default::default()
            },
        )]))
    }

    fn user_sockets_allow_host(host: &str, ports: Vec<u16>) -> SocketsRule {
        SocketsRule {
            net: NetworkRule {
                host: Some(host.to_string()),
                ports: Some(ports),
                ..Default::default()
            },
            protocols: None,
        }
    }

    #[test]
    fn sockets_undeclared_forces_deny() {
        let user = SocketsConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![user_sockets_allow_host("vnc.example.com", vec![5900])],
            ..Default::default()
        };
        let eff = effective_sockets(&user, &Capabilities::default());
        assert!(!eff.declared);
        assert_eq!(eff.config.mode, PolicyMode::Deny);
    }

    #[test]
    fn sockets_empty_declared_allow_forces_deny() {
        let caps = caps_sockets(vec![]);
        let user = SocketsConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![user_sockets_allow_host("vnc.example.com", vec![5900])],
            ..Default::default()
        };
        let eff = effective_sockets(&user, &caps);
        assert!(eff.declared);
        assert_eq!(eff.config.mode, PolicyMode::Deny);
    }

    #[test]
    fn sockets_declared_narrows_user_allow() {
        let caps = caps_sockets(vec![act_types::SocketsAllow {
            host: Some("vnc.example.com".into()),
            cidr: None,
            ports: Some(vec![5900]),
            protocols: vec![act_types::SocketProtocol::Tcp],
        }]);
        let user = SocketsConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![
                user_sockets_allow_host("vnc.example.com", vec![5900]),
                user_sockets_allow_host("evil.com", vec![5900]),
            ],
            ..Default::default()
        };
        let eff = effective_sockets(&user, &caps);
        assert_eq!(eff.config.allow.len(), 1);
        assert_eq!(
            eff.config.allow[0].net.host.as_deref(),
            Some("vnc.example.com")
        );
    }

    #[test]
    fn sockets_open_becomes_allowlist_over_declared_rules() {
        let caps = caps_sockets(vec![act_types::SocketsAllow {
            host: Some("vnc.example.com".into()),
            cidr: None,
            ports: Some(vec![5900]),
            protocols: vec![act_types::SocketProtocol::Tcp],
        }]);
        let user = SocketsConfig {
            mode: PolicyMode::Open,
            ..Default::default()
        };
        let eff = effective_sockets(&user, &caps);
        assert_eq!(eff.config.mode, PolicyMode::Allowlist);
        assert_eq!(eff.config.allow.len(), 1);
        assert_eq!(
            eff.config.allow[0].protocols.as_deref(),
            Some(&[act_types::SocketProtocol::Tcp][..])
        );
    }

    #[test]
    fn sockets_ask_is_bounded_by_declared_ceiling() {
        let caps = caps_sockets(vec![act_types::SocketsAllow {
            host: Some("vnc.example.com".into()),
            cidr: None,
            ports: Some(vec![5900]),
            protocols: vec![act_types::SocketProtocol::Tcp],
        }]);
        let user = SocketsConfig {
            mode: PolicyMode::Ask,
            ..Default::default()
        };
        let eff = effective_sockets(&user, &caps);
        assert_eq!(eff.config.mode, PolicyMode::Ask);
        assert_eq!(eff.config.allow.len(), 1);
        assert_eq!(
            eff.config.allow[0].net.host.as_deref(),
            Some("vnc.example.com")
        );
    }

    #[test]
    fn sockets_protocol_mismatch_drops_user_rule() {
        let caps = caps_sockets(vec![act_types::SocketsAllow {
            host: Some("vnc.example.com".into()),
            cidr: None,
            ports: Some(vec![5900]),
            protocols: vec![act_types::SocketProtocol::Tcp],
        }]);
        let user = SocketsConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![SocketsRule {
                net: NetworkRule {
                    host: Some("vnc.example.com".into()),
                    ports: Some(vec![5900]),
                    ..Default::default()
                },
                protocols: Some(vec![act_types::SocketProtocol::Udp]),
            }],
            ..Default::default()
        };
        let eff = effective_sockets(&user, &caps);
        assert_eq!(eff.config.allow.len(), 0);
    }
}
