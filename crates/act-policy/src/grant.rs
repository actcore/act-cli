//! Grant and policy config types: `PolicyMode`, capability grant shapes,
//! and the per-class config structs produced by the mapper functions.

use std::collections::BTreeMap;

use serde::Deserialize;

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid {cap} constraint: {source}")]
    Constraint {
        cap: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid policy mode '{0}': expected deny / allowlist / open / ask")]
    InvalidMode(String),
    #[error("invalid glob {pat:?}: {source}")]
    Glob {
        pat: String,
        #[source]
        source: globset::Error,
    },
    #[error("capability {cap}: {source}")]
    Capability {
        cap: String,
        #[source]
        source: Box<PolicyError>,
    },
}

// ── Policy mode ───────────────────────────────────────────────────────────────

/// Policy mode, shared by filesystem, HTTP, and sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyMode {
    #[default]
    Deny,
    Allowlist,
    Open,
    /// Prompt the operator on first access to each key, remember the decision
    /// for the session, and degrade to deny when no prompt channel exists
    /// (headless / --mcp / non-TTY). A per-op gate layered on top of the
    /// ceiling intersection.
    Ask,
}

impl PolicyMode {
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        match s {
            "deny" => Ok(Self::Deny),
            "allowlist" => Ok(Self::Allowlist),
            "open" => Ok(Self::Open),
            "ask" => Ok(Self::Ask),
            other => Err(PolicyError::InvalidMode(other.to_string())),
        }
    }
}

impl std::fmt::Display for PolicyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Deny => "deny",
            Self::Allowlist => "allowlist",
            Self::Open => "open",
            Self::Ask => "ask",
        })
    }
}

// ── Resolved config types ─────────────────────────────────────────────────────

/// One entry in a filesystem allow list: a glob pattern plus the access mode
/// the entry permits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsAllow {
    pub glob: String,
    pub mode: act_types::FsMode,
}

/// Resolved filesystem policy for a component invocation.
#[derive(Debug, Clone, Default)]
pub struct FsConfig {
    pub mode: PolicyMode,
    pub allow: Vec<FsAllow>,
    // Consumed by the per-op matcher in Layer 1 Phase C (custom WASI impl).
    // Kept in the public struct so config + CLI parsing is end-to-end now.
    #[allow(dead_code)]
    pub deny: Vec<String>,
}

impl FsConfig {
    #[allow(dead_code)]
    pub fn deny() -> Self {
        Self {
            mode: PolicyMode::Deny,
            ..Default::default()
        }
    }
}

/// Resolved HTTP policy for a component invocation.
///
/// `allow` / `deny` rules are consumed by the per-op matcher in Layer 1
/// Phase C (custom `WasiHttpHooks::send_request`). Kept public so config +
/// CLI parsing is end-to-end now.
#[derive(Debug, Clone, Default)]
pub struct HttpConfig {
    pub mode: PolicyMode,
    #[allow(dead_code)]
    pub allow: Vec<HttpRule>,
    #[allow(dead_code)]
    pub deny: Vec<HttpRule>,
}

/// One allow-or-deny entry in an HTTP policy.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct HttpRule {
    /// Host / port / CIDR fields. Network-level (no HTTP awareness).
    #[serde(flatten)]
    pub net: crate::net::NetworkRule,
    /// Required URI scheme (`"http"` / `"https"`), if set.
    #[serde(default)]
    pub scheme: Option<String>,
    /// Allowed HTTP methods (case-insensitive), if set.
    #[serde(default)]
    pub methods: Option<Vec<String>>,
}

/// Resolved sockets policy for a component invocation.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)] // consumed by sockets_policy + Task 5 wiring
pub struct SocketsConfig {
    pub mode: PolicyMode,
    pub allow: Vec<SocketsRule>,
    pub deny: Vec<SocketsRule>,
}

/// One allow-or-deny entry in a sockets policy.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct SocketsRule {
    /// Host / port / CIDR fields. Reuses the network-rule shape.
    #[serde(flatten)]
    pub net: crate::net::NetworkRule,
    /// Restrict to specific protocols. None = any (default for user
    /// rules); declarations always carry an explicit list.
    #[serde(default)]
    pub protocols: Option<Vec<act_types::SocketProtocol>>,
}

// ── Uniform grant types ───────────────────────────────────────────────────────

/// A grant for one capability id or pattern. Constraints are provider-defined
/// JSON (the `act:core` constraint shape). Modes: deny/allowlist/open.
#[derive(Debug, Clone, Default)]
pub struct CapabilityGrant {
    pub mode: PolicyMode,
    pub allow: Vec<serde_json::Value>,
    pub deny: Vec<serde_json::Value>,
}

/// Resolved host grant policy: a global default + per-id/pattern entries.
#[derive(Debug, Clone)]
pub struct GrantPolicy {
    pub default: PolicyMode,
    pub entries: BTreeMap<String, CapabilityGrant>,
}

impl Default for GrantPolicy {
    fn default() -> Self {
        Self {
            // Ask-by-default: an undeclared `[policy] default` resolves to
            // `ask`, so interactive runs prompt-on-access and headless runs
            // degrade to deny. The `PolicyMode` enum `Default` stays `Deny`
            // (used for empty single-layer configs elsewhere).
            default: PolicyMode::Ask,
            entries: BTreeMap::new(),
        }
    }
}

impl GrantPolicy {
    /// Resolve the effective grant for a concrete capability id.
    /// Priority: exact entry > longest matching `*`-prefix entry > default.
    pub fn resolve(&self, id: &str) -> CapabilityGrant {
        if let Some(g) = self.entries.get(id) {
            return g.clone();
        }
        let mut best: Option<(&str, &CapabilityGrant)> = None;
        for (k, g) in &self.entries {
            if let Some(prefix) = k.strip_suffix('*')
                && id.starts_with(prefix)
                && best.is_none_or(|(bk, _)| prefix.len() > bk.len() - 1)
            {
                best = Some((k, g));
            }
        }
        if let Some((_, g)) = best {
            return g.clone();
        }
        CapabilityGrant {
            mode: self.default,
            allow: vec![],
            deny: vec![],
        }
    }
}

// ── Mapper functions ──────────────────────────────────────────────────────────

/// Map the `wasi:filesystem` grant to the enforcement-facing `FsConfig`.
pub fn to_fs_config(gp: &GrantPolicy) -> Result<FsConfig, PolicyError> {
    let g = gp.resolve(act_types::constants::CAP_FILESYSTEM);
    let allow = parse_fs_allow_constraints(&g.allow)?;
    let deny = parse_fs_deny_constraints(&g.deny)?;
    Ok(FsConfig {
        mode: g.mode,
        allow,
        deny,
    })
}

fn parse_fs_allow_constraints(cs: &[serde_json::Value]) -> Result<Vec<FsAllow>, PolicyError> {
    cs.iter()
        .map(|c| {
            let a: act_types::FilesystemAllow =
                serde_json::from_value(c.clone()).map_err(|e| PolicyError::Constraint {
                    cap: "wasi:filesystem",
                    source: e,
                })?;
            Ok(FsAllow {
                glob: a.path,
                mode: a.mode,
            })
        })
        .collect()
}

fn parse_fs_deny_constraints(cs: &[serde_json::Value]) -> Result<Vec<String>, PolicyError> {
    cs.iter()
        .map(|c| {
            let a: act_types::FilesystemAllow =
                serde_json::from_value(c.clone()).map_err(|e| PolicyError::Constraint {
                    cap: "wasi:filesystem",
                    source: e,
                })?;
            Ok(a.path)
        })
        .collect()
}

/// Map the `wasi:http` grant to `HttpConfig` (constraints → HttpRule).
pub fn to_http_config(gp: &GrantPolicy) -> Result<HttpConfig, PolicyError> {
    let g = gp.resolve(act_types::constants::CAP_HTTP);
    Ok(HttpConfig {
        mode: g.mode,
        allow: parse_http_constraints(&g.allow)?,
        deny: parse_http_constraints(&g.deny)?,
    })
}

fn parse_http_constraints(cs: &[serde_json::Value]) -> Result<Vec<HttpRule>, PolicyError> {
    cs.iter()
        .map(|c| {
            serde_json::from_value::<HttpRule>(c.clone()).map_err(|e| PolicyError::Constraint {
                cap: "wasi:http",
                source: e,
            })
        })
        .collect()
}

/// Map the `wasi:sockets` grant to `SocketsConfig` (constraints → SocketsRule).
pub fn to_sockets_config(gp: &GrantPolicy) -> Result<SocketsConfig, PolicyError> {
    let g = gp.resolve(act_types::constants::CAP_SOCKETS);
    Ok(SocketsConfig {
        mode: g.mode,
        allow: parse_sockets_constraints(&g.allow)?,
        deny: parse_sockets_constraints(&g.deny)?,
    })
}

fn parse_sockets_constraints(cs: &[serde_json::Value]) -> Result<Vec<SocketsRule>, PolicyError> {
    cs.iter()
        .map(|c| {
            serde_json::from_value::<SocketsRule>(c.clone()).map_err(|e| PolicyError::Constraint {
                cap: "wasi:sockets",
                source: e,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::PolicyMode;

    #[test]
    fn policy_mode_display_renders_the_config_spellings() {
        // These are the exact strings an operator reads in an audit line and
        // the config file accepts under `[policy]` — they must match.
        assert_eq!(PolicyMode::Deny.to_string(), "deny");
        assert_eq!(PolicyMode::Allowlist.to_string(), "allowlist");
        assert_eq!(PolicyMode::Open.to_string(), "open");
        assert_eq!(PolicyMode::Ask.to_string(), "ask");
    }
}
