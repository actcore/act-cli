//! Layer 1 of the runtime-policy design: declaration gate + static allowlist
//! for `wasi:filesystem` and `wasi:http`. See
//! `docs/specs/2026-04-19-runtime-policy-hooks-design.md`.
//!
//! This module owns the config parsing and CLI-override resolution. Runtime
//! enforcement (custom WASI impls) lives in `runtime.rs` and consumes the
//! resolved structs produced here.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

// ── Public resolved types (consumed by runtime.rs) ──

/// Policy mode, shared by filesystem and HTTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyMode {
    #[default]
    Deny,
    Allowlist,
    Open,
}

impl PolicyMode {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "deny" => Ok(Self::Deny),
            "allowlist" => Ok(Self::Allowlist),
            "open" => Ok(Self::Open),
            other => anyhow::bail!(
                "unknown policy mode '{}' (expected deny / allowlist / open)",
                other
            ),
        }
    }
}

/// Resolved filesystem policy for a component invocation.
#[derive(Debug, Clone, Default)]
pub struct FsConfig {
    pub mode: PolicyMode,
    pub allow: Vec<String>,
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
    pub net: crate::runtime::network::NetworkRule,
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
    pub net: crate::runtime::network::NetworkRule,
    /// Restrict to specific protocols. None = any (default for user
    /// rules); declarations always carry an explicit list.
    #[serde(default)]
    pub protocols: Option<Vec<act_types::SocketProtocol>>,
}

// ── Uniform grant types ──

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
            default: PolicyMode::Deny,
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

    /// Merge `higher` over self: entries in `higher` replace those in self;
    /// `higher.default` replaces self.default only if explicitly set by the caller
    /// (callers pass the lower default through when not overriding).
    pub fn merge_over(&mut self, higher: GrantPolicy) {
        self.default = higher.default;
        for (k, v) in higher.entries {
            self.entries.insert(k, v);
        }
    }
}

/// Map the `wasi:filesystem` grant to the enforcement-facing `FsConfig`.
pub fn to_fs_config(gp: &GrantPolicy) -> anyhow::Result<FsConfig> {
    let g = gp.resolve(act_types::constants::CAP_FILESYSTEM);
    let allow = parse_fs_constraints(&g.allow)?;
    let deny = parse_fs_constraints(&g.deny)?;
    Ok(FsConfig {
        mode: g.mode,
        allow,
        deny,
    })
}

fn parse_fs_constraints(cs: &[serde_json::Value]) -> anyhow::Result<Vec<String>> {
    cs.iter()
        .map(|c| {
            let a: act_types::FilesystemAllow =
                serde_json::from_value(c.clone()).context("invalid wasi:filesystem constraint")?;
            Ok(a.path)
        })
        .collect()
}

/// Map the `wasi:http` grant to `HttpConfig` (constraints → HttpRule).
pub fn to_http_config(gp: &GrantPolicy) -> anyhow::Result<HttpConfig> {
    let g = gp.resolve(act_types::constants::CAP_HTTP);
    Ok(HttpConfig {
        mode: g.mode,
        allow: parse_http_constraints(&g.allow)?,
        deny: parse_http_constraints(&g.deny)?,
    })
}

fn parse_http_constraints(cs: &[serde_json::Value]) -> anyhow::Result<Vec<HttpRule>> {
    cs.iter()
        .map(|c| {
            serde_json::from_value::<HttpRule>(c.clone()).context("invalid wasi:http constraint")
        })
        .collect()
}

/// Map the `wasi:sockets` grant to `SocketsConfig` (constraints → SocketsRule).
pub fn to_sockets_config(gp: &GrantPolicy) -> anyhow::Result<SocketsConfig> {
    let g = gp.resolve(act_types::constants::CAP_SOCKETS);
    Ok(SocketsConfig {
        mode: g.mode,
        allow: parse_sockets_constraints(&g.allow)?,
        deny: parse_sockets_constraints(&g.deny)?,
    })
}

fn parse_sockets_constraints(cs: &[serde_json::Value]) -> anyhow::Result<Vec<SocketsRule>> {
    cs.iter()
        .map(|c| {
            serde_json::from_value::<SocketsRule>(c.clone())
                .context("invalid wasi:sockets constraint")
        })
        .collect()
}

// ── TOML deserialization types ──

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ConfigFile {
    #[serde(default)]
    #[allow(dead_code)]
    pub listen: Option<String>,
    #[serde(rename = "log-level", default)]
    pub log_level: Option<String>,
    #[serde(default)]
    pub policy: Option<PolicyConfig>,
    #[serde(default)]
    pub profile: HashMap<String, ProfileConfig>,
}

/// Uniform `[policy]` section: a global `default` mode + per-id/pattern grants.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub default: Option<String>,
    #[serde(flatten)]
    pub entries: BTreeMap<String, GrantToml>,
}

/// A grant in TOML: shorthand mode string, or a structured table.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum GrantToml {
    Simple(String),
    Structured {
        mode: String,
        #[serde(default)]
        allow: Vec<serde_json::Value>,
        #[serde(default)]
        deny: Vec<serde_json::Value>,
    },
}

impl GrantToml {
    fn to_grant(&self) -> anyhow::Result<CapabilityGrant> {
        match self {
            GrantToml::Simple(m) => Ok(CapabilityGrant {
                mode: PolicyMode::parse(m)?,
                ..Default::default()
            }),
            GrantToml::Structured { mode, allow, deny } => Ok(CapabilityGrant {
                mode: PolicyMode::parse(mode)?,
                allow: allow.clone(),
                deny: deny.clone(),
            }),
        }
    }
}

impl PolicyConfig {
    fn to_grant_policy(&self) -> anyhow::Result<GrantPolicy> {
        let default = match &self.default {
            Some(m) => PolicyMode::parse(m)?,
            None => PolicyMode::Deny,
        };
        let mut entries = BTreeMap::new();
        for (id, g) in &self.entries {
            entries.insert(id.clone(), g.to_grant()?);
        }
        Ok(GrantPolicy { default, entries })
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ProfileConfig {
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub policy: Option<PolicyConfig>,
}

// ── Loading ──

/// Default config file path: `~/.config/act/config.toml`.
pub fn default_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("act").join("config.toml"))
}

/// Load and parse a TOML config file. Returns `ConfigFile::default()` if the file doesn't exist.
pub fn load_config(path: Option<&Path>) -> Result<ConfigFile> {
    let path = match path {
        Some(p) => {
            if !p.exists() {
                anyhow::bail!("config file not found: {}", p.display());
            }
            p.to_path_buf()
        }
        None => match default_config_path() {
            Some(p) if p.exists() => p,
            _ => return Ok(ConfigFile::default()),
        },
    };

    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("reading config file: {}", path.display()))?;
    let config: ConfigFile =
        toml::from_str(&contents).with_context(|| format!("parsing {}", path.display()))?;
    Ok(config)
}

/// Resolve a profile by name from a loaded config.
pub fn get_profile<'a>(config: &'a ConfigFile, name: &str) -> Result<&'a ProfileConfig> {
    config
        .profile
        .get(name)
        .with_context(|| format!("profile '{}' not found in config", name))
}

// ── Resolution ──

/// CLI-supplied grants (from --grant / --allow / --deny).
#[derive(Debug, Default)]
pub struct CliGrants {
    /// Raw `--grant '<json>'` values (each a JSON object: id -> mode-string | {mode,allow,deny}).
    pub grant_json: Vec<String>,
    /// `--allow <id>` → that id at mode=open.
    pub allow_ids: Vec<String>,
    /// `--deny <id>` → that id at mode=deny.
    pub deny_ids: Vec<String>,
}

impl CliGrants {
    fn is_empty(&self) -> bool {
        self.grant_json.is_empty() && self.allow_ids.is_empty() && self.deny_ids.is_empty()
    }

    fn to_grant_policy(&self) -> anyhow::Result<GrantPolicy> {
        let mut entries = BTreeMap::new();
        for raw in &self.grant_json {
            let map: BTreeMap<String, GrantToml> = serde_json::from_str(raw)
                .context("--grant must be a JSON object: {\"id\": mode|{...}}")?;
            for (id, g) in map {
                entries.insert(id, g.to_grant()?);
            }
        }
        for id in &self.allow_ids {
            entries.insert(
                id.clone(),
                CapabilityGrant {
                    mode: PolicyMode::Open,
                    ..Default::default()
                },
            );
        }
        for id in &self.deny_ids {
            entries.insert(
                id.clone(),
                CapabilityGrant {
                    mode: PolicyMode::Deny,
                    ..Default::default()
                },
            );
        }
        Ok(GrantPolicy {
            default: PolicyMode::Deny,
            entries,
        })
    }
}

/// Build the effective grant policy: global [policy] < profile [policy] < CLI grants.
pub fn build_grant_policy(
    config: &ConfigFile,
    profile: Option<&ProfileConfig>,
    cli: &CliGrants,
) -> anyhow::Result<GrantPolicy> {
    let mut gp = GrantPolicy::default();
    if let Some(p) = &config.policy {
        gp = p.to_grant_policy()?;
    }
    if let Some(prof) = profile
        && let Some(p) = &prof.policy
    {
        let prof_gp = p.to_grant_policy()?;
        gp.merge_over(prof_gp);
    }
    if !cli.is_empty() {
        let mut cli_gp = cli.to_grant_policy()?;
        // CLI doesn't set a global default; keep the lower layer's default.
        cli_gp.default = gp.default;
        gp.merge_over(cli_gp);
    }
    Ok(gp)
}

/// Resolve the merged metadata from profile + CLI.
/// CLI metadata takes precedence over profile metadata.
pub fn resolve_metadata(
    profile: Option<&ProfileConfig>,
    cli_metadata: Option<&serde_json::Value>,
) -> serde_json::Value {
    let mut merged = serde_json::Map::new();

    if let Some(profile) = profile
        && let Some(serde_json::Value::Object(m)) = &profile.metadata
    {
        merged.extend(m.clone());
    }

    if let Some(serde_json::Value::Object(m)) = cli_metadata {
        merged.extend(m.clone());
    }

    if merged.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::Object(merged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_mode_parse() {
        assert_eq!(PolicyMode::parse("deny").unwrap(), PolicyMode::Deny);
        assert_eq!(
            PolicyMode::parse("allowlist").unwrap(),
            PolicyMode::Allowlist
        );
        assert_eq!(PolicyMode::parse("open").unwrap(), PolicyMode::Open);
        assert!(PolicyMode::parse("bogus").is_err());
    }

    #[test]
    fn grant_resolve_priority() {
        let mut entries = std::collections::BTreeMap::new();
        entries.insert(
            "db:*".into(),
            CapabilityGrant {
                mode: PolicyMode::Allowlist,
                ..Default::default()
            },
        );
        entries.insert(
            "db:drop-database".into(),
            CapabilityGrant {
                mode: PolicyMode::Deny,
                ..Default::default()
            },
        );
        let gp = GrantPolicy {
            default: PolicyMode::Deny,
            entries,
        };
        assert_eq!(gp.resolve("db:drop-database").mode, PolicyMode::Deny); // exact wins
        assert_eq!(gp.resolve("db:truncate").mode, PolicyMode::Allowlist); // wildcard
        assert_eq!(gp.resolve("email:send").mode, PolicyMode::Deny); // default
    }

    #[test]
    fn grant_maps_to_fs_config() {
        use serde_json::json;
        let mut entries = std::collections::BTreeMap::new();
        entries.insert(
            "wasi:filesystem".into(),
            CapabilityGrant {
                mode: PolicyMode::Allowlist,
                allow: vec![json!({ "path": "/data/**", "mode": "rw" })],
                deny: vec![],
            },
        );
        let gp = GrantPolicy {
            default: PolicyMode::Deny,
            entries,
        };
        let fs = to_fs_config(&gp).unwrap();
        assert_eq!(fs.mode, PolicyMode::Allowlist);
        assert_eq!(fs.allow, vec!["/data/**".to_string()]);
    }

    #[test]
    fn cli_http_allow_host() {
        use serde_json::json;
        let cli = CliGrants {
            grant_json: vec![
                serde_json::to_string(&json!({
                    "wasi:http": {
                        "mode": "allowlist",
                        "allow": [{ "host": "api.example.com" }]
                    }
                }))
                .unwrap(),
            ],
            ..Default::default()
        };
        let gp = build_grant_policy(&ConfigFile::default(), None, &cli).unwrap();
        let cfg = to_http_config(&gp).unwrap();
        assert_eq!(cfg.mode, PolicyMode::Allowlist);
        assert_eq!(cfg.allow[0].net.host.as_deref(), Some("api.example.com"));
    }

    #[test]
    fn cli_http_deny_cidr() {
        use serde_json::json;
        let cli = CliGrants {
            grant_json: vec![
                serde_json::to_string(&json!({
                    "wasi:http": {
                        "mode": "deny",
                        "deny": [{ "cidr": "10.0.0.0/8" }]
                    }
                }))
                .unwrap(),
            ],
            ..Default::default()
        };
        let gp = build_grant_policy(&ConfigFile::default(), None, &cli).unwrap();
        let cfg = to_http_config(&gp).unwrap();
        assert_eq!(cfg.mode, PolicyMode::Deny);
        assert_eq!(cfg.deny[0].net.cidr.as_deref(), Some("10.0.0.0/8"));
    }

    #[test]
    fn toml_policy_shorthand() {
        let toml_input = r#"
[policy]
default = "deny"
"wasi:http" = "open"

[policy."wasi:filesystem"]
mode = "allowlist"
allow = [{ path = "/tmp/**", mode = "rw" }]
"#;
        let cfg: ConfigFile = toml::from_str(toml_input).expect("parses");
        let gp = cfg.policy.as_ref().unwrap().to_grant_policy().unwrap();
        assert_eq!(to_http_config(&gp).unwrap().mode, PolicyMode::Open);
        let fs = to_fs_config(&gp).unwrap();
        assert_eq!(fs.mode, PolicyMode::Allowlist);
        assert_eq!(fs.allow, vec!["/tmp/**".to_string()]);
    }

    #[test]
    fn toml_policy_structured() {
        use serde_json::json;
        let toml_input = r#"
[policy]
default = "deny"

[policy."wasi:filesystem"]
mode = "allowlist"
allow = [{ path = "/tmp/**", mode = "rw" }]
deny = [{ path = "**/.ssh/**", mode = "ro" }]

[policy."wasi:http"]
mode = "allowlist"
allow = [{ host = "api.openai.com", scheme = "https" }]
"#;
        let cfg: ConfigFile = toml::from_str(toml_input).expect("parses");
        let gp = cfg.policy.as_ref().unwrap().to_grant_policy().unwrap();
        let fs = to_fs_config(&gp).unwrap();
        assert_eq!(fs.mode, PolicyMode::Allowlist);
        assert_eq!(fs.allow, vec!["/tmp/**"]);
        assert_eq!(fs.deny, vec!["**/.ssh/**"]);
        let http = to_http_config(&gp).unwrap();
        assert_eq!(http.mode, PolicyMode::Allowlist);
        assert_eq!(http.allow[0].net.host.as_deref(), Some("api.openai.com"));
        assert_eq!(http.allow[0].scheme.as_deref(), Some("https"));
    }

    #[test]
    fn cli_overrides_config_file() {
        use serde_json::json;
        let toml_input = r#"
[policy]
default = "deny"
"wasi:filesystem" = "deny"
"#;
        let cfg: ConfigFile = toml::from_str(toml_input).unwrap();
        let cli = CliGrants {
            grant_json: vec![
                serde_json::to_string(&json!({
                    "wasi:filesystem": {
                        "mode": "allowlist",
                        "allow": [{ "path": "/tmp/work", "mode": "rw" }]
                    }
                }))
                .unwrap(),
            ],
            ..Default::default()
        };
        let gp = build_grant_policy(&cfg, None, &cli).unwrap();
        let fs = to_fs_config(&gp).unwrap();
        assert_eq!(fs.mode, PolicyMode::Allowlist);
        assert_eq!(fs.allow, vec!["/tmp/work"]);
    }

    #[test]
    fn sockets_cli_allow_host_port() {
        use serde_json::json;
        let cli = CliGrants {
            grant_json: vec![
                serde_json::to_string(&json!({
                    "wasi:sockets": {
                        "mode": "allowlist",
                        "allow": [{ "host": "vnc.example.com", "ports": [5900], "protocols": ["tcp"] }]
                    }
                }))
                .unwrap(),
            ],
            ..Default::default()
        };
        let gp = build_grant_policy(&ConfigFile::default(), None, &cli).unwrap();
        let cfg = to_sockets_config(&gp).unwrap();
        assert_eq!(cfg.mode, PolicyMode::Allowlist);
        assert_eq!(cfg.allow.len(), 1);
        assert_eq!(cfg.allow[0].net.host.as_deref(), Some("vnc.example.com"));
        assert_eq!(cfg.allow[0].net.ports.as_deref(), Some(&[5900u16][..]));
        assert_eq!(
            cfg.allow[0].protocols.as_deref(),
            Some(&[act_types::SocketProtocol::Tcp][..])
        );
    }

    #[test]
    fn sockets_cli_cidr_multiport_default_protocols() {
        use serde_json::json;
        let cli = CliGrants {
            grant_json: vec![
                serde_json::to_string(&json!({
                    "wasi:sockets": {
                        "mode": "allowlist",
                        "allow": [{ "cidr": "10.0.0.0/8", "ports": [80, 443] }]
                    }
                }))
                .unwrap(),
            ],
            ..Default::default()
        };
        let gp = build_grant_policy(&ConfigFile::default(), None, &cli).unwrap();
        let cfg = to_sockets_config(&gp).unwrap();
        assert_eq!(cfg.allow[0].net.cidr.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(cfg.allow[0].net.host, None);
        assert_eq!(cfg.allow[0].net.ports.as_deref(), Some(&[80u16, 443][..]));
        // No protocols field in the JSON → None (any protocol)
        assert!(cfg.allow[0].protocols.is_none());
    }

    #[test]
    fn sockets_toml_structured() {
        let toml_input = r#"
[policy."wasi:sockets"]
mode = "allowlist"
allow = [{ host = "vnc.example.com", ports = [5900], protocols = ["tcp"] }]
deny = [{ cidr = "127.0.0.0/8", ports = [5900], "except-ports" = [5901] }]
"#;
        let cfg: ConfigFile = toml::from_str(toml_input).expect("parses");
        let gp = cfg.policy.as_ref().unwrap().to_grant_policy().unwrap();
        let s = to_sockets_config(&gp).unwrap();
        assert_eq!(s.mode, PolicyMode::Allowlist);
        assert_eq!(s.allow[0].net.host.as_deref(), Some("vnc.example.com"));
        assert_eq!(s.deny[0].net.cidr.as_deref(), Some("127.0.0.0/8"));
        assert_eq!(s.deny[0].net.except_ports.as_deref(), Some(&[5901u16][..]));
    }
}
