//! Layer 1 of the runtime-policy design: declaration gate + static allowlist
//! for `wasi:filesystem` and `wasi:http`. See
//! `docs/specs/2026-04-19-runtime-policy-hooks-design.md`.
//!
//! This module owns the config parsing and CLI-override resolution. Runtime
//! enforcement (custom WASI impls) lives in `runtime.rs` and consumes the
//! resolved structs produced here.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
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
    fn parse(s: &str) -> Result<Self> {
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

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PolicyConfig {
    #[serde(default)]
    pub filesystem: Option<FsPolicyToml>,
    #[serde(default)]
    pub http: Option<HttpPolicyToml>,
    #[allow(dead_code)] // wired by resolve_sockets_config + Task 5
    #[serde(default)]
    pub sockets: Option<SocketsPolicyToml>,
}

/// Filesystem policy in TOML: shorthand string (`"deny"` / `"allowlist"` /
/// `"open"`) or a structured object with `mode` + `allow` + `deny` lists.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum FsPolicyToml {
    Simple(String),
    Structured {
        mode: String,
        #[serde(default)]
        allow: Vec<String>,
        #[serde(default)]
        deny: Vec<String>,
    },
}

/// HTTP policy in TOML: shorthand string or structured object.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum HttpPolicyToml {
    Simple(String),
    Structured {
        mode: String,
        #[serde(default)]
        allow: Vec<HttpRule>,
        #[serde(default)]
        deny: Vec<HttpRule>,
    },
}

/// Sockets policy in TOML: shorthand string or structured object.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[allow(dead_code)] // wired by resolve_sockets_config + Task 5
#[serde(untagged)]
pub enum SocketsPolicyToml {
    Simple(String),
    Structured {
        mode: String,
        #[serde(default)]
        allow: Vec<SocketsRule>,
        #[serde(default)]
        deny: Vec<SocketsRule>,
    },
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

/// CLI-provided policy overrides, collected in one place.
#[derive(Debug, Default)]
pub struct CliPolicyOverrides {
    pub fs_mode: Option<String>,
    pub fs_allow: Vec<String>,
    pub fs_deny: Vec<String>,
    pub http_mode: Option<String>,
    pub http_allow: Vec<String>,
    pub http_deny: Vec<String>,
    #[allow(dead_code)] // wired in Task 5
    pub sockets_mode: Option<String>,
    #[allow(dead_code)]
    pub sockets_allow: Vec<String>,
    #[allow(dead_code)]
    pub sockets_deny: Vec<String>,
}

impl CliPolicyOverrides {
    fn any_fs_override(&self) -> bool {
        self.fs_mode.is_some() || !self.fs_allow.is_empty() || !self.fs_deny.is_empty()
    }
    fn any_http_override(&self) -> bool {
        self.http_mode.is_some() || !self.http_allow.is_empty() || !self.http_deny.is_empty()
    }
    #[allow(dead_code)] // wired in Task 5
    fn any_sockets_override(&self) -> bool {
        self.sockets_mode.is_some()
            || !self.sockets_allow.is_empty()
            || !self.sockets_deny.is_empty()
    }
}

fn parse_fs_toml(policy: &FsPolicyToml) -> Result<FsConfig> {
    match policy {
        FsPolicyToml::Simple(s) => Ok(FsConfig {
            mode: PolicyMode::parse(s)?,
            ..Default::default()
        }),
        FsPolicyToml::Structured { mode, allow, deny } => Ok(FsConfig {
            mode: PolicyMode::parse(mode)?,
            allow: allow.clone(),
            deny: deny.clone(),
        }),
    }
}

fn parse_http_toml(policy: &HttpPolicyToml) -> Result<HttpConfig> {
    match policy {
        HttpPolicyToml::Simple(s) => Ok(HttpConfig {
            mode: PolicyMode::parse(s)?,
            ..Default::default()
        }),
        HttpPolicyToml::Structured { mode, allow, deny } => Ok(HttpConfig {
            mode: PolicyMode::parse(mode)?,
            allow: allow.clone(),
            deny: deny.clone(),
        }),
    }
}

fn parse_host_or_cidr(s: &str) -> HttpRule {
    use crate::runtime::network::NetworkRule;
    let net = if let Some(slash) = s.find('/')
        && s[slash + 1..].parse::<u32>().is_ok()
    {
        NetworkRule {
            cidr: Some(s.to_string()),
            ..Default::default()
        }
    } else {
        NetworkRule {
            host: Some(s.to_string()),
            ..Default::default()
        }
    };
    HttpRule {
        net,
        ..Default::default()
    }
}

/// Parse a single `--allow-socket` / `--deny-socket` spec.
///
/// Grammar: `<host_or_cidr>:<ports>[/<protos>]`
/// - host: exact, `*.suffix`, or `*`
/// - cidr: `A.B.C.D/N` (must contain `/` and a numeric suffix)
/// - ports: comma-separated u16 list; non-empty
/// - protos: comma-separated subset of `tcp`, `udp`; default unset (any)
#[allow(dead_code)] // wired in Task 5
pub fn parse_socket_spec(s: &str) -> Result<SocketsRule> {
    use crate::runtime::network::NetworkRule;
    use act_types::SocketProtocol;

    // Split off optional /<protocols>. A protocol section is purely
    // alphabetic (comma-separated for multiples); anything containing
    // digits or colons after the last `/` is part of a CIDR mask, not
    // a protocol separator.
    let (host_port, protos) = match s.rsplit_once('/') {
        Some((before, after))
            if !after.is_empty() && after.chars().all(|c| c.is_ascii_alphabetic() || c == ',') =>
        {
            (before, Some(after))
        }
        _ => (s, None),
    };

    let (host_or_cidr, ports_str) = host_port
        .rsplit_once(':')
        .with_context(|| format!("socket spec missing ':<port>' — got {s:?}"))?;

    let mut ports = Vec::new();
    for p in ports_str.split(',') {
        let p = p.trim();
        if p.is_empty() {
            anyhow::bail!("empty port entry in {ports_str:?}");
        }
        ports.push(
            p.parse::<u16>()
                .with_context(|| format!("invalid port {p:?}"))?,
        );
    }
    if ports.is_empty() {
        anyhow::bail!("at least one port required in {s:?}");
    }

    let net = if let Some((_, mask)) = host_or_cidr.rsplit_once('/')
        && mask.parse::<u8>().is_ok()
    {
        NetworkRule {
            cidr: Some(host_or_cidr.to_string()),
            ports: Some(ports),
            ..Default::default()
        }
    } else {
        NetworkRule {
            host: Some(host_or_cidr.to_string()),
            ports: Some(ports),
            ..Default::default()
        }
    };

    let protocols = match protos {
        None => None,
        Some(list) => {
            let mut v = Vec::new();
            for p in list.split(',') {
                v.push(match p.trim() {
                    "tcp" => SocketProtocol::Tcp,
                    "udp" => SocketProtocol::Udp,
                    other => anyhow::bail!("unknown socket protocol {other:?}"),
                });
            }
            Some(v)
        }
    };

    Ok(SocketsRule { net, protocols })
}

/// Resolve the final `FsConfig` from config file + profile + CLI overrides.
pub fn resolve_fs_config(
    config: &ConfigFile,
    profile: Option<&ProfileConfig>,
    cli: &CliPolicyOverrides,
) -> Result<FsConfig> {
    if cli.any_fs_override() {
        let mode = match cli.fs_mode.as_deref() {
            Some(m) => PolicyMode::parse(m)?,
            None if !cli.fs_allow.is_empty() => PolicyMode::Allowlist,
            None => PolicyMode::Deny,
        };
        return Ok(FsConfig {
            mode,
            allow: cli.fs_allow.clone(),
            deny: cli.fs_deny.clone(),
        });
    }

    if let Some(profile) = profile
        && let Some(ref policy) = profile.policy
        && let Some(ref fs) = policy.filesystem
    {
        return parse_fs_toml(fs);
    }

    if let Some(ref policy) = config.policy
        && let Some(ref fs) = policy.filesystem
    {
        return parse_fs_toml(fs);
    }

    Ok(FsConfig::deny())
}

/// Resolve the final `HttpConfig` from config file + profile + CLI overrides.
pub fn resolve_http_config(
    config: &ConfigFile,
    profile: Option<&ProfileConfig>,
    cli: &CliPolicyOverrides,
) -> Result<HttpConfig> {
    if cli.any_http_override() {
        let mode = match cli.http_mode.as_deref() {
            Some(m) => PolicyMode::parse(m)?,
            None if !cli.http_allow.is_empty() => PolicyMode::Allowlist,
            None => PolicyMode::Deny,
        };
        let allow: Vec<HttpRule> = cli
            .http_allow
            .iter()
            .map(|s| parse_host_or_cidr(s))
            .collect();
        let deny: Vec<HttpRule> = cli
            .http_deny
            .iter()
            .map(|s| parse_host_or_cidr(s))
            .collect();
        return Ok(HttpConfig { mode, allow, deny });
    }

    if let Some(profile) = profile
        && let Some(ref policy) = profile.policy
        && let Some(ref http) = policy.http
    {
        return parse_http_toml(http);
    }

    if let Some(ref policy) = config.policy
        && let Some(ref http) = policy.http
    {
        return parse_http_toml(http);
    }

    Ok(HttpConfig::default())
}

#[allow(dead_code)] // wired in Task 5
fn parse_sockets_toml(policy: &SocketsPolicyToml) -> Result<SocketsConfig> {
    match policy {
        SocketsPolicyToml::Simple(s) => Ok(SocketsConfig {
            mode: PolicyMode::parse(s)?,
            ..Default::default()
        }),
        SocketsPolicyToml::Structured { mode, allow, deny } => Ok(SocketsConfig {
            mode: PolicyMode::parse(mode)?,
            allow: allow.clone(),
            deny: deny.clone(),
        }),
    }
}

/// Resolve the final `SocketsConfig` from config file + profile + CLI overrides.
#[allow(dead_code)] // wired in Task 5
pub fn resolve_sockets_config(
    config: &ConfigFile,
    profile: Option<&ProfileConfig>,
    cli: &CliPolicyOverrides,
) -> Result<SocketsConfig> {
    if cli.any_sockets_override() {
        let mode = match cli.sockets_mode.as_deref() {
            Some(m) => PolicyMode::parse(m)?,
            None if !cli.sockets_allow.is_empty() => PolicyMode::Allowlist,
            None => PolicyMode::Deny,
        };
        let allow: Result<Vec<_>> = cli
            .sockets_allow
            .iter()
            .map(|s| parse_socket_spec(s))
            .collect();
        let deny: Result<Vec<_>> = cli
            .sockets_deny
            .iter()
            .map(|s| parse_socket_spec(s))
            .collect();
        return Ok(SocketsConfig {
            mode,
            allow: allow?,
            deny: deny?,
        });
    }

    if let Some(profile) = profile
        && let Some(ref policy) = profile.policy
        && let Some(ref sockets) = policy.sockets
    {
        return parse_sockets_toml(sockets);
    }

    if let Some(ref policy) = config.policy
        && let Some(ref sockets) = policy.sockets
    {
        return parse_sockets_toml(sockets);
    }

    Ok(SocketsConfig::default())
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
    fn cli_http_allow_host() {
        let cli = CliPolicyOverrides {
            http_allow: vec!["api.example.com".into()],
            ..Default::default()
        };
        let cfg = resolve_http_config(&ConfigFile::default(), None, &cli).unwrap();
        assert_eq!(cfg.mode, PolicyMode::Allowlist);
        assert_eq!(cfg.allow[0].net.host.as_deref(), Some("api.example.com"));
    }

    #[test]
    fn cli_http_deny_cidr() {
        let cli = CliPolicyOverrides {
            http_deny: vec!["10.0.0.0/8".into()],
            ..Default::default()
        };
        let cfg = resolve_http_config(&ConfigFile::default(), None, &cli).unwrap();
        assert_eq!(cfg.mode, PolicyMode::Deny);
        assert_eq!(cfg.deny[0].net.cidr.as_deref(), Some("10.0.0.0/8"));
    }

    #[test]
    fn toml_policy_shorthand() {
        let toml = r#"
[policy]
filesystem = "allowlist"
http = "deny"
"#;
        let cfg: ConfigFile = toml::from_str(toml).unwrap();
        let fs = resolve_fs_config(&cfg, None, &CliPolicyOverrides::default()).unwrap();
        let http = resolve_http_config(&cfg, None, &CliPolicyOverrides::default()).unwrap();
        assert_eq!(fs.mode, PolicyMode::Allowlist);
        assert_eq!(http.mode, PolicyMode::Deny);
    }

    #[test]
    fn toml_policy_structured() {
        let toml = r#"
[policy.filesystem]
mode = "allowlist"
allow = ["/tmp/**"]
deny = ["**/.ssh/**"]

[policy.http]
mode = "allowlist"
allow = [{ host = "api.openai.com", scheme = "https" }]
"#;
        let cfg: ConfigFile = toml::from_str(toml).unwrap();
        let fs = resolve_fs_config(&cfg, None, &CliPolicyOverrides::default()).unwrap();
        assert_eq!(fs.mode, PolicyMode::Allowlist);
        assert_eq!(fs.allow, vec!["/tmp/**"]);
        assert_eq!(fs.deny, vec!["**/.ssh/**"]);
        let http = resolve_http_config(&cfg, None, &CliPolicyOverrides::default()).unwrap();
        assert_eq!(http.mode, PolicyMode::Allowlist);
        assert_eq!(http.allow[0].net.host.as_deref(), Some("api.openai.com"));
        assert_eq!(http.allow[0].scheme.as_deref(), Some("https"));
    }

    #[test]
    fn cli_overrides_config_file() {
        let toml = r#"
[policy]
filesystem = "deny"
"#;
        let cfg: ConfigFile = toml::from_str(toml).unwrap();
        let cli = CliPolicyOverrides {
            fs_allow: vec!["/tmp/work".into()],
            ..Default::default()
        };
        let fs = resolve_fs_config(&cfg, None, &cli).unwrap();
        assert_eq!(fs.mode, PolicyMode::Allowlist);
        assert_eq!(fs.allow, vec!["/tmp/work"]);
    }

    #[test]
    fn sockets_cli_allow_host_port() {
        let cli = CliPolicyOverrides {
            sockets_allow: vec!["vnc.example.com:5900/tcp".into()],
            ..Default::default()
        };
        let cfg = resolve_sockets_config(&ConfigFile::default(), None, &cli).unwrap();
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
        let cli = CliPolicyOverrides {
            sockets_allow: vec!["10.0.0.0/8:80,443".into()],
            ..Default::default()
        };
        let cfg = resolve_sockets_config(&ConfigFile::default(), None, &cli).unwrap();
        assert_eq!(cfg.allow[0].net.cidr.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(cfg.allow[0].net.host, None);
        assert_eq!(cfg.allow[0].net.ports.as_deref(), Some(&[80u16, 443][..]));
        assert!(cfg.allow[0].protocols.is_none());
    }

    #[test]
    fn sockets_toml_structured() {
        let toml = r#"
[policy.sockets]
mode = "allowlist"
allow = [{ host = "vnc.example.com", ports = [5900], protocols = ["tcp"] }]
deny = [{ cidr = "127.0.0.0/8", except-ports = [5900] }]
"#;
        let cfg: ConfigFile = toml::from_str(toml).unwrap();
        let s = resolve_sockets_config(&cfg, None, &CliPolicyOverrides::default()).unwrap();
        assert_eq!(s.mode, PolicyMode::Allowlist);
        assert_eq!(s.allow[0].net.host.as_deref(), Some("vnc.example.com"));
        assert_eq!(s.deny[0].net.except_ports.as_deref(), Some(&[5900u16][..]));
    }

    #[test]
    fn sockets_spec_rejects_missing_port() {
        let r = parse_socket_spec("vnc.example.com");
        assert!(r.is_err(), "spec without port must be rejected");
    }

    #[test]
    fn sockets_spec_rejects_bad_protocol() {
        let r = parse_socket_spec("host:80/sctp");
        assert!(r.is_err(), "unknown protocol must be rejected");
    }
}
