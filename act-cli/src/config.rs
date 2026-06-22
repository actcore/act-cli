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

// ── Re-export policy types from act-policy ──
#[cfg(test)]
pub use act_policy::grant::FsAllow;
pub use act_policy::grant::{CapabilityGrant, GrantPolicy, HttpConfig, PolicyMode};

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
    /// Returns the explicit default (None if unset) and per-id entries for
    /// layer-aware merging. Only a `Some` default should override the lower layer.
    fn layer(&self) -> anyhow::Result<(Option<PolicyMode>, BTreeMap<String, CapabilityGrant>)> {
        let default = self.default.as_deref().map(PolicyMode::parse).transpose()?;
        let mut entries = BTreeMap::new();
        for (id, g) in &self.entries {
            entries.insert(id.clone(), g.to_grant()?);
        }
        Ok((default, entries))
    }

    /// Materializes a `GrantPolicy` treating an absent `default` as Deny.
    /// Used in tests for single-layer assertions.
    #[cfg(test)]
    fn to_grant_policy(&self) -> anyhow::Result<GrantPolicy> {
        let (default, entries) = self.layer()?;
        Ok(GrantPolicy {
            default: default.unwrap_or(PolicyMode::Deny),
            entries,
        })
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
    pub fn is_empty(&self) -> bool {
        self.grant_json.is_empty() && self.allow_ids.is_empty() && self.deny_ids.is_empty()
    }

    /// Returns `(None, entries)`: CLI grants never set a global default; the
    /// lower layer's default is always inherited.
    fn layer(&self) -> anyhow::Result<(Option<PolicyMode>, BTreeMap<String, CapabilityGrant>)> {
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
        Ok((None, entries))
    }
}

/// Build the effective grant policy: global [policy] < profile [policy] < CLI grants.
///
/// Each layer's `default` is inherited from the layer below when not explicitly
/// set. Only an explicitly present `default` key overrides the accumulated value.
pub fn build_grant_policy(
    config: &ConfigFile,
    profile: Option<&ProfileConfig>,
    cli: &CliGrants,
) -> anyhow::Result<GrantPolicy> {
    let mut gp = GrantPolicy::default(); // default = Ask, empty entries

    // Helper: apply one layer onto gp — only update default when Some.
    let mut apply = |def: Option<PolicyMode>, entries: BTreeMap<String, CapabilityGrant>| {
        if let Some(d) = def {
            gp.default = d;
        }
        for (k, v) in entries {
            gp.entries.insert(k, v);
        }
    };

    if let Some(p) = &config.policy {
        let (d, e) = p.layer()?;
        apply(d, e);
    }
    if let Some(prof) = profile
        && let Some(p) = &prof.policy
    {
        let (d, e) = p.layer()?;
        apply(d, e);
    }
    if !cli.is_empty() {
        let (d, e) = cli.layer()?;
        apply(d, e); // d is always None for CLI
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
    use act_policy::grant::{to_fs_config, to_http_config, to_sockets_config};

    #[test]
    fn policy_mode_parse() {
        assert_eq!(PolicyMode::parse("deny").unwrap(), PolicyMode::Deny);
        assert_eq!(
            PolicyMode::parse("allowlist").unwrap(),
            PolicyMode::Allowlist
        );
        assert_eq!(PolicyMode::parse("open").unwrap(), PolicyMode::Open);
        assert_eq!(PolicyMode::parse("ask").unwrap(), PolicyMode::Ask);
        assert!(PolicyMode::parse("bogus").is_err());
    }

    #[test]
    fn parse_error_lists_ask() {
        let err = PolicyMode::parse("bogus").unwrap_err().to_string();
        assert!(err.contains("ask"), "error should list 'ask': {err}");
    }

    #[test]
    fn grant_policy_default_resolves_to_ask() {
        // With no `[policy]` / profile / CLI grant, the global default is
        // ask-by-default: an undeclared capability id resolves to `Ask`
        // (interactive runs prompt; headless degrades to deny).
        let gp = build_grant_policy(&ConfigFile::default(), None, &CliGrants::default()).unwrap();
        assert_eq!(gp.default, PolicyMode::Ask);
        assert_eq!(gp.resolve("wasi:filesystem").mode, PolicyMode::Ask);
        assert_eq!(gp.resolve("some:undeclared").mode, PolicyMode::Ask);
        // The to_*_config mappers carry the ask mode through.
        assert_eq!(to_fs_config(&gp).unwrap().mode, PolicyMode::Ask);
        assert_eq!(to_http_config(&gp).unwrap().mode, PolicyMode::Ask);
        assert_eq!(to_sockets_config(&gp).unwrap().mode, PolicyMode::Ask);
    }

    #[test]
    fn explicit_default_overrides_ask() {
        // An explicit `[policy] default = "deny"` still wins over ask-default.
        let toml_input = r#"
[policy]
default = "deny"
"#;
        let cfg: ConfigFile = toml::from_str(toml_input).unwrap();
        let gp = build_grant_policy(&cfg, None, &CliGrants::default()).unwrap();
        assert_eq!(gp.default, PolicyMode::Deny);
        assert_eq!(gp.resolve("some:undeclared").mode, PolicyMode::Deny);
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
        assert_eq!(
            fs.allow,
            vec![FsAllow {
                glob: "/data/**".into(),
                mode: act_types::FsMode::Rw
            }]
        );
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
        assert_eq!(
            fs.allow,
            vec![FsAllow {
                glob: "/tmp/**".into(),
                mode: act_types::FsMode::Rw
            }]
        );
    }

    #[test]
    fn toml_policy_structured() {
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
        assert_eq!(
            fs.allow,
            vec![FsAllow {
                glob: "/tmp/**".into(),
                mode: act_types::FsMode::Rw
            }]
        );
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
        assert_eq!(
            fs.allow,
            vec![FsAllow {
                glob: "/tmp/work".into(),
                mode: act_types::FsMode::Rw
            }]
        );
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
    fn profile_layering_inherits_global_default_and_overrides_per_id() {
        let toml_input = r#"
[policy]
default = "allowlist"
"wasi:http" = "open"

[profile.p.policy]
"wasi:http" = "deny"
"#;
        let cfg: ConfigFile = toml::from_str(toml_input).expect("parses");
        let prof = cfg.profile.get("p");
        let gp = build_grant_policy(&cfg, prof, &CliGrants::default()).unwrap();
        // profile overrides wasi:http -> deny
        assert_eq!(gp.resolve("wasi:http").mode, PolicyMode::Deny);
        // profile omits `default` -> inherits global default (allowlist), NOT reset to Deny
        assert_eq!(gp.resolve("something:else").mode, PolicyMode::Allowlist);
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
