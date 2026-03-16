use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ── Public types ──

/// A single guest←host directory mapping.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub struct DirMount {
    pub guest: String,
    pub host: PathBuf,
}

/// Resolved filesystem configuration for a component invocation.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct FsConfig {
    pub mounts: Vec<DirMount>,
}

#[allow(dead_code)]
impl FsConfig {
    /// No filesystem access (default).
    pub fn none() -> Self {
        Self { mounts: vec![] }
    }

    /// Full filesystem: host `/` mapped to guest `/`.
    pub fn full() -> Self {
        Self {
            mounts: vec![DirMount {
                guest: "/".to_string(),
                host: PathBuf::from("/"),
            }],
        }
    }
}

// ── TOML deserialization types ──

#[derive(Debug, Clone, Deserialize, Default)]
#[allow(dead_code)]
pub struct ConfigFile {
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(rename = "log-level", default)]
    pub log_level: Option<String>,
    #[serde(default)]
    pub policy: Option<PolicyConfig>,
    #[serde(default)]
    pub profile: HashMap<String, ProfileConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[allow(dead_code)]
pub struct PolicyConfig {
    #[serde(default)]
    pub filesystem: Option<FilesystemPolicy>,
    #[serde(default)]
    pub network: Option<bool>,
}

/// Filesystem policy — either a simple string ("none"/"full") or a structured object.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
#[allow(dead_code)]
pub enum FilesystemPolicy {
    Simple(String),
    Structured(StructuredFsPolicy),
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[allow(dead_code)]
pub struct StructuredFsPolicy {
    pub mode: String,
    #[serde(rename = "allow-dir", default)]
    pub allow_dir: Vec<DirMapping>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[allow(dead_code)]
pub struct DirMapping {
    pub guest: String,
    pub host: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[allow(dead_code)]
pub struct ProfileConfig {
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub policy: Option<PolicyConfig>,
}

// ── Loading ──

/// Default config file path: `~/.config/act/config.toml`.
#[allow(dead_code)]
pub fn default_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("act").join("config.toml"))
}

/// Load and parse a TOML config file. Returns `ConfigFile::default()` if the file doesn't exist.
#[allow(dead_code)]
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
#[allow(dead_code)]
pub fn get_profile<'a>(config: &'a ConfigFile, name: &str) -> Result<&'a ProfileConfig> {
    config
        .profile
        .get(name)
        .with_context(|| format!("profile '{}' not found in config", name))
}

/// Expand `~` in a path string to the user's home directory.
#[allow(dead_code)]
fn expand_path(s: &str) -> PathBuf {
    let expanded = shellexpand::tilde(s);
    PathBuf::from(expanded.as_ref())
}

// ── Resolution ──

/// Resolve the final `FsConfig` from a filesystem policy.
#[allow(dead_code)]
fn resolve_fs_policy(policy: &FilesystemPolicy) -> Result<FsConfig> {
    match policy {
        FilesystemPolicy::Simple(s) => match s.as_str() {
            "none" => Ok(FsConfig::none()),
            "full" => Ok(FsConfig::full()),
            other => anyhow::bail!("unknown filesystem policy: '{}'", other),
        },
        FilesystemPolicy::Structured(s) => {
            if s.mode != "directory" {
                anyhow::bail!("unknown filesystem mode: '{}'", s.mode);
            }
            let mounts = s
                .allow_dir
                .iter()
                .map(|d| DirMount {
                    guest: d.guest.clone(),
                    host: expand_path(&d.host),
                })
                .collect();
            Ok(FsConfig { mounts })
        }
    }
}

/// CLI-provided filesystem overrides.
#[allow(dead_code)]
pub struct CliOverrides {
    pub allow_fs: bool,
    pub allow_dir: Vec<String>,
}

/// Resolve the final `FsConfig` from config file + profile + CLI overrides.
///
/// Resolution order: CLI flags > profile > config defaults.
#[allow(dead_code)]
pub fn resolve_fs_config(
    config: &ConfigFile,
    profile: Option<&ProfileConfig>,
    cli: &CliOverrides,
) -> Result<FsConfig> {
    // CLI flags take highest priority
    if cli.allow_fs {
        return Ok(FsConfig::full());
    }
    if !cli.allow_dir.is_empty() {
        let mounts = cli
            .allow_dir
            .iter()
            .map(|s| parse_allow_dir(s))
            .collect::<Result<Vec<_>>>()?;
        return Ok(FsConfig { mounts });
    }

    // Profile policy
    if let Some(profile) = profile
        && let Some(ref policy) = profile.policy
        && let Some(ref fs) = policy.filesystem
    {
        return resolve_fs_policy(fs);
    }

    // Config defaults
    if let Some(ref policy) = config.policy
        && let Some(ref fs) = policy.filesystem
    {
        return resolve_fs_policy(fs);
    }

    Ok(FsConfig::none())
}

/// Resolve the merged metadata from profile + CLI.
/// CLI metadata takes precedence over profile metadata.
#[allow(dead_code)]
pub fn resolve_metadata(
    profile: Option<&ProfileConfig>,
    cli_metadata: Option<&serde_json::Value>,
) -> serde_json::Value {
    let mut merged = serde_json::Map::new();

    // Profile metadata (lower priority)
    if let Some(profile) = profile
        && let Some(serde_json::Value::Object(m)) = &profile.metadata
    {
        merged.extend(m.clone());
    }

    // CLI metadata (higher priority, overwrites)
    if let Some(serde_json::Value::Object(m)) = cli_metadata {
        merged.extend(m.clone());
    }

    if merged.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::Object(merged)
    }
}

/// Adjust guest paths in FsConfig based on the component's `std:fs:mount-root`.
/// All guest paths become `{mount_root}/{guest}`.
#[allow(dead_code)]
pub fn apply_mount_root(fs_config: &mut FsConfig, mount_root: &str) {
    if mount_root == "/" || mount_root.is_empty() {
        return;
    }
    let root = mount_root.trim_end_matches('/');
    for mount in &mut fs_config.mounts {
        if mount.guest == "/" {
            mount.guest = root.to_string();
        } else {
            let guest = mount.guest.trim_start_matches('/');
            mount.guest = format!("{}/{}", root, guest);
        }
    }
}

/// Parse `--allow-dir guest:host` flag value.
#[allow(dead_code)]
fn parse_allow_dir(s: &str) -> Result<DirMount> {
    let (guest, host) = s
        .split_once(':')
        .with_context(|| format!("invalid --allow-dir format '{}', expected guest:host", s))?;
    Ok(DirMount {
        guest: guest.to_string(),
        host: expand_path(host),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_allow_dir ──

    #[test]
    fn parse_allow_dir_valid() {
        let m = parse_allow_dir("data:/real/data").unwrap();
        assert_eq!(m.guest, "data");
        assert_eq!(m.host, PathBuf::from("/real/data"));
    }

    #[test]
    fn parse_allow_dir_root() {
        let m = parse_allow_dir("/:/").unwrap();
        assert_eq!(m.guest, "/");
        assert_eq!(m.host, PathBuf::from("/"));
    }

    #[test]
    fn parse_allow_dir_no_colon() {
        assert!(parse_allow_dir("nohost").is_err());
    }

    #[test]
    fn parse_allow_dir_tilde_expansion() {
        let m = parse_allow_dir("data:~/mydir").unwrap();
        assert_eq!(m.guest, "data");
        // ~ should be expanded; at minimum it should not start with ~
        assert!(!m.host.starts_with("~"));
    }

    // ── FsConfig constructors ──

    #[test]
    fn fs_config_none_has_no_mounts() {
        assert!(FsConfig::none().mounts.is_empty());
    }

    #[test]
    fn fs_config_full_maps_root() {
        let fs = FsConfig::full();
        assert_eq!(fs.mounts.len(), 1);
        assert_eq!(fs.mounts[0].guest, "/");
        assert_eq!(fs.mounts[0].host, PathBuf::from("/"));
    }

    // ── TOML parsing ──

    #[test]
    fn parse_minimal_config() {
        let toml_str = r#"
listen = "[::1]:4000"
"#;
        let config: ConfigFile = toml::from_str(toml_str).unwrap();
        assert_eq!(config.listen.as_deref(), Some("[::1]:4000"));
        assert!(config.profile.is_empty());
    }

    #[test]
    fn parse_config_with_simple_policy() {
        let toml_str = r#"
[policy]
filesystem = "none"
network = true
"#;
        let config: ConfigFile = toml::from_str(toml_str).unwrap();
        let policy = config.policy.unwrap();
        assert_eq!(
            policy.filesystem,
            Some(FilesystemPolicy::Simple("none".to_string()))
        );
        assert_eq!(policy.network, Some(true));
    }

    #[test]
    fn parse_config_with_structured_policy() {
        let toml_str = r#"
[profile.sqlite.policy]
filesystem = { mode = "directory", allow-dir = [
  { guest = "/data", host = "/home/user/.local/share/act/sqlite" },
]}
"#;
        let config: ConfigFile = toml::from_str(toml_str).unwrap();
        let profile = config.profile.get("sqlite").unwrap();
        let policy = profile.policy.as_ref().unwrap();
        let fs = policy.filesystem.as_ref().unwrap();
        match fs {
            FilesystemPolicy::Structured(s) => {
                assert_eq!(s.mode, "directory");
                assert_eq!(s.allow_dir.len(), 1);
                assert_eq!(s.allow_dir[0].guest, "/data");
            }
            _ => panic!("expected structured policy"),
        }
    }

    #[test]
    fn parse_structured_policy_tilde_host() {
        let toml_str = r#"
[profile.test.policy]
filesystem = { mode = "directory", allow-dir = [
  { guest = "/data", host = "~/.local/share/act/test" },
]}
"#;
        let config: ConfigFile = toml::from_str(toml_str).unwrap();
        let profile = config.profile.get("test").unwrap();
        let cli = CliOverrides {
            allow_fs: false,
            allow_dir: vec![],
        };
        let fs = resolve_fs_config(&config, Some(profile), &cli).unwrap();
        // Tilde should be expanded
        assert!(!fs.mounts[0].host.starts_with("~"));
    }

    #[test]
    fn parse_full_config() {
        let toml_str = r#"
listen = "[::1]:3000"
log-level = "info"

[policy]
filesystem = "none"
network = true

[profile.sqlite]
metadata = { database_path = "/data/app.db" }

[profile.sqlite.policy]
filesystem = { mode = "directory", allow-dir = [
  { guest = "/data", host = "~/.local/share/act/sqlite" },
]}

[profile.filesystem]
policy.filesystem = "full"
"#;
        let config: ConfigFile = toml::from_str(toml_str).unwrap();
        assert_eq!(config.listen.as_deref(), Some("[::1]:3000"));
        assert_eq!(config.profile.len(), 2);
        assert!(config.profile.contains_key("sqlite"));
        assert!(config.profile.contains_key("filesystem"));
    }

    #[test]
    fn parse_profile_metadata() {
        let toml_str = r#"
[profile.sqlite]
metadata = { database_path = "/data/app.db", max_connections = 5 }
"#;
        let config: ConfigFile = toml::from_str(toml_str).unwrap();
        let profile = config.profile.get("sqlite").unwrap();
        let meta = profile.metadata.as_ref().unwrap();
        assert_eq!(meta["database_path"], "/data/app.db");
        assert_eq!(meta["max_connections"], 5);
    }

    // ── Resolution ──

    #[test]
    fn resolve_cli_allow_fs_wins() {
        let config = ConfigFile::default();
        let cli = CliOverrides {
            allow_fs: true,
            allow_dir: vec![],
        };
        let fs = resolve_fs_config(&config, None, &cli).unwrap();
        assert_eq!(fs.mounts.len(), 1);
        assert_eq!(fs.mounts[0].guest, "/");
    }

    #[test]
    fn resolve_cli_allow_fs_wins_over_allow_dir() {
        let config = ConfigFile::default();
        let cli = CliOverrides {
            allow_fs: true,
            allow_dir: vec!["data:/tmp".to_string()],
        };
        let fs = resolve_fs_config(&config, None, &cli).unwrap();
        // --allow-fs takes priority, ignores --allow-dir
        assert_eq!(fs.mounts.len(), 1);
        assert_eq!(fs.mounts[0].guest, "/");
    }

    #[test]
    fn resolve_cli_allow_dir_wins() {
        let config = ConfigFile::default();
        let cli = CliOverrides {
            allow_fs: false,
            allow_dir: vec!["data:/tmp/data".to_string()],
        };
        let fs = resolve_fs_config(&config, None, &cli).unwrap();
        assert_eq!(fs.mounts.len(), 1);
        assert_eq!(fs.mounts[0].guest, "data");
        assert_eq!(fs.mounts[0].host, PathBuf::from("/tmp/data"));
    }

    #[test]
    fn resolve_profile_over_default() {
        let toml_str = r#"
[policy]
filesystem = "none"

[profile.test.policy]
filesystem = "full"
"#;
        let config: ConfigFile = toml::from_str(toml_str).unwrap();
        let profile = config.profile.get("test").unwrap();
        let cli = CliOverrides {
            allow_fs: false,
            allow_dir: vec![],
        };
        let fs = resolve_fs_config(&config, Some(profile), &cli).unwrap();
        assert_eq!(fs.mounts.len(), 1);
        assert_eq!(fs.mounts[0].guest, "/");
    }

    #[test]
    fn resolve_falls_back_to_default() {
        let toml_str = r#"
[policy]
filesystem = "full"
"#;
        let config: ConfigFile = toml::from_str(toml_str).unwrap();
        let cli = CliOverrides {
            allow_fs: false,
            allow_dir: vec![],
        };
        let fs = resolve_fs_config(&config, None, &cli).unwrap();
        assert_eq!(fs.mounts.len(), 1);
    }

    #[test]
    fn resolve_no_config_no_cli_is_none() {
        let config = ConfigFile::default();
        let cli = CliOverrides {
            allow_fs: false,
            allow_dir: vec![],
        };
        let fs = resolve_fs_config(&config, None, &cli).unwrap();
        assert!(fs.mounts.is_empty());
    }

    // ── Metadata resolution ──

    #[test]
    fn resolve_metadata_cli_wins() {
        let profile = ProfileConfig {
            metadata: Some(serde_json::json!({"key": "from_profile", "extra": 1})),
            policy: None,
        };
        let cli_meta = serde_json::json!({"key": "from_cli"});
        let merged = resolve_metadata(Some(&profile), Some(&cli_meta));
        assert_eq!(merged["key"], "from_cli");
        assert_eq!(merged["extra"], 1);
    }

    #[test]
    fn resolve_metadata_profile_only() {
        let profile = ProfileConfig {
            metadata: Some(serde_json::json!({"db": "/data/app.db"})),
            policy: None,
        };
        let merged = resolve_metadata(Some(&profile), None);
        assert_eq!(merged["db"], "/data/app.db");
    }

    #[test]
    fn resolve_metadata_none() {
        let merged = resolve_metadata(None, None);
        assert!(merged.is_null());
    }

    // ── apply_mount_root ──

    #[test]
    fn apply_mount_root_default_noop() {
        let mut fs = FsConfig {
            mounts: vec![DirMount {
                guest: "/data".to_string(),
                host: PathBuf::from("/tmp"),
            }],
        };
        apply_mount_root(&mut fs, "/");
        assert_eq!(fs.mounts[0].guest, "/data");
    }

    #[test]
    fn apply_mount_root_empty_noop() {
        let mut fs = FsConfig {
            mounts: vec![DirMount {
                guest: "/data".to_string(),
                host: PathBuf::from("/tmp"),
            }],
        };
        apply_mount_root(&mut fs, "");
        assert_eq!(fs.mounts[0].guest, "/data");
    }

    #[test]
    fn apply_mount_root_custom() {
        let mut fs = FsConfig {
            mounts: vec![DirMount {
                guest: "data".to_string(),
                host: PathBuf::from("/tmp"),
            }],
        };
        apply_mount_root(&mut fs, "/workspace");
        assert_eq!(fs.mounts[0].guest, "/workspace/data");
    }

    #[test]
    fn apply_mount_root_full_fs() {
        let mut fs = FsConfig::full();
        apply_mount_root(&mut fs, "/app");
        assert_eq!(fs.mounts[0].guest, "/app");
    }

    // ── load_config ──

    #[test]
    fn load_config_missing_explicit_path_errors() {
        assert!(load_config(Some(Path::new("/nonexistent/config.toml"))).is_err());
    }

    #[test]
    fn load_config_no_path_returns_default() {
        // When no path given and default doesn't exist, returns empty config
        let config = load_config(None).unwrap();
        assert!(config.listen.is_none());
        assert!(config.profile.is_empty());
    }
}
