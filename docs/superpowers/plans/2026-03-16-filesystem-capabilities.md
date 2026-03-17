# Filesystem Capabilities Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow act-cli to grant filesystem access to WASM components with different isolation levels, controlled via CLI flags and a TOML configuration file.

**Architecture:** New `config.rs` module handles TOML config file parsing and profile resolution. New `FsConfig` struct with mount list flows from CLI/config into `create_store()`, which calls `WasiCtxBuilder::preopened_dir()` for each mount. CLI flags (`--allow-dir`, `--allow-fs`, `--profile`, `--config`) added to all subcommands via a shared `CommonOpts` struct. Resolution order: CLI flags > profile > config defaults.

**Tech Stack:** `toml` crate for config parsing, `wasmtime_wasi::WasiCtxBuilder::preopened_dir` for filesystem mounts, `dirs` crate for `~/.config/act/` resolution, `shellexpand` for tilde expansion in paths.

**Spec:** `docs/specs/2026-03-16-filesystem-capabilities.md`

**Scope note:** `config.listen` and `config.log_level` are parsed into the config struct for forward compatibility but are NOT wired up in this plan. They will be applied in a follow-up.

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `Cargo.toml` | Modify | Add `toml`, `dirs`, `shellexpand` dependencies |
| `../act-sdk-rs/act-types/src/constants.rs` | Modify | Add `COMPONENT_FS_MOUNT_ROOT` and capability identifier constants |
| `../act-sdk-rs/act-types/src/types.rs` | Modify | Add `Metadata::extend()` method |
| `src/config.rs` | Create | Config file structs, TOML parsing, profile merging, `FsConfig` resolution |
| `src/runtime.rs` | Modify | `create_store()` accepts `&FsConfig`, calls `preopened_dir()` for each mount; `warn_missing_capabilities()` |
| `src/main.rs` | Modify | `CommonOpts` struct with shared flags, config loading orchestration, plumb `FsConfig` through all subcommands |
| `src/http.rs` | Modify | `AppState` holds resolved metadata (profile + CLI merged), handlers merge it with request metadata |
| `src/mcp.rs` | No change | Already receives metadata from caller |

---

## Chunk 1: Dependencies and act-types Changes

### Task 1: Add dependencies to act-cli

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add toml, dirs, shellexpand to Cargo.toml**

Add under `[dependencies]`:
```toml
toml = "0.8"
dirs = "6"
shellexpand = "3"
```

- [ ] **Step 2: Verify it compiles**

Run: `cd /mnt/devenv/workspace/act/act-cli && cargo check`
Expected: compiles without errors

- [ ] **Step 3: Commit**

```bash
cd /mnt/devenv/workspace/act/act-cli
git add Cargo.toml Cargo.lock
git commit -m "feat: add toml, dirs, shellexpand dependencies for config file support"
```

---

### Task 2: Add constants and `Metadata::extend` to act-types

**Files:**
- Modify: `../act-sdk-rs/act-types/src/constants.rs`
- Modify: `../act-sdk-rs/act-types/src/types.rs`
- Modify: `Cargo.toml` (switch `act-types` to path dependency)

**Note:** `act-types` is currently a crates.io dependency (`"0.2.2"`). We add new symbols to the local source, so `act-cli/Cargo.toml` must switch to a path dependency during development. Before releasing act-cli, publish a new `act-types` version and switch back.

- [ ] **Step 0: Switch act-types to path dependency**

In `Cargo.toml`, change:
```toml
act-types = "0.2.2"
```
To:
```toml
act-types = { path = "../act-sdk-rs/act-types" }
```

- [ ] **Step 1: Add filesystem and capability constants**

In `../act-sdk-rs/act-types/src/constants.rs`, add after the `COMPONENT_SKILL` line:

```rust
pub const COMPONENT_FS_MOUNT_ROOT: &str = "std:fs:mount-root";

// ── Capability identifiers ──

pub const CAP_FILESYSTEM: &str = "wasi:filesystem";
pub const CAP_SOCKETS: &str = "wasi:sockets";
pub const CAP_HTTP: &str = "wasi:http";
```

- [ ] **Step 2: Add `extend` method to `Metadata`**

In `../act-sdk-rs/act-types/src/types.rs`, inside the `impl Metadata` block, after the `len()` method (line ~157), add:

```rust
    /// Merge all entries from `other` into `self`. Entries in `other` overwrite existing keys.
    pub fn extend(&mut self, other: Metadata) {
        self.0.extend(other.0);
    }
```

- [ ] **Step 3: Verify act-types compiles and tests pass**

Run: `cd /mnt/devenv/workspace/act/act-sdk-rs && cargo test --target x86_64-unknown-linux-gnu -p act-types`
Expected: compiles and all tests pass

- [ ] **Step 4: Commit**

```bash
cd /mnt/devenv/workspace/act/act-sdk-rs
git add act-types/src/constants.rs act-types/src/types.rs
git commit -m "feat: add filesystem constants, capability IDs, and Metadata::extend"
```

Also commit the path dependency change in act-cli:
```bash
cd /mnt/devenv/workspace/act/act-cli
git add Cargo.toml Cargo.lock
git commit -m "chore: switch act-types to path dependency for development"
```

---

## Chunk 2: Config Module

### Task 3: Write config module with tests

**Files:**
- Create: `src/config.rs`
- Modify: `src/main.rs` (add `mod config;`)

- [ ] **Step 1: Create `src/config.rs` with types, parsing, resolution, and tests**

```rust
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ── Public types ──

/// A single guest←host directory mapping.
#[derive(Debug, Clone, PartialEq)]
pub struct DirMount {
    pub guest: String,
    pub host: PathBuf,
}

/// Resolved filesystem configuration for a component invocation.
#[derive(Debug, Clone, Default)]
pub struct FsConfig {
    pub mounts: Vec<DirMount>,
}

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
pub struct PolicyConfig {
    #[serde(default)]
    pub filesystem: Option<FilesystemPolicy>,
    #[serde(default)]
    pub network: Option<bool>,
}

/// Filesystem policy — either a simple string ("none"/"full") or a structured object.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum FilesystemPolicy {
    Simple(String),
    Structured(StructuredFsPolicy),
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct StructuredFsPolicy {
    pub mode: String,
    #[serde(rename = "allow-dir", default)]
    pub allow_dir: Vec<DirMapping>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct DirMapping {
    pub guest: String,
    pub host: String,
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

/// Expand `~` in a path string to the user's home directory.
fn expand_path(s: &str) -> PathBuf {
    let expanded = shellexpand::tilde(s);
    PathBuf::from(expanded.as_ref())
}

// ── Resolution ──

/// Resolve the final `FsConfig` from a filesystem policy.
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
pub struct CliOverrides {
    pub allow_fs: bool,
    pub allow_dir: Vec<String>,
}

/// Resolve the final `FsConfig` from config file + profile + CLI overrides.
///
/// Resolution order: CLI flags > profile > config defaults.
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
    if let Some(profile) = profile {
        if let Some(ref policy) = profile.policy {
            if let Some(ref fs) = policy.filesystem {
                return resolve_fs_policy(fs);
            }
        }
    }

    // Config defaults
    if let Some(ref policy) = config.policy {
        if let Some(ref fs) = policy.filesystem {
            return resolve_fs_policy(fs);
        }
    }

    Ok(FsConfig::none())
}

/// Resolve the merged metadata from profile + CLI.
/// CLI metadata takes precedence over profile metadata.
pub fn resolve_metadata(
    profile: Option<&ProfileConfig>,
    cli_metadata: Option<&serde_json::Value>,
) -> serde_json::Value {
    let mut merged = serde_json::Map::new();

    // Profile metadata (lower priority)
    if let Some(profile) = profile {
        if let Some(serde_json::Value::Object(m)) = &profile.metadata {
            merged.extend(m.clone());
        }
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
```

- [ ] **Step 2: Add `mod config;` to `main.rs`**

At the top of `src/main.rs`, change:
```rust
mod http;
mod mcp;
mod runtime;
```
To:
```rust
mod config;
mod http;
mod mcp;
mod runtime;
```

- [ ] **Step 3: Run tests**

Run: `cd /mnt/devenv/workspace/act/act-cli && cargo test config::tests`
Expected: all tests pass

- [ ] **Step 4: Commit**

```bash
cd /mnt/devenv/workspace/act/act-cli
git add src/config.rs src/main.rs
git commit -m "feat: add config module with TOML parsing, profile merging, and filesystem resolution"
```

---

## Chunk 3: Runtime, CLI, and HTTP Integration (Atomic)

This chunk modifies `runtime.rs`, `main.rs`, and `http.rs` together in a single commit so the codebase is never left in a non-compiling state.

### Task 4: Modify runtime.rs — create_store with FsConfig + capability warning

**Files:**
- Modify: `src/runtime.rs`

- [ ] **Step 1: Add `use anyhow::Context;` import if missing**

Check the imports at the top of `runtime.rs`. If `anyhow::Context` is not imported, add it to the existing `use anyhow::Result;`:
```rust
use anyhow::{Context, Result};
```

- [ ] **Step 2: Update `create_store` to accept `FsConfig`**

Replace the `create_store` function (lines 88-97):

```rust
/// Create a new store with WASI context and optional filesystem mounts.
pub fn create_store(engine: &Engine, fs_config: &crate::config::FsConfig) -> Result<Store<HostState>> {
    let mut builder = WasiCtxBuilder::new();
    for mount in &fs_config.mounts {
        builder.preopened_dir(
            &mount.host,
            &mount.guest,
            wasmtime_wasi::DirPerms::all(),
            wasmtime_wasi::FilePerms::all(),
        ).with_context(|| format!(
            "failed to preopen host dir '{}' as guest '{}'",
            mount.host.display(),
            mount.guest
        ))?;
    }
    let wasi = builder.build();
    let state = HostState {
        wasi,
        table: ResourceTable::new(),
        http_p2: WasiHttpCtx::new(),
        http_p3: DefaultWasiHttpCtx,
    };
    Ok(Store::new(engine, state))
}
```

- [ ] **Step 3: Update `instantiate_component` to accept `FsConfig`**

Change signature and body:

```rust
pub async fn instantiate_component(
    engine: &Engine,
    component: &Component,
    linker: &Linker<HostState>,
    fs_config: &crate::config::FsConfig,
) -> Result<(ActWorld, Store<HostState>)> {
    let mut store = create_store(engine, fs_config)?;
    let instance = ActWorld::instantiate_async(&mut store, component, linker)
        .await
        .map_err(|e| anyhow::anyhow!("failed to instantiate component: {e}"))?;

    Ok((instance, store))
}
```

- [ ] **Step 4: Add `warn_missing_capabilities` function**

Add after `read_component_info`:

```rust
/// Log a warning if the component declares `wasi:filesystem` capability but no filesystem is granted.
pub fn warn_missing_capabilities(info: &ComponentInfo, fs_config: &crate::config::FsConfig) {
    let wants_fs = info
        .capabilities
        .iter()
        .any(|c| c.id == act_types::constants::CAP_FILESYSTEM);
    if wants_fs && fs_config.mounts.is_empty() {
        tracing::warn!(
            component = %info.name,
            "component declares wasi:filesystem capability but no filesystem access was granted"
        );
    }
}
```

**Do NOT commit yet — the codebase won't compile until main.rs and http.rs are updated.**

---

### Task 5: Update main.rs — CommonOpts, resolve_opts, all subcommands

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Replace the `Cli` enum with `CommonOpts` + updated variants**

Replace everything from the `use` block through the `Cli` enum (lines 1-76) with:

```rust
mod config;
mod http;
mod mcp;
mod runtime;

use act_types::cbor;

use anyhow::{Context, Result};
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

/// Shared options for subcommands that instantiate components.
#[derive(clap::Args, Clone, Debug)]
struct CommonOpts {
    /// JSON metadata to pass to the component
    #[arg(short, long)]
    metadata: Option<String>,

    /// Path to a JSON metadata file
    #[arg(long)]
    metadata_file: Option<PathBuf>,

    /// Map a host directory to a guest path (guest:host). Repeatable.
    #[arg(long = "allow-dir")]
    allow_dir: Vec<String>,

    /// Grant full filesystem access (host / → guest /)
    #[arg(long = "allow-fs")]
    allow_fs: bool,

    /// Use a named profile from the config file
    #[arg(long)]
    profile: Option<String>,

    /// Override config file location
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Parser)]
#[command(name = "act", about = "ACT — Agent Component Tools CLI")]
enum Cli {
    /// Load a .wasm component and serve it as an ACT-HTTP server
    Serve {
        /// Path to the .wasm component file
        component: PathBuf,

        /// Address to listen on (host:port)
        #[arg(short, long, default_value = "[::1]:3000")]
        listen: SocketAddr,

        #[command(flatten)]
        opts: CommonOpts,
    },
    /// Call a tool directly and print the result
    Call {
        /// Path to the .wasm component file
        component: PathBuf,

        /// Tool name to call
        tool: String,

        /// JSON arguments
        #[arg(long, default_value = "{}")]
        args: String,

        #[command(flatten)]
        opts: CommonOpts,
    },
    /// Load a .wasm component and serve it as an MCP server over stdio
    Mcp {
        /// Path to the .wasm component file
        component: PathBuf,

        #[command(flatten)]
        opts: CommonOpts,
    },
    /// Show component info (name, version, description, capabilities)
    Info {
        /// Path to the .wasm component file
        component: PathBuf,
    },
    /// List tools exposed by a component
    Tools {
        /// Path to the .wasm component file
        component: PathBuf,

        #[command(flatten)]
        opts: CommonOpts,
    },
}
```

- [ ] **Step 2: Update `main()` match arms**

```rust
match cli {
    Cli::Serve {
        component,
        listen,
        opts,
    } => serve(component, listen, opts).await,
    Cli::Call {
        component,
        tool,
        args,
        opts,
    } => cli_call_tool(component, tool, args, opts).await,
    Cli::Mcp { component, opts } => mcp_serve(component, opts).await,
    Cli::Info { component } => cli_info(component).await,
    Cli::Tools { component, opts } => cli_tools(component, opts).await,
}
```

- [ ] **Step 3: Add `resolve_opts` helper after `parse_cli_metadata`**

```rust
/// Resolve config file, profile, filesystem, and metadata from CommonOpts.
fn resolve_opts(
    opts: &CommonOpts,
) -> Result<(config::FsConfig, Option<serde_json::Value>)> {
    let config_file = config::load_config(opts.config.as_deref())?;

    let profile = match &opts.profile {
        Some(name) => Some(config::get_profile(&config_file, name)?),
        None => None,
    };

    let cli_overrides = config::CliOverrides {
        allow_fs: opts.allow_fs,
        allow_dir: opts.allow_dir.clone(),
    };

    let fs_config = config::resolve_fs_config(&config_file, profile, &cli_overrides)?;

    let cli_metadata = parse_cli_metadata(opts.metadata.clone(), opts.metadata_file.clone())?;
    let merged_metadata = config::resolve_metadata(profile, cli_metadata.as_ref());

    let metadata = if merged_metadata.is_null() {
        None
    } else {
        Some(merged_metadata)
    };

    Ok((fs_config, metadata))
}
```

- [ ] **Step 4: Replace all subcommand functions**

Replace `cli_call_tool`:
```rust
async fn cli_call_tool(
    component_path: PathBuf,
    tool: String,
    args: String,
    opts: CommonOpts,
) -> Result<()> {
    let (mut fs_config, metadata) = resolve_opts(&opts)?;
    let metadata_kv: runtime::Metadata = metadata
        .map(runtime::Metadata::from)
        .unwrap_or_default();

    let arguments: serde_json::Value =
        serde_json::from_str(&args).context("invalid --args JSON")?;
    let cbor_args = cbor::json_to_cbor(&arguments).context("encoding args as CBOR")?;

    let wasm_bytes = std::fs::read(&component_path).context("reading component file")?;
    let component_info = runtime::read_component_info(&wasm_bytes)?;
    let mount_root = component_info
        .metadata
        .get(act_types::constants::COMPONENT_FS_MOUNT_ROOT)
        .and_then(|v| v.as_str())
        .unwrap_or("/");
    config::apply_mount_root(&mut fs_config, mount_root);
    runtime::warn_missing_capabilities(&component_info, &fs_config);

    let engine = runtime::create_engine()?;
    let component = runtime::load_component(&engine, &component_path)?;
    let linker = runtime::create_linker(&engine)?;
    let (instance, store) =
        runtime::instantiate_component(&engine, &component, &linker, &fs_config).await?;

    let component_handle = runtime::spawn_component_actor(instance, store);

    let tool_call = runtime::act::core::types::ToolCall {
        name: tool,
        arguments: cbor_args,
        metadata: metadata_kv.clone().into(),
    };

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::CallTool {
        call: tool_call,
        reply: reply_tx,
    };

    component_handle
        .send(request)
        .await
        .map_err(|_| anyhow::anyhow!("component actor unavailable"))?;

    match reply_rx.await? {
        Ok(result) => {
            for event in &result.events {
                match event {
                    runtime::act::core::types::StreamEvent::Content(part) => {
                        let data = cbor::decode_content_data(&part.data, part.mime_type.as_deref());
                        match data {
                            serde_json::Value::String(s) => println!("{s}"),
                            other => println!("{}", serde_json::to_string_pretty(&other)?),
                        }
                    }
                    runtime::act::core::types::StreamEvent::Error(err) => {
                        let ls = act_types::types::LocalizedString::from(&err.message);
                        anyhow::bail!("{}: {}", err.kind, ls.any_text());
                    }
                }
            }
            Ok(())
        }
        Err(runtime::ComponentError::Tool(te)) => {
            let ls = act_types::types::LocalizedString::from(&te.message);
            anyhow::bail!("{}: {}", te.kind, ls.any_text());
        }
        Err(runtime::ComponentError::Internal(e)) => Err(e),
    }
}
```

Replace `mcp_serve`:
```rust
async fn mcp_serve(component_path: PathBuf, opts: CommonOpts) -> Result<()> {
    let (mut fs_config, metadata) = resolve_opts(&opts)?;
    let metadata_kv: runtime::Metadata = metadata
        .map(runtime::Metadata::from)
        .unwrap_or_default();

    let wasm_bytes = std::fs::read(&component_path).context("reading component file")?;
    let component_info = runtime::read_component_info(&wasm_bytes)?;
    let mount_root = component_info
        .metadata
        .get(act_types::constants::COMPONENT_FS_MOUNT_ROOT)
        .and_then(|v| v.as_str())
        .unwrap_or("/");
    config::apply_mount_root(&mut fs_config, mount_root);
    runtime::warn_missing_capabilities(&component_info, &fs_config);

    let engine = runtime::create_engine()?;
    let component = runtime::load_component(&engine, &component_path)?;
    let linker = runtime::create_linker(&engine)?;
    let (instance, store) =
        runtime::instantiate_component(&engine, &component, &linker, &fs_config).await?;

    tracing::info!(
        name = %component_info.name,
        version = %component_info.version,
        mounts = fs_config.mounts.len(),
        "Loaded component (MCP stdio)"
    );

    let component_handle = runtime::spawn_component_actor(instance, store);

    mcp::run_stdio(component_info, component_handle, metadata_kv).await
}
```

Replace `cli_tools`:
```rust
async fn cli_tools(component_path: PathBuf, opts: CommonOpts) -> Result<()> {
    let (mut fs_config, metadata) = resolve_opts(&opts)?;
    let metadata_kv: runtime::Metadata = metadata
        .map(runtime::Metadata::from)
        .unwrap_or_default();

    let wasm_bytes = std::fs::read(&component_path).context("reading component file")?;
    let component_info = runtime::read_component_info(&wasm_bytes)?;
    let mount_root = component_info
        .metadata
        .get(act_types::constants::COMPONENT_FS_MOUNT_ROOT)
        .and_then(|v| v.as_str())
        .unwrap_or("/");
    config::apply_mount_root(&mut fs_config, mount_root);
    runtime::warn_missing_capabilities(&component_info, &fs_config);

    let engine = runtime::create_engine()?;
    let component = runtime::load_component(&engine, &component_path)?;
    let linker = runtime::create_linker(&engine)?;
    let (instance, store) =
        runtime::instantiate_component(&engine, &component, &linker, &fs_config).await?;

    let component_handle = runtime::spawn_component_actor(instance, store);

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::ListTools {
        metadata: metadata_kv.clone(),
        reply: reply_tx,
    };

    component_handle
        .send(request)
        .await
        .map_err(|_| anyhow::anyhow!("component actor unavailable"))?;

    match reply_rx.await? {
        Ok(list_response) => {
            for td in &list_response.tools {
                let ls = act_types::types::LocalizedString::from(&td.description);
                println!("  {} — {}", td.name, ls.any_text());
            }
        }
        Err(runtime::ComponentError::Tool(te)) => {
            let ls = act_types::types::LocalizedString::from(&te.message);
            anyhow::bail!("{}: {}", te.kind, ls.any_text());
        }
        Err(runtime::ComponentError::Internal(e)) => return Err(e),
    }
    Ok(())
}
```

Replace `serve`:
```rust
async fn serve(component_path: PathBuf, addr: SocketAddr, opts: CommonOpts) -> Result<()> {
    let (mut fs_config, metadata) = resolve_opts(&opts)?;

    let wasm_bytes = std::fs::read(&component_path).context("reading component file")?;
    let component_info = runtime::read_component_info(&wasm_bytes)?;
    let mount_root = component_info
        .metadata
        .get(act_types::constants::COMPONENT_FS_MOUNT_ROOT)
        .and_then(|v| v.as_str())
        .unwrap_or("/");
    config::apply_mount_root(&mut fs_config, mount_root);
    runtime::warn_missing_capabilities(&component_info, &fs_config);

    let engine = runtime::create_engine()?;
    let component = runtime::load_component(&engine, &component_path)?;
    let linker = runtime::create_linker(&engine)?;

    let (instance, store) =
        runtime::instantiate_component(&engine, &component, &linker, &fs_config).await?;

    tracing::info!(
        name = %component_info.name,
        version = %component_info.version,
        mounts = fs_config.mounts.len(),
        "Loaded component"
    );

    let component_handle = runtime::spawn_component_actor(instance, store);

    let resolved_metadata: runtime::Metadata = metadata
        .map(runtime::Metadata::from)
        .unwrap_or_default();

    let state = Arc::new(http::AppState {
        info: component_info,
        component: component_handle,
        metadata: resolved_metadata,
    });

    tracing::info!(%addr, component = %component_path.display(), "ACT host listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, http::create_router(state))
        .await
        .context("server error")?;

    Ok(())
}
```

**Do NOT commit yet — http.rs needs the `metadata` field on `AppState`.**

---

### Task 6: Update http.rs — AppState metadata + handler merging

**Files:**
- Modify: `src/http.rs`

- [ ] **Step 1: Add `metadata` field to `AppState`**

Change:
```rust
pub struct AppState {
    pub info: act_types::ComponentInfo,
    pub component: runtime::ComponentHandle,
}
```

To:
```rust
pub struct AppState {
    pub info: act_types::ComponentInfo,
    pub component: runtime::ComponentHandle,
    pub metadata: Metadata,
}
```

- [ ] **Step 2: Update `post_metadata_schema` to merge base metadata**

Replace the metadata construction block in `post_metadata_schema` (the section that builds the `metadata` variable):

```rust
    let mut metadata = state.metadata.clone();
    if !body_bytes.is_empty() {
        let body: act_http::MetadataSchemaRequest = match serde_json::from_slice(&body_bytes) {
            Ok(b) => b,
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        };
        if let Some(value) = body.metadata {
            metadata.extend(runtime::Metadata::from(value));
        }
    }
```

Replace the full function body from `let metadata =` through the old block:
```rust
async fn post_metadata_schema(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> axum::response::Response {
    let body_bytes = match axum::body::to_bytes(request.into_body(), 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let mut metadata = state.metadata.clone();
    if !body_bytes.is_empty() {
        let body: act_http::MetadataSchemaRequest = match serde_json::from_slice(&body_bytes) {
            Ok(b) => b,
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        };
        if let Some(value) = body.metadata {
            metadata.extend(runtime::Metadata::from(value));
        }
    }

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::GetMetadataSchema {
        metadata,
        reply: reply_tx,
    };

    if state.component.send(request).await.is_err() {
        return internal_error_response("component actor unavailable");
    }

    match reply_rx.await {
        Ok(Ok(Some(schema))) => {
            (StatusCode::OK, [("content-type", MIME_JSON)], schema).into_response()
        }
        Ok(Ok(None)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => component_error_response(e),
        Err(_) => component_error_response(runtime::ComponentError::Internal(anyhow::anyhow!(
            "component actor dropped reply"
        ))),
    }
}
```

- [ ] **Step 3: Update `list_tools_inner` to merge base metadata**

Replace:
```rust
async fn list_tools_inner(
    state: &AppState,
    metadata: Option<serde_json::Value>,
) -> axum::response::Response {
    let meta = match metadata {
        Some(value) => runtime::Metadata::from(value),
        None => runtime::Metadata::new(),
    };
```

With:
```rust
async fn list_tools_inner(
    state: &AppState,
    metadata: Option<serde_json::Value>,
) -> axum::response::Response {
    let mut meta = state.metadata.clone();
    if let Some(value) = metadata {
        meta.extend(runtime::Metadata::from(value));
    }
```

- [ ] **Step 4: Update `tool_call_dispatcher` to merge base metadata**

Replace:
```rust
    let metadata: Metadata = match body.metadata {
        Some(value) => Metadata::from(value),
        None => Metadata::new(),
    };
```

With:
```rust
    let mut metadata = state.metadata.clone();
    if let Some(value) = body.metadata {
        metadata.extend(Metadata::from(value));
    }
```

- [ ] **Step 5: Verify the whole project compiles**

Run: `cd /mnt/devenv/workspace/act/act-cli && cargo check`
Expected: compiles without errors

- [ ] **Step 6: Run all tests**

Run: `cd /mnt/devenv/workspace/act/act-cli && cargo test`
Expected: all tests pass

- [ ] **Step 7: Run clippy**

Run: `cd /mnt/devenv/workspace/act/act-cli && cargo clippy -- -D warnings`
Expected: no warnings

- [ ] **Step 8: Commit all changes atomically**

```bash
cd /mnt/devenv/workspace/act/act-cli
git add src/runtime.rs src/main.rs src/http.rs
git commit -m "feat: integrate filesystem capabilities into runtime, CLI, and HTTP server

- create_store() accepts FsConfig for WASI preopened directories
- CommonOpts with --allow-dir, --allow-fs, --profile, --config flags
- resolve_opts() handles config file + profile + CLI flag resolution
- AppState carries resolved metadata, HTTP handlers merge request metadata on top
- warn_missing_capabilities() logs when component wants filesystem but none granted
- std:fs:mount-root applied to all guest paths"
```

---

## Chunk 4: Integration Test and Verification

### Task 7: CLI integration test

**Files:**
- Create: `tests/config_integration.rs`

- [ ] **Step 1: Write integration test that verifies CLI flags exist**

```rust
#[test]
fn cli_help_shows_filesystem_flags() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_act"))
        .args(["serve", "--help"])
        .output()
        .expect("failed to run act");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow-dir"), "missing --allow-dir flag");
    assert!(stdout.contains("allow-fs"), "missing --allow-fs flag");
    assert!(stdout.contains("profile"), "missing --profile flag");
    assert!(stdout.contains("config"), "missing --config flag");
}

#[test]
fn cli_call_help_shows_filesystem_flags() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_act"))
        .args(["call", "--help"])
        .output()
        .expect("failed to run act");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow-dir"), "missing --allow-dir in call");
    assert!(stdout.contains("allow-fs"), "missing --allow-fs in call");
}

#[test]
fn cli_mcp_help_shows_filesystem_flags() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_act"))
        .args(["mcp", "--help"])
        .output()
        .expect("failed to run act");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow-dir"), "missing --allow-dir in mcp");
}

#[test]
fn cli_info_help_does_not_show_filesystem_flags() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_act"))
        .args(["info", "--help"])
        .output()
        .expect("failed to run act");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Info doesn't instantiate, so no filesystem flags
    assert!(!stdout.contains("allow-dir"), "--allow-dir should not be in info");
}
```

- [ ] **Step 2: Run integration tests**

Run: `cd /mnt/devenv/workspace/act/act-cli && cargo test --test config_integration`
Expected: all pass

- [ ] **Step 3: Commit**

```bash
cd /mnt/devenv/workspace/act/act-cli
git add tests/config_integration.rs
git commit -m "test: add CLI integration tests for filesystem capability flags"
```

---

### Task 8: Final verification

- [ ] **Step 1: Run full test suite**

Run: `cd /mnt/devenv/workspace/act/act-cli && cargo test`
Expected: all tests pass

- [ ] **Step 2: Run clippy**

Run: `cd /mnt/devenv/workspace/act/act-cli && cargo clippy -- -D warnings`
Expected: no warnings

- [ ] **Step 3: Verify help output**

Run: `cd /mnt/devenv/workspace/act/act-cli && cargo run -- serve --help`
Expected output includes:
```
--allow-dir <ALLOW_DIR>   Map a host directory to a guest path (guest:host). Repeatable
--allow-fs                Grant full filesystem access (host / → guest /)
--profile <PROFILE>       Use a named profile from the config file
--config <CONFIG>         Override config file location
```

- [ ] **Step 4: Manual smoke test (if filesystem component is built)**

With filesystem access:
```bash
cargo run -- serve ../components/filesystem/target/wasm32-wasip2/release/component_filesystem.wasm \
  --allow-dir /data:/tmp/test-fs
```
Expected: component loads, NO capability warning.

Without filesystem access:
```bash
cargo run -- serve ../components/filesystem/target/wasm32-wasip2/release/component_filesystem.wasm
```
Expected: component loads WITH warning: "component declares wasi:filesystem capability but no filesystem access was granted"

- [ ] **Step 5: Format check**

```bash
cargo fmt -- --check
```
If needed: `cargo fmt && git add -u && git commit -m "style: format"`
