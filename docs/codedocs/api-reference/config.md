---
title: "API Reference: config"
description: "Public Rust items in act-cli/src/config.rs that load config, resolve profiles, and compute filesystem, HTTP, and metadata settings."
---

This module is the policy resolution entry point for `act-cli`. The items below are public in the source tree, but they should be treated as internal implementation API rather than a stable library contract because `act-cli` is published as a binary crate.

Source file: `act-cli/src/config.rs`

## Types

```rust
pub enum PolicyMode {
    Deny,
    Allowlist,
    Open,
}
```

```rust
pub struct FsConfig {
    pub mode: PolicyMode,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}
```

```rust
pub struct HttpConfig {
    pub mode: PolicyMode,
    pub allow: Vec<HttpRule>,
    pub deny: Vec<HttpRule>,
}
```

```rust
pub struct HttpRule {
    pub net: crate::runtime::network::NetworkRule,
    pub scheme: Option<String>,
    pub methods: Option<Vec<String>>,
}
```

```rust
pub struct ConfigFile {
    pub listen: Option<String>,
    pub log_level: Option<String>,
    pub policy: Option<PolicyConfig>,
    pub profile: HashMap<String, ProfileConfig>,
}
```

```rust
pub struct PolicyConfig {
    pub filesystem: Option<FsPolicyToml>,
    pub http: Option<HttpPolicyToml>,
}
```

```rust
pub enum FsPolicyToml {
    Simple(String),
    Structured {
        mode: String,
        allow: Vec<String>,
        deny: Vec<String>,
    },
}
```

```rust
pub enum HttpPolicyToml {
    Simple(String),
    Structured {
        mode: String,
        allow: Vec<HttpRule>,
        deny: Vec<HttpRule>,
    },
}
```

```rust
pub struct ProfileConfig {
    pub metadata: Option<serde_json::Value>,
    pub policy: Option<PolicyConfig>,
}
```

```rust
pub struct CliPolicyOverrides {
    pub fs_mode: Option<String>,
    pub fs_allow: Vec<String>,
    pub fs_deny: Vec<String>,
    pub http_mode: Option<String>,
    pub http_allow: Vec<String>,
    pub http_deny: Vec<String>,
}
```

### Field Notes

| Field | Type | Description |
|-------|------|-------------|
| `FsConfig.allow` | `Vec<String>` | Filesystem allow globs later compiled by `FsMatcher`. |
| `FsConfig.deny` | `Vec<String>` | Deny globs checked before allow globs. |
| `HttpRule.net` | `crate::runtime::network::NetworkRule` | Shared network-level matcher input for host, port, and CIDR checks. |
| `ProfileConfig.metadata` | `Option<serde_json::Value>` | Per-profile metadata merged into outgoing ACT metadata. |

## Functions

### `FsConfig::deny`

```rust
pub fn deny() -> Self
```

Returns a default deny-all filesystem configuration.

Example:

```rust
let fs = crate::config::FsConfig::deny();
assert!(matches!(fs.mode, crate::config::PolicyMode::Deny));
```

### `default_config_path`

```rust
pub fn default_config_path() -> Option<PathBuf>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| — | — | — | Uses the platform config directory and appends `act/config.toml`. |

Returns `Some(path)` when the platform has a config directory, otherwise `None`.

### `load_config`

```rust
pub fn load_config(path: Option<&Path>) -> Result<ConfigFile>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `path` | `Option<&Path>` | `None` | Explicit config path. Falls back to `default_config_path()` and returns `ConfigFile::default()` when no file exists. |

Reads TOML from disk and deserializes it into `ConfigFile`.

Example:

```rust
let cfg = crate::config::load_config(None)?;
```

### `get_profile`

```rust
pub fn get_profile<'a>(config: &'a ConfigFile, name: &str) -> Result<&'a ProfileConfig>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | `&ConfigFile` | — | Loaded config file. |
| `name` | `&str` | — | Profile key under `config.profile`. |

Returns the named profile or an error when it is missing.

### `resolve_fs_config`

```rust
pub fn resolve_fs_config(
    config: &ConfigFile,
    profile: Option<&ProfileConfig>,
    cli: &CliPolicyOverrides,
) -> Result<FsConfig>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | `&ConfigFile` | — | Top-level config file state. |
| `profile` | `Option<&ProfileConfig>` | `None` | Optional profile chosen by CLI. |
| `cli` | `&CliPolicyOverrides` | — | CLI override layer. Any filesystem override replaces config-file policy resolution. |

Returns the final filesystem policy used for the invocation.

### `resolve_http_config`

```rust
pub fn resolve_http_config(
    config: &ConfigFile,
    profile: Option<&ProfileConfig>,
    cli: &CliPolicyOverrides,
) -> Result<HttpConfig>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | `&ConfigFile` | — | Top-level config file state. |
| `profile` | `Option<&ProfileConfig>` | `None` | Optional profile chosen by CLI. |
| `cli` | `&CliPolicyOverrides` | — | CLI override layer. Any HTTP override replaces config-file policy resolution. |

Returns the final HTTP policy used for the invocation.

### `resolve_metadata`

```rust
pub fn resolve_metadata(
    profile: Option<&ProfileConfig>,
    cli_metadata: Option<&serde_json::Value>,
) -> serde_json::Value
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `profile` | `Option<&ProfileConfig>` | `None` | Optional profile whose `metadata` object is the base layer. |
| `cli_metadata` | `Option<&serde_json::Value>` | `None` | Optional JSON object from `--metadata` or `--metadata-file`. |

Merges object keys, with CLI keys taking precedence. Non-object metadata is ignored.

## Common Pattern

```rust
let config = crate::config::load_config(None)?;
let profile = crate::config::get_profile(&config, "local").ok();
let cli = crate::config::CliPolicyOverrides {
    fs_mode: Some("allowlist".to_string()),
    fs_allow: vec!["/workspace/**".to_string()],
    ..Default::default()
};
let fs = crate::config::resolve_fs_config(&config, profile, &cli)?;
let http = crate::config::resolve_http_config(&config, profile, &cli)?;
let metadata = crate::config::resolve_metadata(profile, None);
```

Related pages: [Runtime Policies](/docs/runtime-policies), [API Reference: filesystem policy](/docs/api-reference/filesystem-policy), and [API Reference: networking policy](/docs/api-reference/networking-policy).
