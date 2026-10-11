---
title: "API Reference: manifest resolution"
description: "Public Rust items in act-build/src/manifest that resolve and validate component metadata from Cargo, Python, and JavaScript manifests."
---

Source files: `act-build/src/manifest/mod.rs`, `manifest/cargo.rs`, `manifest/pyproject.rs`, `manifest/packagejson.rs`, and `manifest/validate.rs`

## Manifest Readers

### Cargo

```rust
pub fn from_cargo_metadata(dir: &Path) -> Result<(ComponentInfo, Option<toml::Value>)>
pub fn from_toml(path: &Path) -> Result<(ComponentInfo, Option<toml::Value>)>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `dir` | `&Path` | — | Project directory passed to `cargo metadata`. |
| `path` | `&Path` | — | Direct `Cargo.toml` path for raw TOML fallback. |

`from_cargo_metadata` is preferred because it respects workspace inheritance. `from_toml` is the fallback when `cargo metadata` is unavailable.

### Python

```rust
pub fn from_toml(path: &Path) -> Result<(ComponentInfo, Option<toml::Value>)>
```

Reads base metadata and `[tool.act]` from `pyproject.toml`.

### JavaScript

```rust
pub fn from_json(path: &Path) -> Result<(ComponentInfo, Option<serde_json::Value>)>
```

Reads base metadata and top-level `act` from `package.json`.

## Resolver

### `resolve`

```rust
pub fn resolve(dir: &Path) -> Result<ComponentInfo>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `dir` | `&Path` | — | Project directory containing `Cargo.toml`, `pyproject.toml`, `package.json`, and or `act.toml`. |

Merges metadata in this order:

1. Base language manifest.
2. Inline ACT patch.
3. `act.toml`.

Returns an error when no recognized manifest is found.

Example:

```rust
let info = crate::manifest::resolve(project_dir)?;
```

## Capability Validation

### `validate`

```rust
pub fn validate(caps: &Capabilities) -> Result<()>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `caps` | `&Capabilities` | — | Capability declaration inside `ComponentInfo.std.capabilities`. |

Validates:

- Non-empty filesystem allow paths.
- Valid filesystem glob syntax.
- Non-empty HTTP hosts.
- HTTP schemes restricted to `http` or `https`.

## Practical Notes

- The resolver uses merge-patch semantics, not custom deep merge rules.
- `act.toml` can stand alone even when no language-specific manifest exists.
- Validation is designed to fail packaging early rather than allow malformed declarations to reach runtime.

Related pages: [Component Packaging](/docs/component-packaging) and [API Reference: build pipeline](/docs/api-reference/build-pipeline).
