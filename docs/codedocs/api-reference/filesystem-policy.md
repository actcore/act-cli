---
title: "API Reference: filesystem policy"
description: "Public Rust items in runtime/effective.rs, runtime/fs_matcher.rs, and runtime/fs_policy.rs that implement capability ceilings and path gating."
---

Source files: `act-cli/src/runtime/effective.rs`, `act-cli/src/runtime/fs_matcher.rs`, and `act-cli/src/runtime/fs_policy.rs`

## Effective Policy

```rust
pub struct EffectivePolicy<T> {
    pub config: T,
    pub declared: bool,
}
```

```rust
pub fn effective_fs(user: &FsConfig, caps: &Capabilities) -> EffectivePolicy<FsConfig>
pub fn effective_http(user: &HttpConfig, caps: &Capabilities) -> EffectivePolicy<HttpConfig>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `user` | `&FsConfig` or `&HttpConfig` | — | User-resolved policy from config and CLI. |
| `caps` | `&Capabilities` | — | Declared component capabilities from `act:component`. |

These functions intersect user policy with the component declaration. Undeclared capabilities collapse to `Deny`.

## Filesystem Matcher

```rust
pub enum FsDecision {
    Allow,
    Deny,
}
```

```rust
pub struct FsMatcher { /* compiled allow/deny glob sets */ }
```

### `FsMatcher::compile`

```rust
pub fn compile(cfg: &FsConfig) -> Result<Self>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `cfg` | `&FsConfig` | — | Resolved filesystem policy. |

Compiles allow and deny globs into `GlobSet`s and records literal prefixes used for ancestor traversal checks.

### `FsMatcher::decide`

```rust
pub fn decide(&self, path: &Path) -> FsDecision
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `path` | `&Path` | — | Absolute, canonical host path. |

Evaluates deny globs first, then allow globs, then ancestor traversal rules.

## Filesystem Host Adapter

```rust
pub struct Preopen {
    pub guest: String,
    pub host: PathBuf,
}
```

```rust
pub struct PolicyFilesystem;
```

```rust
pub struct PolicyFilesystemCtxView<'a> {
    pub ctx: &'a mut WasiFilesystemCtx,
    pub table: &'a mut ResourceTable,
    pub matcher: &'a FsMatcher,
    pub fd_paths: &'a mut FdPathMap,
    pub mode: PolicyMode,
}
```

```rust
pub struct FdPathMap {
    pub preopens: Vec<(String, PathBuf)>,
    pub by_rep: HashMap<u32, PathBuf>,
}
```

### `derive_preopens`

```rust
pub fn derive_preopens(cfg: &FsConfig) -> Vec<Preopen>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `cfg` | `&FsConfig` | — | Resolved filesystem policy. |

Returns platform-root preopens for `Open` and `Allowlist`, and no preopens for `Deny`.

### `apply_mount_root`

```rust
pub fn apply_mount_root(preopens: &mut [Preopen], mount_root: &str)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `preopens` | `&mut [Preopen]` | — | Derived preopens to rewrite. |
| `mount_root` | `&str` | `/` | Cosmetic guest mount root from component capabilities. |

Rewrites only the guest-visible path names, not the host paths.

## Example

```rust
let effective = crate::runtime::effective::effective_fs(&fs, &info.std.capabilities);
let mut preopens = crate::runtime::fs_policy::derive_preopens(&effective.config);
crate::runtime::fs_policy::apply_mount_root(
    &mut preopens,
    info.std.capabilities.fs_mount_root().unwrap_or("/"),
);
let matcher = crate::runtime::fs_matcher::FsMatcher::compile(&effective.config)?;
```

## Practical Notes

- `PolicyFilesystemCtxView` exists because the source shadows default Wasmtime filesystem bindings with a policy-aware wrapper.
- `FdPathMap` tracks descriptor-to-host-path mappings so later path-based operations can be checked against the matcher.
- `effective_http` is documented here because the capability-ceiling logic for filesystem and HTTP lives in the same module.

Related pages: [Runtime Policies](/docs/runtime-policies), [API Reference: runtime core](/docs/api-reference/runtime-core), and [API Reference: networking policy](/docs/api-reference/networking-policy).
