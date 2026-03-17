# Filesystem Capabilities & Config Design

## Goal

Allow act-cli to grant filesystem access to WASM components with different isolation levels, controlled via CLI flags and a configuration file.

## Filesystem Modes

| Mode | CLI flag | Behavior |
|------|----------|----------|
| **None** (default) | no flags | No filesystem. FS calls return errors. |
| **Directory** | `--allow-dir guest:host` | Map specific host directories to guest paths. |
| **Full** | `--allow-fs` | Shorthand for `--allow-dir /:/`. |

### Mount point

Components declare `std:fs:mount-root` in the `act:component` metadata section (default: `/`). All directory mappings are relative to this path.

- `--allow-dir data:/real/data` → guest sees `{rootfs}/data`
- `--allow-fs` → host `/` mapped to guest `{rootfs}`

### Capability warning

If a component declares `wasi:filesystem` in `std:capabilities` but the host grants no filesystem access, the host logs a warning. The component still loads — filesystem calls fail gracefully (return errors, no trap).

## Configuration File

Location: `~/.config/act/config.toml`

### Structure

```toml
# Host defaults
listen = "[::1]:3000"
log-level = "info"

# Default security policy for all components
[policy]
filesystem = "none"
network = true

# Named profiles — applied explicitly via --profile
[profile.sqlite]
metadata = { database_path = "/data/app.db" }

[profile.sqlite.policy]
filesystem = { mode = "directory", allow-dir = [
  { guest = "/data", host = "~/.local/share/act/sqlite" },
]}

[profile.memory]
metadata = { storage_path = "/data/memory.json" }

[profile.memory.policy]
filesystem = { mode = "directory", allow-dir = [
  { guest = "/data", host = "~/.local/share/act/memory" },
]}

[profile.filesystem]
policy.filesystem = "full"
```

### Profile usage

```bash
act serve sqlite.wasm --profile sqlite    # uses profile config
act serve component.wasm                   # defaults only
act serve component.wasm --allow-fs        # CLI override
```

Profiles are **not matched automatically** by component name. The user explicitly binds a wasm file to a profile via `--profile`. This prevents a malicious component from claiming a trusted name to inherit permissions.

### Resolution order

**CLI flags > profile > defaults**

- CLI flags (`--allow-dir`, `--allow-fs`, `--metadata`) always win.
- If `--profile <name>` is specified, that profile's settings are applied.
- Otherwise, only top-level defaults apply.

### Metadata injection

A profile's `metadata` section is merged into `tool-call.metadata` for every call. This replaces the need for `--metadata` CLI flags for static per-component config (database paths, API keys, etc.).

## CLI Changes

New flags for `act serve`, `act call`, `act mcp`, `act tools`:

| Flag | Description |
|------|-------------|
| `--allow-dir guest:host` | Map a host directory to a guest path. Repeatable. |
| `--allow-fs` | Grant full filesystem access (`/` → `/`). |
| `--profile <name>` | Use a named profile from config file. |
| `--config <path>` | Override config file location. |

## Implementation

### runtime.rs — `create_store()`

Currently:
```rust
let wasi = WasiCtxBuilder::new().build();
```

After:
```rust
let mut builder = WasiCtxBuilder::new();
for mount in &fs_config.mounts {
    builder.preopened_dir(&mount.host, &mount.guest, DirPerms::all(), FilePerms::all())?;
}
let wasi = builder.build();
```

### Config loading

1. Load `~/.config/act/config.toml` (or `--config` path).
2. Parse with `toml` crate into typed structs.
3. If `--profile` specified, merge profile into defaults.
4. CLI flags override merged result.

### New constant

`std:fs:mount-root` added to `ACT-CONSTANTS.md` Section 2 (Component Info Keys).

## Scope

This design covers filesystem capabilities only. Network policy, toolserver profile matching, and other security features are out of scope and will be designed separately.

## Non-goals

- Automatic profile matching by component name (security risk).
- Toolserver multi-component config (separate design).
- Fine-grained file permissions (read-only mounts) — can be added later via `DirPerms`/`FilePerms`.
