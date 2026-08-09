---
title: "API Reference: build pipeline"
description: "Public Rust items in act-build/src that pack skills, write custom sections, and validate completed ACT components."
---

Source files: `act-build/src/pack.rs`, `skill.rs`, `validate.rs`, and `wasm.rs`

## Pack

### `run`

```rust
pub fn run(wasm_path: &Path) -> Result<()>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `wasm_path` | `&Path` | — | Path to the compiled component to rewrite in place. |

Performs the full pack pipeline:

1. Find the project directory.
2. Resolve and validate metadata.
3. Read the existing `.wasm`.
4. Write `act:component`.
5. Write `version` and `description`.
6. Optionally write `act:skill`.
7. Persist the modified bytes.

Example:

```rust
crate::pack::run(wasm_path)?;
```

## Skill Packaging

### `pack_skill_dir`

```rust
pub fn pack_skill_dir(project_dir: &Path) -> Result<Option<Vec<u8>>>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `project_dir` | `&Path` | — | Project root checked for a `skill/` directory. |

Returns `None` when no `skill/` directory exists, and returns a tar archive when `skill/SKILL.md` is present.

## Validation

### `run`

```rust
pub fn run(wasm_path: &Path) -> Result<()>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `wasm_path` | `&Path` | — | Packed component to inspect. |

Checks that:

- `act:component` exists.
- The section decodes to `ComponentInfo`.
- `std.name` and `std.version` are non-empty.
- The component exports `act:core/tool-provider`.

### `check_tool_provider_export`

```rust
pub fn check_tool_provider_export(wasm: &[u8]) -> Result<bool>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `wasm` | `&[u8]` | — | Raw component bytes. |

Returns `true` when the component export section contains a name including `act:core/tool-provider`.

## Custom Section Utilities

### `read_custom_section`

```rust
pub fn read_custom_section<'a>(wasm: &'a [u8], name: &str) -> Result<Option<&'a [u8]>>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `wasm` | `&'a [u8]` | — | Raw component bytes. |
| `name` | `&str` | — | Custom section name to search for. |

### `set_custom_section`

```rust
pub fn set_custom_section(wasm: &[u8], name: &str, data: &[u8]) -> Result<Vec<u8>>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `wasm` | `&[u8]` | — | Raw component bytes. |
| `name` | `&str` | — | Custom section to add or replace. |
| `data` | `&[u8]` | — | Section payload bytes. |

Adds or replaces a top-level custom section by scanning top-level section framing and splicing in the newly encoded section bytes.

## Example

```rust
let mut wasm = std::fs::read(wasm_path)?;
wasm = crate::wasm::set_custom_section(&wasm, "version", b"1.2.3")?;
let has_provider = crate::validate::check_tool_provider_export(&wasm)?;
```

## Practical Notes

- `set_custom_section` requires a component-layer WASM header and will reject module-layer binaries.
- `pack::run` writes in place, so plan artifact immutability accordingly.
- `check_tool_provider_export` performs a substring check on export names rather than a stronger semantic WIT verification.

Related pages: [Component Packaging](/docs/component-packaging) and [Guides: Packing and Validating Components](/docs/guides/packing-and-validating-components).
