---
title: "API Reference: resolve"
description: "Public Rust items in act-cli/src/resolve.rs that parse component references and resolve them to local cached files."
---

Source file: `act-cli/src/resolve.rs`

## Types

```rust
pub enum ComponentRef {
    Local(PathBuf),
    Http(Url),
    Oci(String),
    Name(String),
}
```

`ComponentRef` implements `FromStr` and `Display`. Parsing never fails; unresolved or ambiguous inputs become `Name`.

## Functions

### `resolve`

```rust
pub async fn resolve(component_ref: &ComponentRef, fresh: bool) -> Result<PathBuf>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `component_ref` | `&ComponentRef` | — | Parsed local, HTTP, OCI, or logical-name reference. |
| `fresh` | `bool` | `false` in most callers | When `true`, bypasses the on-disk cache for remote refs and redownloads the artifact. |

Returns a local filesystem path to the resolved `.wasm` file.

Behavior by variant:

| Variant | Resolution path |
|---------|-----------------|
| `Local` | Verifies the path exists and returns it directly. |
| `Http` | Downloads with `reqwest`, streams to `~/.cache/act/components/<sha256>.wasm`, and returns the cached path. |
| `Oci` | Pulls the first layer blob from the OCI manifest with `oci-client`, streams it to the same cache, and returns the cached path. |
| `Name` | Returns an error because centralized registry lookup is not implemented yet. |

## Examples

Basic HTTP resolution:

```rust
use std::str::FromStr;

let component = crate::resolve::ComponentRef::from_str(
    "https://example.com/component.wasm"
).unwrap();
let path = crate::resolve::resolve(&component, false).await?;
```

Forced OCI refresh:

```rust
use std::str::FromStr;

let component = crate::resolve::ComponentRef::from_str(
    "ghcr.io/actpkg/sqlite:0.1.0"
).unwrap();
let path = crate::resolve::resolve(&component, true).await?;
```

## Practical Notes

- Cache keys are SHA-256 hashes of the original input string, not of the downloaded bytes.
- Progress bars are displayed for downloads through `indicatif`.
- `cmd_pull` in `act-cli/src/main.rs` is the only built-in caller that always sets `fresh = true`.
- Logical names intentionally remain a parsed-but-unresolved state. That lets the command surface reserve the shape now without overloading parse failures with future registry concerns.
- The module is a pure resolution layer. It does not read component metadata, compute policy, or instantiate Wasmtime, which is why callers always hand the returned path off to `runtime::read_component_info` or the runtime bootstrap helpers next.

Related pages: [Component References](/docs/component-references) and [API Reference: runtime core](/docs/api-reference/runtime-core).
