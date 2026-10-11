---
title: "API Reference: format"
description: "Public Rust items in act-cli/src/format.rs that render act info output as text or JSON."
---

This module formats the output of `act info`. It takes a fully assembled `InfoData` value and renders either a human-readable text document or a structured JSON payload. Source file: `act-cli/src/format.rs`.

## Types

```rust
pub struct InfoData<'a> {
    pub info: &'a ComponentInfo,
    pub metadata_schema: Option<String>,
    pub tools: Option<Vec<crate::runtime::act::core::types::ToolDefinition>>,
}
```

```rust
pub struct InfoJson {
    pub name: String,
    pub version: String,
    pub description: String,
    pub default_language: Option<String>,
    pub capabilities: serde_json::Value,
    pub skill: Option<String>,
    pub metadata_schema: Option<serde_json::Value>,
    pub tools: Option<Vec<ToolJson>>,
}
```

```rust
pub struct ToolJson {
    pub name: String,
    pub description: String,
    pub parameters_schema: serde_json::Value,
    pub read_only: Option<bool>,
    pub idempotent: Option<bool>,
    pub destructive: Option<bool>,
    pub streaming: Option<bool>,
    pub timeout_ms: Option<u64>,
    pub usage_hints: Option<String>,
    pub anti_usage_hints: Option<String>,
    pub tags: Vec<String>,
}
```

## Functions

### `to_json`

```rust
pub fn to_json(data: &InfoData<'_>) -> anyhow::Result<String>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `data` | `&InfoData<'_>` | — | Component info plus optional metadata schema and tool list. |

Returns pretty-printed JSON. Invalid tool parameter schemas are preserved as JSON strings instead of crashing the formatter.

Example:

```rust
let output = crate::format::to_json(&data)?;
println!("{output}");
```

### `to_text`

```rust
pub fn to_text(data: &InfoData<'_>) -> String
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `data` | `&InfoData<'_>` | — | Component info plus optional metadata schema and tool list. |

Returns a markdown-like string that includes component metadata, capability summary, optional embedded skill text, metadata schema, and tool details.

Example:

```rust
let output = crate::format::to_text(&data);
print!("{output}");
```

## Notes

- `to_json` extracts tool annotations such as read-only, idempotent, destructive, streaming, timeout, usage hints, and tags from ACT metadata keys.
- `to_text` summarizes capability classes and prints metadata and tool sections only when the corresponding data exists.
- The module is used directly by `cmd_info` in `act-cli/src/main.rs`.

Common pattern:

```rust
let data = crate::format::InfoData {
    info: &component_info,
    metadata_schema,
    tools,
};

match format {
    OutputFormat::Text => print!("{}", crate::format::to_text(&data)),
    OutputFormat::Json => println!("{}", crate::format::to_json(&data)?),
}
```

Related pages: [Getting Started](/docs), [API Reference: resolve](/docs/api-reference/resolve), and [API Reference: runtime core](/docs/api-reference/runtime-core).
