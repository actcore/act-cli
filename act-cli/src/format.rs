//! Output formatting for the `act info` command.
//!
//! Provides [`InfoData`] struct and two rendering functions:
//! - [`to_text`] — markdown-like human-readable output
//! - [`to_json`] — machine-readable JSON output

use act_types::{
    constants::{
        META_ANTI_USAGE_HINTS, META_DESTRUCTIVE, META_IDEMPOTENT, META_READ_ONLY, META_STREAMING,
        META_TAGS, META_TIMEOUT_MS, META_USAGE_HINTS,
    },
    types::{ComponentInfo, LocalizedString, Metadata},
};
use serde::Serialize;
use serde_with::skip_serializing_none;

// ── Data carrier ──────────────────────────────────────────────────────────────

/// All data needed to render `act info` output.
pub struct InfoData<'a> {
    pub info: &'a ComponentInfo,
    /// JSON string returned by `get-metadata-schema`, if requested.
    pub metadata_schema: Option<String>,
    /// Tool list from `list-tools`, if requested.
    pub tools: Option<Vec<crate::runtime::act::core::types::ToolDefinition>>,
}

// ── JSON output ───────────────────────────────────────────────────────────────

#[skip_serializing_none]
#[derive(Serialize)]
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

#[skip_serializing_none]
#[derive(Serialize)]
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Render [`InfoData`] as a machine-readable JSON string.
pub fn to_json(data: &InfoData<'_>) -> anyhow::Result<String> {
    let info = data.info;

    let skill = info
        .extra
        .get("std:skill")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let capabilities = serde_json::to_value(&info.std.capabilities)
        .unwrap_or_else(|_| serde_json::Value::Object(Default::default()));

    let metadata_schema_value: Option<serde_json::Value> = data
        .metadata_schema
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .unwrap_or(None);

    let tools_json = data
        .tools
        .as_ref()
        .map(|tools| tools.iter().map(tool_to_json).collect::<Vec<_>>());

    let out = InfoJson {
        name: info.std.name.clone(),
        version: info.std.version.clone(),
        description: info.std.description.clone(),
        default_language: info.std.default_language.clone(),
        capabilities,
        skill,
        metadata_schema: metadata_schema_value,
        tools: tools_json,
    };

    Ok(serde_json::to_string_pretty(&out)?)
}

fn tool_to_json(td: &crate::runtime::act::core::types::ToolDefinition) -> ToolJson {
    let meta = Metadata::from(td.metadata.clone());
    let desc = LocalizedString::from(&td.description);

    let params_schema: serde_json::Value = serde_json::from_str(&td.parameters_schema)
        .unwrap_or(serde_json::Value::String(td.parameters_schema.clone()));

    let tags: Vec<String> = meta.get_as::<Vec<String>>(META_TAGS).unwrap_or_default();

    ToolJson {
        name: td.name.clone(),
        description: desc.any_text().to_string(),
        parameters_schema: params_schema,
        read_only: meta.get_as::<bool>(META_READ_ONLY),
        idempotent: meta.get_as::<bool>(META_IDEMPOTENT),
        destructive: meta.get_as::<bool>(META_DESTRUCTIVE),
        streaming: meta.get_as::<bool>(META_STREAMING),
        timeout_ms: meta.get_as::<u64>(META_TIMEOUT_MS),
        usage_hints: meta.get_as::<String>(META_USAGE_HINTS),
        anti_usage_hints: meta.get_as::<String>(META_ANTI_USAGE_HINTS),
        tags,
    }
}

// ── Text output ───────────────────────────────────────────────────────────────

/// Render [`InfoData`] as a markdown-like human-readable string.
pub fn to_text(data: &InfoData<'_>) -> String {
    let info = data.info;
    let mut out = String::new();

    // Header
    out.push_str(&format!("# {} v{}\n", info.std.name, info.std.version));
    if !info.std.description.is_empty() {
        out.push_str(&info.std.description);
        out.push('\n');
    }

    // Capabilities
    if !info.std.capabilities.is_empty() {
        out.push_str("\nCapabilities:\n");
        if let Some(fs) = &info.std.capabilities.filesystem {
            out.push_str("  wasi:filesystem");
            if let Some(root) = &fs.mount_root {
                out.push_str(&format!(" (mount-root: {})", root));
            }
            out.push('\n');
        }
        if info.std.capabilities.http.is_some() {
            out.push_str("  wasi:http\n");
        }
        if info.std.capabilities.sockets.is_some() {
            out.push_str("  wasi:sockets\n");
        }
        for (id, params) in &info.std.capabilities.other {
            out.push_str(&format!("  {}", id));
            if let serde_json::Value::Object(map) = params
                && !map.is_empty()
            {
                let pairs: Vec<String> = map
                    .iter()
                    .map(|(k, v)| match v {
                        serde_json::Value::String(s) => format!("{}: {}", k, s),
                        other => format!("{}: {}", k, other),
                    })
                    .collect();
                out.push_str(&format!(" ({})", pairs.join(", ")));
            }
            out.push('\n');
        }
    }

    // Skill
    if let Some(skill) = info.extra.get("std:skill").and_then(|v| v.as_str()) {
        out.push_str("\n## Skill\n");
        out.push_str(skill);
        out.push('\n');
    }

    // Metadata schema
    if let Some(schema_str) = &data.metadata_schema {
        out.push_str("\n## Metadata Schema\n");
        // Pretty-print if valid JSON, otherwise print as-is
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(schema_str) {
            out.push_str(&serde_json::to_string_pretty(&v).unwrap_or_else(|_| schema_str.clone()));
        } else {
            out.push_str(schema_str);
        }
        out.push('\n');
    }

    // Tools
    if let Some(tools) = &data.tools {
        for td in tools {
            out.push('\n');
            out.push_str(&tool_to_text(td));
        }
    }

    out
}

fn tool_to_text(td: &crate::runtime::act::core::types::ToolDefinition) -> String {
    let mut out = String::new();
    let meta = Metadata::from(td.metadata.clone());
    let desc = LocalizedString::from(&td.description);

    out.push_str(&format!("## {}\n", td.name));
    let desc_text = desc.any_text();
    if !desc_text.is_empty() {
        out.push_str(desc_text);
        out.push('\n');
    }

    // Annotations line: [read-only, idempotent, destructive, streaming]
    let mut annotations: Vec<&str> = Vec::new();
    if meta.get_as::<bool>(META_READ_ONLY).unwrap_or(false) {
        annotations.push("read-only");
    }
    if meta.get_as::<bool>(META_IDEMPOTENT).unwrap_or(false) {
        annotations.push("idempotent");
    }
    if meta.get_as::<bool>(META_DESTRUCTIVE).unwrap_or(false) {
        annotations.push("destructive");
    }
    if meta.get_as::<bool>(META_STREAMING).unwrap_or(false) {
        annotations.push("streaming");
    }
    if !annotations.is_empty() {
        out.push_str(&format!("[{}]\n", annotations.join(", ")));
    }

    // Timeout
    if let Some(ms) = meta.get_as::<u64>(META_TIMEOUT_MS) {
        out.push_str(&format!("Timeout: {}ms\n", ms));
    }

    // Tags
    let tags: Vec<String> = meta.get_as::<Vec<String>>(META_TAGS).unwrap_or_default();
    if !tags.is_empty() {
        out.push_str(&format!("Tags: {}\n", tags.join(", ")));
    }

    // Usage hints
    if let Some(hint) = meta.get_as::<String>(META_USAGE_HINTS) {
        out.push_str(&format!("When to use: {}\n", hint));
    }
    if let Some(hint) = meta.get_as::<String>(META_ANTI_USAGE_HINTS) {
        out.push_str(&format!("When NOT to use: {}\n", hint));
    }

    // Parameters
    if let Ok(schema) = serde_json::from_str::<serde_json::Value>(&td.parameters_schema) {
        let params = extract_params(&schema);
        if !params.is_empty() {
            out.push_str("Parameters:\n");
            for (name, type_str, required, description) in params {
                let req_marker = if required { " (required)" } else { "" };
                if let Some(d) = description {
                    out.push_str(&format!("  {}: {}{} — {}\n", name, type_str, req_marker, d));
                } else {
                    out.push_str(&format!("  {}: {}{}\n", name, type_str, req_marker));
                }
            }
        }
    }

    out
}

/// Extract parameter info from a JSON Schema object schema.
/// Returns Vec of (name, type, required, description).
fn extract_params(schema: &serde_json::Value) -> Vec<(String, String, bool, Option<String>)> {
    let mut result = Vec::new();
    let props = match schema.get("properties").and_then(|p| p.as_object()) {
        Some(p) => p,
        None => return result,
    };
    let required_list: Vec<&str> = schema
        .get("required")
        .and_then(|r| r.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    for (name, prop) in props {
        let type_str = prop
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("any")
            .to_string();
        let required = required_list.contains(&name.as_str());
        let description = prop
            .get("description")
            .and_then(|d| d.as_str())
            .map(|s| s.to_string());
        result.push((name.clone(), type_str, required, description));
    }

    result
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use act_types::FilesystemCap;
    use act_types::types::ComponentInfo;

    fn sample_info() -> ComponentInfo {
        let mut info = ComponentInfo::new("component-sqlite", "0.2.0", "SQLite database access");
        info.std.default_language = Some("en".to_string());
        info.std.capabilities.filesystem = Some(FilesystemCap {
            mount_root: Some("/data".to_string()),
        });
        info.extra.insert(
            "std:skill".to_string(),
            serde_json::Value::String("Use this component for database operations...".to_string()),
        );
        info
    }

    #[test]
    fn text_header_and_description() {
        let info = sample_info();
        let data = InfoData {
            info: &info,
            metadata_schema: None,
            tools: None,
        };
        let text = to_text(&data);
        assert!(text.contains("# component-sqlite v0.2.0"));
        assert!(text.contains("SQLite database access"));
    }

    #[test]
    fn text_capabilities() {
        let info = sample_info();
        let data = InfoData {
            info: &info,
            metadata_schema: None,
            tools: None,
        };
        let text = to_text(&data);
        assert!(text.contains("wasi:filesystem (mount-root: /data)"));
    }

    #[test]
    fn text_skill() {
        let info = sample_info();
        let data = InfoData {
            info: &info,
            metadata_schema: None,
            tools: None,
        };
        let text = to_text(&data);
        assert!(text.contains("## Skill"));
        assert!(text.contains("Use this component for database operations..."));
    }

    #[test]
    fn text_metadata_schema() {
        let info = sample_info();
        let schema = r#"{"type":"object","properties":{"database_path":{"type":"string"}}}"#;
        let data = InfoData {
            info: &info,
            metadata_schema: Some(schema.to_string()),
            tools: None,
        };
        let text = to_text(&data);
        assert!(text.contains("## Metadata Schema"));
        assert!(text.contains("database_path"));
    }

    #[test]
    fn json_output_basic() {
        let info = sample_info();
        let data = InfoData {
            info: &info,
            metadata_schema: None,
            tools: None,
        };
        let json_str = to_json(&data).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(v["name"], "component-sqlite");
        assert_eq!(v["version"], "0.2.0");
        assert_eq!(v["description"], "SQLite database access");
        assert_eq!(v["skill"], "Use this component for database operations...");
        assert_eq!(v["capabilities"]["wasi:filesystem"]["mount-root"], "/data");
    }

    #[test]
    fn json_metadata_schema_parsed() {
        let info = sample_info();
        let schema = r#"{"type":"object"}"#;
        let data = InfoData {
            info: &info,
            metadata_schema: Some(schema.to_string()),
            tools: None,
        };
        let json_str = to_json(&data).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(v["metadata_schema"]["type"], "object");
    }

    #[test]
    fn empty_info_no_panic() {
        let info = ComponentInfo::default();
        let data = InfoData {
            info: &info,
            metadata_schema: None,
            tools: None,
        };
        let text = to_text(&data);
        let json_str = to_json(&data).unwrap();
        // Should not panic, produce some output
        assert!(text.contains('#'));
        assert!(json_str.contains("name"));
    }
}
