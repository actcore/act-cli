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
use owo_colors::{OwoColorize, Stream, Style};
use serde::Serialize;
use serde_with::skip_serializing_none;
use std::fmt::Write as _;

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

/// Palette for human-readable `act info` output.
///
/// All writes go through `.if_supports_color(Stream::Stdout, …)` so the
/// styling evaporates when stdout isn't a TTY (`act info … | cat`, CI
/// logs) or when `NO_COLOR` is set. LLMs should use `--format json`;
/// these styles exist only to make interactive inspection scannable.
struct Palette {
    name: Style,
    version: Style,
    description: Style,
    section: Style,
    tool_name: Style,
    annotation: Style,
    required: Style,
    param: Style,
    param_type: Style,
    dim: Style,
}

impl Palette {
    fn new() -> Self {
        Self {
            name: Style::new().bold().bright_yellow(),
            version: Style::new().dimmed(),
            description: Style::new(),
            section: Style::new().bold(),
            tool_name: Style::new().bold().bright_cyan(),
            annotation: Style::new().green(),
            required: Style::new().bold().red(),
            param: Style::new().cyan(),
            param_type: Style::new().dimmed(),
            dim: Style::new().dimmed(),
        }
    }
}

/// Render [`InfoData`] as a human-readable string with terminal colors.
///
/// LLMs and scripts should prefer `--format json` — it's stable,
/// structured, and unambiguous. This renderer is tuned for humans
/// eyeballing a component in a terminal.
pub fn to_text(data: &InfoData<'_>) -> String {
    let info = data.info;
    let p = Palette::new();
    let mut out = String::new();

    let styled = |value: &str, style: Style| {
        value
            .if_supports_color(Stream::Stdout, move |s| s.style(style))
            .to_string()
    };

    // Header: `name vX.Y.Z`
    writeln!(
        out,
        "{} {}",
        styled(&info.std.name, p.name),
        styled(&format!("v{}", info.std.version), p.version),
    )
    .unwrap();

    // Description on its own line, separated by a blank line.
    if !info.std.description.is_empty() {
        writeln!(out, "\n{}", styled(&info.std.description, p.description)).unwrap();
    }

    // Capabilities — one entry per line, with mount-root / other
    // per-capability params rendered inline.
    if !info.std.capabilities.is_empty() {
        writeln!(out, "\n{}", styled("Capabilities:", p.section)).unwrap();
        if let Some(fs) = &info.std.capabilities.filesystem {
            out.push_str("  wasi:filesystem");
            if let Some(root) = &fs.mount_root {
                write!(out, " {}", styled(&format!("(mount-root: {root})"), p.dim)).unwrap();
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
            write!(out, "  {id}").unwrap();
            if let serde_json::Value::Object(map) = params
                && !map.is_empty()
            {
                let pairs: Vec<String> = map
                    .iter()
                    .map(|(k, v)| match v {
                        serde_json::Value::String(s) => format!("{k}: {s}"),
                        other => format!("{k}: {other}"),
                    })
                    .collect();
                write!(
                    out,
                    " {}",
                    styled(&format!("({})", pairs.join(", ")), p.dim)
                )
                .unwrap();
            }
            out.push('\n');
        }
    }

    // Skill
    if let Some(skill) = info.extra.get("std:skill").and_then(|v| v.as_str()) {
        writeln!(out, "\n{}", styled("Skill:", p.section)).unwrap();
        out.push_str(skill);
        if !skill.ends_with('\n') {
            out.push('\n');
        }
    }

    // Metadata schema — raw JSON block under a section label.
    if let Some(schema_str) = &data.metadata_schema {
        writeln!(out, "\n{}", styled("Metadata Schema:", p.section)).unwrap();
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(schema_str) {
            out.push_str(&serde_json::to_string_pretty(&v).unwrap_or_else(|_| schema_str.clone()));
        } else {
            out.push_str(schema_str);
        }
        out.push('\n');
    }

    // Tools.
    if let Some(tools) = &data.tools
        && !tools.is_empty()
    {
        writeln!(out, "\n{}", styled("Tools:", p.section)).unwrap();
        for td in tools {
            out.push('\n');
            out.push_str(&tool_to_text(td, &p));
        }
    }

    out
}

fn tool_to_text(td: &crate::runtime::act::core::types::ToolDefinition, p: &Palette) -> String {
    let mut out = String::new();
    let meta = Metadata::from(td.metadata.clone());
    let desc = LocalizedString::from(&td.description);

    let styled = |value: &str, style: Style| {
        value
            .if_supports_color(Stream::Stdout, move |s| s.style(style))
            .to_string()
    };

    // Tool name + annotations on one line.
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
    write!(out, "{}", styled(&td.name, p.tool_name)).unwrap();
    if !annotations.is_empty() {
        write!(
            out,
            " {}",
            styled(&format!("[{}]", annotations.join(", ")), p.annotation),
        )
        .unwrap();
    }
    out.push('\n');

    // Indented description.
    let desc_text = desc.any_text();
    if !desc_text.is_empty() {
        writeln!(out, "  {desc_text}").unwrap();
    }

    // Extras: timeout, tags, usage hints, parameters.
    let mut opened_extras = false;
    let ensure_blank = |out: &mut String, opened: &mut bool| {
        if !*opened {
            out.push('\n');
            *opened = true;
        }
    };

    if let Some(ms) = meta.get_as::<u64>(META_TIMEOUT_MS) {
        ensure_blank(&mut out, &mut opened_extras);
        writeln!(out, "  {} {ms}ms", styled("Timeout:", p.section)).unwrap();
    }
    let tags: Vec<String> = meta.get_as::<Vec<String>>(META_TAGS).unwrap_or_default();
    if !tags.is_empty() {
        ensure_blank(&mut out, &mut opened_extras);
        writeln!(out, "  {} {}", styled("Tags:", p.section), tags.join(", ")).unwrap();
    }
    if let Some(hint) = meta.get_as::<String>(META_USAGE_HINTS) {
        ensure_blank(&mut out, &mut opened_extras);
        writeln!(out, "  {} {hint}", styled("When to use:", p.section)).unwrap();
    }
    if let Some(hint) = meta.get_as::<String>(META_ANTI_USAGE_HINTS) {
        ensure_blank(&mut out, &mut opened_extras);
        writeln!(out, "  {} {hint}", styled("When NOT to use:", p.section)).unwrap();
    }

    if let Ok(schema) = serde_json::from_str::<serde_json::Value>(&td.parameters_schema) {
        let params = extract_params(&schema);
        if !params.is_empty() {
            ensure_blank(&mut out, &mut opened_extras);
            writeln!(out, "  {}", styled("Parameters:", p.section)).unwrap();
            for (name, type_str, required, description) in params {
                write!(
                    out,
                    "    {}{}{}",
                    styled(&name, p.param),
                    styled(": ", p.dim),
                    styled(&type_str, p.param_type),
                )
                .unwrap();
                if required {
                    write!(out, " {}", styled("(required)", p.required)).unwrap();
                }
                if let Some(d) = description {
                    write!(out, "{}{d}", styled(" — ", p.dim)).unwrap();
                }
                out.push('\n');
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
            ..Default::default()
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
        assert!(text.contains("component-sqlite"));
        assert!(text.contains("v0.2.0"));
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
        assert!(text.contains("Capabilities:"));
        assert!(text.contains("wasi:filesystem"));
        assert!(text.contains("mount-root: /data"));
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
        assert!(text.contains("Skill:"));
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
        assert!(text.contains("Metadata Schema:"));
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
        assert!(!text.is_empty());
        assert!(json_str.contains("name"));
    }
}
