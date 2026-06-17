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
    /// Tool list from `list-tools`, if requested.
    pub tools: Option<Vec<crate::runtime::exports::act::tools::tool_provider::ToolDefinition>>,
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

/// Build the curated [`InfoJson`] view shared by the JSON and TOON renderers,
/// so both serialize the exact same data shape.
fn build_info_json(data: &InfoData<'_>) -> InfoJson {
    let info = data.info;

    let skill = info
        .extra
        .get("std:skill")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let capabilities = serde_json::to_value(&info.std.capabilities)
        .unwrap_or_else(|_| serde_json::Value::Object(Default::default()));

    let tools_json = data
        .tools
        .as_ref()
        .map(|tools| tools.iter().map(tool_to_json).collect::<Vec<_>>());

    InfoJson {
        name: info.std.name.clone(),
        version: info.std.version.clone(),
        description: info.std.description.clone(),
        default_language: info.std.default_language.clone(),
        capabilities,
        skill,
        tools: tools_json,
    }
}

/// Render [`InfoData`] as a machine-readable JSON string.
pub fn to_json(data: &InfoData<'_>) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(&build_info_json(data))?)
}

/// Render [`InfoData`] as TOON (Token-Oriented Object Notation) — the same
/// curated shape as [`to_json`], serialized in a compact, LLM-friendly
/// encoding that uses ~40% fewer tokens than JSON.
pub fn to_info_toon(data: &InfoData<'_>) -> anyhow::Result<String> {
    to_toon(&build_info_json(data))
}

/// Encode any serializable value as TOON using the spec-default options.
///
/// TOON mirrors the JSON data model: uniform arrays of scalar-only objects
/// collapse into a CSV-like table, nested objects use YAML-style
/// indentation. Used wherever `--format toon` is accepted.
pub fn to_toon<T: Serialize>(value: &T) -> anyhow::Result<String> {
    toon_format::encode_default(value).map_err(|e| anyhow::anyhow!("encoding as TOON: {e}"))
}

/// Render the full decoded `act:component` manifest (`ComponentInfo`,
/// `std` + `extra`) as pretty JSON — the raw, verbatim view behind
/// `act inspect component-manifest`. Unlike [`to_json`], this performs no
/// curation: it is the stable machine contract for registry tooling.
pub fn to_manifest_json(info: &act_types::ComponentInfo) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(info)?)
}

fn tool_to_json(
    td: &crate::runtime::exports::act::tools::tool_provider::ToolDefinition,
) -> ToolJson {
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
    optional: Style,
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
            optional: Style::new().dimmed(),
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

    // Capabilities — one entry per line, with scalar params rendered inline.
    if !info.std.capabilities.is_empty() {
        writeln!(out, "\n{}", styled("Capabilities:", p.section)).unwrap();
        for (id, req) in info.std.capabilities.iter() {
            write!(out, "  {id}").unwrap();
            // Render scalar params inline (e.g. filesystem mount-root).
            if !req.params.is_empty() {
                let pairs: Vec<String> = req
                    .params
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

fn tool_to_text(
    td: &crate::runtime::exports::act::tools::tool_provider::ToolDefinition,
    p: &Palette,
) -> String {
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
                if !required {
                    write!(out, " {}", styled("(optional)", p.optional)).unwrap();
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
        let type_str = type_label(prop);
        let required = required_list.contains(&name.as_str());
        let description = prop
            .get("description")
            .and_then(|d| d.as_str())
            .map(|s| s.to_string());
        result.push((name.clone(), type_str, required, description));
    }

    result
}

/// Derive a human label for a JSON Schema property's type.
///
/// Handles the common shapes schemars emits for Rust types:
/// - scalar `"type": "string"` → `"string"`
/// - nullable `"type": ["integer", "null"]` (schemars' `Option<T>`) → `"integer"`
/// - union `"type": ["string", "integer"]` → `"string|integer"`
/// - `anyOf` / `oneOf` with typed branches → joined types, `"null"` dropped
/// - enum with homogeneous value type → inferred from the first variant
/// - anything else → `"any"`
fn type_label(prop: &serde_json::Value) -> String {
    if let Some(t) = prop.get("type").and_then(|t| t.as_str()) {
        return t.to_string();
    }
    if let Some(types) = prop.get("type").and_then(|t| t.as_array()) {
        let non_null: Vec<&str> = types
            .iter()
            .filter_map(|v| v.as_str())
            .filter(|s| *s != "null")
            .collect();
        if !non_null.is_empty() {
            return non_null.join("|");
        }
    }
    for key in ["anyOf", "oneOf"] {
        if let Some(arr) = prop.get(key).and_then(|v| v.as_array()) {
            let types: Vec<String> = arr
                .iter()
                .filter_map(|sub| sub.get("type").and_then(|t| t.as_str()).map(String::from))
                .filter(|s| s != "null")
                .collect();
            if !types.is_empty() {
                return types.join("|");
            }
        }
    }
    if let Some(first) = prop
        .get("enum")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
    {
        return match first {
            serde_json::Value::String(_) => "string".into(),
            serde_json::Value::Number(_) => "number".into(),
            serde_json::Value::Bool(_) => "boolean".into(),
            _ => "any".into(),
        };
    }
    "any".to_string()
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use act_types::types::ComponentInfo;

    fn sample_info() -> ComponentInfo {
        let mut info = ComponentInfo::new("component-sqlite", "0.2.0", "SQLite database access");
        info.std.default_language = Some("en".to_string());
        info.std.capabilities.0.insert(
            "wasi:filesystem".to_string(),
            act_types::CapabilityRequest {
                params: std::collections::BTreeMap::from([(
                    "mount-root".to_string(),
                    serde_json::json!("/data"),
                )]),
                ..Default::default()
            },
        );
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
            tools: None,
        };
        let text = to_text(&data);
        assert!(text.contains("Skill:"));
        assert!(text.contains("Use this component for database operations..."));
    }

    #[test]
    fn json_output_basic() {
        let info = sample_info();
        let data = InfoData {
            info: &info,
            tools: None,
        };
        let json_str = to_json(&data).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(v["name"], "component-sqlite");
        assert_eq!(v["version"], "0.2.0");
        assert_eq!(v["description"], "SQLite database access");
        assert_eq!(v["skill"], "Use this component for database operations...");
        assert_eq!(
            v["capabilities"]["wasi:filesystem"]["params"]["mount-root"],
            "/data"
        );
    }

    #[test]
    fn type_label_scalar() {
        let prop = serde_json::json!({"type": "string"});
        assert_eq!(type_label(&prop), "string");
    }

    #[test]
    fn type_label_nullable_from_schemars() {
        // schemars emits this shape for Option<T>.
        let prop = serde_json::json!({"type": ["integer", "null"]});
        assert_eq!(type_label(&prop), "integer");
    }

    #[test]
    fn type_label_union() {
        let prop = serde_json::json!({"type": ["string", "integer"]});
        assert_eq!(type_label(&prop), "string|integer");
    }

    #[test]
    fn type_label_anyof_with_null() {
        let prop = serde_json::json!({
            "anyOf": [{"type": "string"}, {"type": "null"}]
        });
        assert_eq!(type_label(&prop), "string");
    }

    #[test]
    fn type_label_enum_inferred() {
        let prop = serde_json::json!({"enum": ["a", "b", "c"]});
        assert_eq!(type_label(&prop), "string");
    }

    #[test]
    fn type_label_missing_is_any() {
        let prop = serde_json::json!({});
        assert_eq!(type_label(&prop), "any");
    }

    #[test]
    fn empty_info_no_panic() {
        let info = ComponentInfo::default();
        let data = InfoData {
            info: &info,
            tools: None,
        };
        let text = to_text(&data);
        let json_str = to_json(&data).unwrap();
        // Should not panic, produce some output
        assert!(!text.is_empty());
        assert!(json_str.contains("name"));
    }

    #[test]
    fn manifest_json_includes_std_and_extra() {
        let mut info = ComponentInfo::new("demo", "1.2.3", "desc");
        info.extra
            .insert("vendor:thing".to_string(), serde_json::json!({ "k": "v" }));

        let s = to_manifest_json(&info).expect("render");
        let v: serde_json::Value = serde_json::from_str(&s).expect("valid JSON");

        assert_eq!(v["std"]["name"], "demo");
        assert_eq!(v["std"]["version"], "1.2.3");
        // `extra` is flattened to the top level of ComponentInfo.
        assert_eq!(v["vendor:thing"]["k"], "v");
    }

    #[test]
    fn info_toon_basic() {
        let info = sample_info();
        let data = InfoData {
            info: &info,
            tools: None,
        };
        let toon = to_info_toon(&data).expect("render TOON");
        // YAML-style scalar lines for the top-level fields. The spec-compliant
        // encoder quotes values that would otherwise be ambiguous (hyphens,
        // digit-leading version strings), so match on the key + value loosely.
        assert!(toon.contains("name:"), "{toon}");
        assert!(toon.contains("component-sqlite"), "{toon}");
        assert!(toon.contains("0.2.0"), "{toon}");
    }

    #[test]
    fn info_toon_round_trips_to_same_shape() {
        let info = sample_info();
        let data = InfoData {
            info: &info,
            tools: None,
        };
        let toon = to_info_toon(&data).expect("render TOON");
        let decoded: serde_json::Value = toon_format::decode_default(&toon).expect("decode TOON");
        let expected = serde_json::to_value(build_info_json(&data)).expect("to_value");
        assert_eq!(decoded, expected);
    }

    #[test]
    fn manifest_toon_round_trips() {
        let mut info = ComponentInfo::new("demo", "1.2.3", "desc");
        info.extra
            .insert("vendor:thing".to_string(), serde_json::json!({ "k": "v" }));

        let toon = to_toon(&info).expect("render TOON");
        let decoded: serde_json::Value = toon_format::decode_default(&toon).expect("decode TOON");
        let expected = serde_json::to_value(&info).expect("to_value");
        assert_eq!(decoded, expected);
    }

    #[test]
    fn to_toon_uniform_array_is_tabular() {
        // A list of objects whose fields are all scalars collapses into
        // TOON's CSV-like tabular form — this is the `store list` case.
        let rows = serde_json::json!([
            { "ref": "a.wasm", "version": "0.1.0" },
            { "ref": "b.wasm", "version": "0.2.0" },
        ]);
        let toon = to_toon(&rows).expect("render TOON");
        // `[2]{ref,version}:` header declares length + fields once, then one
        // comma-separated row per element (values may be quoted).
        assert!(toon.contains("[2]{"), "{toon}");
        assert!(toon.contains("ref"), "{toon}");
        assert!(toon.contains("a.wasm,"), "{toon}");
    }
}
