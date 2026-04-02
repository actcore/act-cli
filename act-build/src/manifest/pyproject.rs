use std::path::Path;

use act_types::ComponentInfo;
use anyhow::{Context, Result};
use serde::Deserialize;

// ── Serde structs ──

#[derive(Debug, Default, Deserialize)]
struct PyprojectManifest {
    #[serde(default)]
    project: Option<PyprojectProject>,
    #[serde(default)]
    tool: Option<PyprojectTool>,
}

#[derive(Debug, Default, Deserialize)]
struct PyprojectProject {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PyprojectTool {
    #[serde(rename = "act-component", default)]
    act_component: Option<toml::Value>,
}

/// Parse pyproject.toml for base metadata and inline ACT config.
pub fn from_toml(path: &Path) -> Result<(ComponentInfo, Option<toml::Value>)> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let manifest: PyprojectManifest =
        toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;

    let mut info = ComponentInfo::default();
    if let Some(proj) = &manifest.project {
        if let Some(name) = &proj.name {
            info.std.name = name.clone();
        }
        if let Some(version) = &proj.version {
            info.std.version = version.clone();
        }
        if let Some(desc) = &proj.description {
            info.std.description = desc.clone();
        }
    }

    let inline_patch = manifest.tool.and_then(|t| t.act_component);

    Ok((info, inline_patch))
}
