use std::path::Path;

use act_types::ComponentInfo;
use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
struct PackageJson {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    act: Option<serde_json::Value>,
}

/// Parse package.json for base metadata and inline ACT config.
pub fn from_json(path: &Path) -> Result<(ComponentInfo, Option<serde_json::Value>)> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let manifest: PackageJson =
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;

    let mut info = ComponentInfo::default();
    if let Some(name) = &manifest.name {
        info.std.name = name.clone();
    }
    if let Some(version) = &manifest.version {
        info.std.version = version.clone();
    }
    if let Some(desc) = &manifest.description {
        info.std.description = desc.clone();
    }

    Ok((info, manifest.act))
}
