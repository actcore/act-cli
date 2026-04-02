use std::path::Path;

use act_types::ComponentInfo;
use anyhow::{Context, Result};
use serde::Deserialize;

// ── Serde structs ──

#[derive(Debug, Default, Deserialize)]
struct CargoManifest {
    #[serde(default)]
    package: Option<CargoPackage>,
}

#[derive(Debug, Default, Deserialize)]
struct CargoPackage {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    metadata: Option<CargoMetadata>,
}

#[derive(Debug, Default, Deserialize)]
struct CargoMetadata {
    #[serde(rename = "act-component", default)]
    act_component: Option<toml::Value>,
}

// ── cargo metadata (preferred) ──

/// Use `cargo metadata` to resolve package info (handles workspace inheritance).
pub fn from_cargo_metadata(dir: &Path) -> Result<(ComponentInfo, Option<toml::Value>)> {
    let output = std::process::Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version=1"])
        .current_dir(dir)
        .output()
        .context("running cargo metadata")?;

    if !output.status.success() {
        anyhow::bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("parsing cargo metadata output")?;

    let packages = metadata["packages"]
        .as_array()
        .context("no packages in cargo metadata")?;

    let manifest_path = dir.join("Cargo.toml").canonicalize().ok();
    let pkg = packages
        .iter()
        .find(|p| {
            p["manifest_path"]
                .as_str()
                .and_then(|s| Path::new(s).canonicalize().ok())
                == manifest_path
        })
        .or_else(|| packages.first())
        .context("no matching package found")?;

    let mut info = ComponentInfo::default();
    if let Some(name) = pkg["name"].as_str() {
        info.std.name = name.to_string();
    }
    if let Some(version) = pkg["version"].as_str() {
        info.std.version = version.to_string();
    }
    if let Some(desc) = pkg["description"].as_str() {
        info.std.description = desc.to_string();
    }

    // cargo metadata returns JSON — convert to toml::Value for consistency.
    let inline_patch = pkg
        .get("metadata")
        .and_then(|m| m.get("act-component"))
        .and_then(|v| toml::Value::try_from(v.clone()).ok());

    Ok((info, inline_patch))
}

// ── Raw TOML fallback ──

/// Parse Cargo.toml directly (no workspace resolution).
pub fn from_toml(path: &Path) -> Result<(ComponentInfo, Option<toml::Value>)> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let manifest: CargoManifest =
        toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;

    let mut info = ComponentInfo::default();
    if let Some(pkg) = &manifest.package {
        if let Some(name) = &pkg.name {
            info.std.name = name.clone();
        }
        if let Some(version) = &pkg.version {
            info.std.version = version.clone();
        }
        if let Some(desc) = &pkg.description {
            info.std.description = desc.clone();
        }
    }

    let inline_patch = manifest
        .package
        .and_then(|p| p.metadata)
        .and_then(|m| m.act_component);

    Ok((info, inline_patch))
}
