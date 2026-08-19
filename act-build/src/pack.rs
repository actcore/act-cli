use anyhow::{Context, Result};
use std::path::Path;
use tracing::info;

/// Apply `--set <dotted.key>=<value>` overrides to resolved component metadata.
/// Each value is set as a JSON string at the dotted path (e.g. `std.name`).
fn apply_overrides(
    info: act_types::ComponentInfo,
    overrides: &[String],
) -> anyhow::Result<act_types::ComponentInfo> {
    if overrides.is_empty() {
        return Ok(info);
    }
    let mut value = serde_json::to_value(&info).context("serializing ComponentInfo to JSON")?;
    for ov in overrides {
        let (key, val) = ov
            .split_once('=')
            .with_context(|| format!("--set expects KEY=VALUE, got '{ov}'"))?;
        if key.is_empty() || key.starts_with('.') || key.ends_with('.') || key.contains("..") {
            anyhow::bail!(
                "--set key must be a non-empty dotted path with no empty segments, got '{key}'"
            );
        }
        let path: Vec<&str> = key.split('.').collect();
        set_json_path(
            &mut value,
            &path,
            serde_json::Value::String(val.to_string()),
        )
        .with_context(|| format!("applying --set '{ov}'"))?;
    }
    serde_json::from_value(value).context("--set overrides produced invalid component metadata")
}

/// Set `leaf` at the dotted `path` inside `value`, creating intermediate objects.
fn set_json_path(
    value: &mut serde_json::Value,
    path: &[&str],
    leaf: serde_json::Value,
) -> anyhow::Result<()> {
    let (head, rest) = path.split_first().context("empty --set key")?;
    let obj = value
        .as_object_mut()
        .context("--set key traverses a non-object")?;
    if rest.is_empty() {
        obj.insert((*head).to_string(), leaf);
    } else {
        let child = obj
            .entry((*head).to_string())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        set_json_path(child, rest, leaf)?;
    }
    Ok(())
}

/// Orchestrate the full pack pipeline: embed `act:component`, WASM metadata,
/// and optionally `act:skill` into a compiled WASM component.
pub fn run(wasm_path: &Path, overrides: &[String]) -> Result<()> {
    // 1. Find project directory — walk up from wasm_path's parent to find a
    //    directory containing act.toml, Cargo.toml, or pyproject.toml.
    let project_dir = find_project_dir(wasm_path)?;
    info!(dir = %project_dir.display(), "found project directory");

    // 2. Resolve metadata via merge-patch (act.toml / Cargo.toml / pyproject.toml).
    let component_info =
        crate::manifest::resolve(&project_dir).context("resolving component metadata")?;

    // 2b. Apply --set overrides (e.g. feature-conditional name).
    let component_info = apply_overrides(component_info, overrides)?;

    info!(
        name = %component_info.std.name,
        version = %component_info.std.version,
        "resolved component metadata"
    );

    // 3. Validate capability declarations before touching the WASM file.
    crate::manifest::validate::validate(
        &component_info.std.capabilities,
        &component_info.std.credentials,
    )
    .context("capability declarations failed validation")?;

    // 4. Read WASM file.
    let mut wasm = std::fs::read(wasm_path)
        .with_context(|| format!("reading WASM file {}", wasm_path.display()))?;
    info!(bytes = wasm.len(), "read WASM file");

    // 5. Embed act:component — serialize ComponentInfo as CBOR.
    let mut cbor_buf = Vec::new();
    ciborium::into_writer(&component_info, &mut cbor_buf)
        .context("serializing ComponentInfo to CBOR")?;
    wasm = crate::wasm::set_custom_section(&wasm, "act:component", &cbor_buf)
        .context("embedding act:component custom section")?;
    info!(
        cbor_bytes = cbor_buf.len(),
        "embedded act:component section"
    );

    // 6. Add WASM metadata as custom sections — version and description.
    if !component_info.std.version.is_empty() {
        wasm = crate::wasm::set_custom_section(
            &wasm,
            "version",
            component_info.std.version.as_bytes(),
        )
        .context("embedding version custom section")?;
        info!(version = %component_info.std.version, "embedded version section");
    }

    if !component_info.std.description.is_empty() {
        wasm = crate::wasm::set_custom_section(
            &wasm,
            "description",
            component_info.std.description.as_bytes(),
        )
        .context("embedding description custom section")?;
        info!("embedded description section");
    }

    // 7. Embed act:skill — pack skill/ directory into tar if it exists.
    match crate::skill::pack_skill_dir(&project_dir).context("packing skill directory")? {
        Some(tar_bytes) => {
            wasm = crate::wasm::set_custom_section(&wasm, "act:skill", &tar_bytes)
                .context("embedding act:skill custom section")?;
            info!(tar_bytes = tar_bytes.len(), "embedded act:skill section");
        }
        None => {
            info!("no skill/ directory found, skipping act:skill");
        }
    }

    // 8. Write back.
    std::fs::write(wasm_path, &wasm)
        .with_context(|| format!("writing WASM file {}", wasm_path.display()))?;
    info!(bytes = wasm.len(), path = %wasm_path.display(), "wrote packed WASM component");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use act_types::ComponentInfo;

    fn info(json: serde_json::Value) -> ComponentInfo {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn set_overrides_std_name_and_preserves_others() {
        let i = info(serde_json::json!({
            "std": {"name": "sqlite", "version": "0.4.0", "description": "SQLite ops"}
        }));
        let out = apply_overrides(i, &["std.name=sqlite-vec".to_string()]).unwrap();
        assert_eq!(out.std.name, "sqlite-vec");
        assert_eq!(out.std.version, "0.4.0");
        assert_eq!(out.std.description, "SQLite ops");
    }

    #[test]
    fn set_multiple_overrides() {
        let i = info(serde_json::json!({"std": {"name": "a", "version": "1.0.0"}}));
        let out = apply_overrides(
            i,
            &["std.name=b".to_string(), "std.description=two".to_string()],
        )
        .unwrap();
        assert_eq!(out.std.name, "b");
        assert_eq!(out.std.description, "two");
    }

    #[test]
    fn set_requires_key_equals_value() {
        let i = info(serde_json::json!({"std": {}}));
        assert!(apply_overrides(i, &["std.name".to_string()]).is_err());
    }

    #[test]
    fn empty_overrides_is_identity() {
        let i = info(serde_json::json!({"std": {"name": "x"}}));
        let out = apply_overrides(i, &[]).unwrap();
        assert_eq!(out.std.name, "x");
    }

    #[test]
    fn set_rejects_empty_key() {
        let i = info(serde_json::json!({"std": {}}));
        assert!(apply_overrides(i, &["=x".to_string()]).is_err());
    }

    #[test]
    fn set_rejects_trailing_dot() {
        let i = info(serde_json::json!({"std": {}}));
        assert!(apply_overrides(i, &["std.=x".to_string()]).is_err());
    }

    #[test]
    fn set_value_may_contain_equals() {
        let i = info(serde_json::json!({"std": {"name": "a"}}));
        let out = apply_overrides(i, &["std.description=a=b".to_string()]).unwrap();
        assert_eq!(out.std.description, "a=b");
    }
}

/// Walk up from `wasm_path`'s parent directory to find a project root containing
/// `act.toml`, `Cargo.toml`, or `pyproject.toml`. Falls back to the current
/// working directory.
fn find_project_dir(wasm_path: &Path) -> Result<std::path::PathBuf> {
    let start = wasm_path
        .parent()
        .and_then(|p| std::fs::canonicalize(p).ok())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    let mut dir = start.as_path();
    loop {
        if dir.join("act.toml").exists()
            || dir.join("Cargo.toml").exists()
            || dir.join("pyproject.toml").exists()
        {
            return Ok(dir.to_path_buf());
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => break,
        }
    }

    // Fall back to current working directory.
    let cwd = std::env::current_dir().context("getting current working directory")?;
    info!(
        cwd = %cwd.display(),
        "no project manifest found walking up from WASM path, using current directory"
    );
    Ok(cwd)
}
