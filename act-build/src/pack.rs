use anyhow::{Context, Result};
use std::path::Path;
use tracing::info;

/// Orchestrate the full pack pipeline: embed `act:component`, WASM metadata,
/// and optionally `act:skill` into a compiled WASM component.
pub fn run(wasm_path: &Path) -> Result<()> {
    // 1. Find project directory — walk up from wasm_path's parent to find a
    //    directory containing act.toml, Cargo.toml, or pyproject.toml.
    let project_dir = find_project_dir(wasm_path)?;
    info!(dir = %project_dir.display(), "found project directory");

    // 2. Resolve metadata via merge-patch (act.toml / Cargo.toml / pyproject.toml).
    let component_info =
        crate::manifest::resolve(&project_dir).context("resolving component metadata")?;
    info!(
        name = %component_info.std.name,
        version = %component_info.std.version,
        "resolved component metadata"
    );

    // 3. Validate capability declarations before touching the WASM file.
    crate::manifest::validate::validate(&component_info.std.capabilities)
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
