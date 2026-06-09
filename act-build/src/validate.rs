use anyhow::{Context, Result, bail};
use std::path::Path;
use wasmparser::{Parser, Payload};

use crate::wasm::read_custom_section;

const ACT_COMPONENT_SECTION: &str = "act:component";
// The tool-provider interface lives in the `act:tools` package (since the spec
// split `act:core` into types-only + `act:tools`/`act:sessions`). Matched as a
// substring so any version suffix (`@0.1.0`, …) still resolves.
const TOOL_PROVIDER_INTERFACE: &str = "act:tools/tool-provider";

/// Validate a WASM component: check the `act:component` custom section and
/// verify the component exports `act:tools/tool-provider`.
pub fn run(wasm_path: &Path) -> Result<()> {
    let wasm = std::fs::read(wasm_path)
        .with_context(|| format!("failed to read {}", wasm_path.display()))?;

    // Step 1: Check custom section exists and decodes to ComponentInfo.
    let section_data = read_custom_section(&wasm, ACT_COMPONENT_SECTION)
        .with_context(|| "failed to parse WASM custom sections")?;

    let section_data = match section_data {
        Some(data) => data,
        None => bail!(
            "missing `{}` custom section — run `act-build pack` first",
            ACT_COMPONENT_SECTION
        ),
    };

    let info: act_types::ComponentInfo =
        ciborium::from_reader(section_data).with_context(|| {
            format!(
                "`{}` custom section is not valid CBOR",
                ACT_COMPONENT_SECTION
            )
        })?;

    // Step 2: Validate required std fields.
    if info.std.name.is_empty() {
        bail!("`std.name` is empty in component metadata");
    }
    if info.std.version.is_empty() {
        bail!("`std.version` is empty in component metadata");
    }

    // Step 3: Check the component exports `act:core/tool-provider`.
    let has_export =
        check_tool_provider_export(&wasm).context("failed to inspect component export section")?;

    if !has_export {
        bail!(
            "component does not export `{}` — is this a valid ACT component?",
            TOOL_PROVIDER_INTERFACE
        );
    }

    println!(
        "✓ {} {} — valid ACT component",
        info.std.name, info.std.version
    );

    Ok(())
}

/// Return `true` if any export in the component's export section has a name
/// containing `"act:tools/tool-provider"`.
pub fn check_tool_provider_export(wasm: &[u8]) -> Result<bool> {
    for payload in Parser::new(0).parse_all(wasm) {
        let payload = payload.context("failed to parse WASM payload")?;
        if let Payload::ComponentExportSection(reader) = payload {
            for export in reader {
                let export = export.context("failed to read component export")?;
                if export.name.name.contains(TOOL_PROVIDER_INTERFACE) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_encoder::{Component, ComponentExportKind, ComponentExportSection};

    /// The interface string current ACT components actually export. If this ever
    /// changes, `TOOL_PROVIDER_INTERFACE` must change with it — `validate` uses a
    /// substring match, so the constant has to be a substring of this name. This
    /// pins the exact invariant that regressed when the spec moved tool-provider
    /// out of `act:core` into `act:tools`.
    const CURRENT_EXPORT: &str = "act:tools/tool-provider@0.1.0";

    #[test]
    fn constant_matches_current_exported_interface() {
        assert!(
            CURRENT_EXPORT.contains(TOOL_PROVIDER_INTERFACE),
            "validate constant `{TOOL_PROVIDER_INTERFACE}` no longer matches the \
             exported interface `{CURRENT_EXPORT}`"
        );
    }

    /// Build a minimal component whose export section names a single export.
    /// The export index is dangling, but `check_tool_provider_export` only reads
    /// the export *name* (structural parse, no validation), so that is fine.
    fn component_exporting(name: &str) -> Vec<u8> {
        let mut exports = ComponentExportSection::new();
        exports.export(name, ComponentExportKind::Func, 0, None);
        let mut component = Component::new();
        component.section(&exports);
        component.finish()
    }

    #[test]
    fn detects_tool_provider_export() {
        let wasm = component_exporting(CURRENT_EXPORT);
        assert!(check_tool_provider_export(&wasm).unwrap());
    }

    #[test]
    fn ignores_unrelated_export() {
        let wasm = component_exporting("wasi:cli/run@0.2.0");
        assert!(!check_tool_provider_export(&wasm).unwrap());
    }
}
