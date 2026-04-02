use anyhow::{Context, Result, bail};
use std::path::Path;
use wasmparser::{Parser, Payload};

use crate::wasm::read_custom_section;

const ACT_COMPONENT_SECTION: &str = "act:component";
const TOOL_PROVIDER_INTERFACE: &str = "act:core/tool-provider";

/// Validate a WASM component: check the `act:component` custom section and
/// verify the component exports `act:core/tool-provider`.
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
/// containing `"act:core/tool-provider"`.
pub fn check_tool_provider_export(wasm: &[u8]) -> Result<bool> {
    for payload in Parser::new(0).parse_all(wasm) {
        let payload = payload.context("failed to parse WASM payload")?;
        if let Payload::ComponentExportSection(reader) = payload {
            for export in reader {
                let export = export.context("failed to read component export")?;
                if export.name.0.contains(TOOL_PROVIDER_INTERFACE) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}
