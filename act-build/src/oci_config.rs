//! Generate `application/vnd.wasm.config.v0+json` config blob per the
//! CNCF TAG-Runtime Wasm OCI Artifact specification.
//!
//! See: <https://tag-runtime.cncf.io/wgs/wasm/deliverables/wasm-oci-artifact/>

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use wasmparser::{Parser, Payload};

pub const WASM_CONFIG_MEDIA_TYPE: &str = "application/vnd.wasm.config.v0+json";
pub const WASM_LAYER_MEDIA_TYPE: &str = "application/wasm";

/// Wasm OCI Artifact config schema (`application/vnd.wasm.config.v0+json`).
#[derive(Debug, Serialize)]
pub struct WasmConfig {
    pub architecture: &'static str,
    pub os: &'static str,
    #[serde(rename = "layerDigests")]
    pub layer_digests: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<WasmComponentConfig>,
}

#[derive(Debug, Serialize)]
pub struct WasmComponentConfig {
    pub exports: Vec<String>,
    pub imports: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

/// Compute the `sha256:HEX` digest of arbitrary bytes (OCI digest format).
pub fn sha256_digest(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hex: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("sha256:{hex}")
}

/// Build a CNCF-conformant config blob for a single-layer Wasm artifact.
///
/// The `architecture` is fixed to `"wasm"`. The `os` is `"wasip2"` for
/// components and `"wasip1"` for modules — detected from the WASM header.
/// `component.{exports,imports}` are extracted from the component's
/// top-level export/import sections (interface URIs like
/// `act:tools/tool-provider@0.1.0`).
pub fn build_config(wasm: &[u8]) -> Result<WasmConfig> {
    let layer_digest = sha256_digest(wasm);
    let layer_digests = vec![layer_digest];

    let (os, component) = inspect_wasm(wasm)?;

    Ok(WasmConfig {
        architecture: "wasm",
        os,
        layer_digests,
        component,
    })
}

/// Walk the WASM payloads. Returns `(os_string, component_section)`:
/// - `wasip2` + `Some(component)` for components (layer 0x0d)
/// - `wasip1` + `None` for core modules
fn inspect_wasm(wasm: &[u8]) -> Result<(&'static str, Option<WasmComponentConfig>)> {
    if wasm.len() < 8 || &wasm[0..4] != b"\0asm" {
        anyhow::bail!("not a valid WASM file");
    }
    // Layer byte: 0x01 = core module, 0x0d = component.
    let is_component = wasm[4] == 0x0d;
    if !is_component {
        return Ok(("wasip1", None));
    }

    let mut exports: Vec<String> = Vec::new();
    let mut imports: Vec<String> = Vec::new();

    for payload in Parser::new(0).parse_all(wasm) {
        let payload = payload.context("parsing WASM payload")?;
        match payload {
            Payload::ComponentExportSection(reader) => {
                for export in reader {
                    let export = export.context("reading component export")?;
                    exports.push(export.name.name.to_string());
                }
            }
            Payload::ComponentImportSection(reader) => {
                for import in reader {
                    let import = import.context("reading component import")?;
                    imports.push(import.name.name.to_string());
                }
            }
            _ => {}
        }
    }

    exports.sort();
    exports.dedup();
    imports.sort();
    imports.dedup();

    Ok((
        "wasip2",
        Some(WasmComponentConfig {
            exports,
            imports,
            target: None,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_encoder::Component;

    #[test]
    fn sha256_matches_known_vector() {
        // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(
            sha256_digest(b"hello"),
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn config_for_minimal_component() {
        let wasm = Component::new().finish();
        let config = build_config(&wasm).unwrap();
        assert_eq!(config.architecture, "wasm");
        assert_eq!(config.os, "wasip2");
        assert_eq!(config.layer_digests.len(), 1);
        assert!(config.layer_digests[0].starts_with("sha256:"));
        let comp = config.component.expect("component section present");
        assert!(comp.exports.is_empty());
        assert!(comp.imports.is_empty());
    }

    #[test]
    fn config_serializes_with_camelcase_layerdigests() {
        let wasm = Component::new().finish();
        let config = build_config(&wasm).unwrap();
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"layerDigests\""));
        assert!(json.contains("\"architecture\":\"wasm\""));
        assert!(json.contains("\"os\":\"wasip2\""));
    }

    #[test]
    fn rejects_non_wasm_bytes() {
        let result = build_config(b"not wasm");
        assert!(result.is_err());
    }

    #[test]
    fn core_module_is_wasip1_no_component() {
        // Core module header: \0asm + version 0x01 0x00 0x00 0x00
        let core_module = b"\0asm\x01\x00\x00\x00";
        let config = build_config(core_module).unwrap();
        assert_eq!(config.os, "wasip1");
        assert!(config.component.is_none());
    }
}
