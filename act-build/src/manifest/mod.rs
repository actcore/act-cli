mod cargo;
mod packagejson;
mod pyproject;
pub mod validate;

use std::path::Path;

use act_types::ComponentInfo;
use anyhow::{Context, Result};

/// Resolve ACT component metadata from the project directory using merge-patch.
///
/// Resolution order (each layer patches the previous):
/// 1. **Base** from language manifest (`Cargo.toml`, `pyproject.toml`, or `package.json`):
///    `name`, `version`, `description` map to `std.*`.
/// 2. **Inline patch** from the same manifest:
///    `[package.metadata.act]` (Rust), `[tool.act]` (Python),
///    or `act` (JS/TS).
/// 3. **`act.toml`** — highest priority, applied last.
///
/// For Rust projects, tries `cargo metadata` first (resolves workspace inheritance),
/// falls back to raw TOML parsing if `cargo` is not available.
pub fn resolve(dir: &Path) -> Result<ComponentInfo> {
    let mut info: Option<ComponentInfo> = None;

    // --- Layer 1 + 2: language manifest ---
    let cargo_path = dir.join("Cargo.toml");
    let pyproject_path = dir.join("pyproject.toml");

    if cargo_path.exists() {
        let (base, inline_patch) = match cargo::from_cargo_metadata(dir) {
            Ok(result) => result,
            Err(_) => {
                tracing::debug!("cargo metadata failed, falling back to raw TOML parsing");
                cargo::from_toml(&cargo_path)?
            }
        };
        info = Some(base);

        if let Some(patch_val) = inline_patch {
            let patch_json = serde_json::to_value(&patch_val)?;
            info = Some(apply_merge_patch(info.unwrap(), &patch_json)?);
        }
    } else if pyproject_path.exists() {
        let (base, inline_patch) = pyproject::from_toml(&pyproject_path)?;
        info = Some(base);

        if let Some(patch_val) = inline_patch {
            let patch_json = serde_json::to_value(&patch_val)?;
            info = Some(apply_merge_patch(info.unwrap(), &patch_json)?);
        }
    } else if dir.join("package.json").exists() {
        let (base, inline_patch) = packagejson::from_json(&dir.join("package.json"))?;
        info = Some(base);

        if let Some(patch_val) = inline_patch {
            info = Some(apply_merge_patch(info.unwrap(), &patch_val)?);
        }
    }

    // --- Layer 3: act.toml ---
    let act_toml_path = dir.join("act.toml");
    if act_toml_path.exists() {
        let raw = std::fs::read_to_string(&act_toml_path)
            .with_context(|| format!("reading {}", act_toml_path.display()))?;
        let doc: toml::Value =
            toml::from_str(&raw).with_context(|| format!("parsing {}", act_toml_path.display()))?;
        let patch_json = serde_json::to_value(&doc)?;

        match info {
            Some(existing) => info = Some(apply_merge_patch(existing, &patch_json)?),
            None => {
                info = Some(serde_json::from_value(patch_json).context("deserializing act.toml")?);
            }
        }
    }

    info.ok_or_else(|| {
        anyhow::anyhow!(
            "no component metadata found in {}; expected Cargo.toml, pyproject.toml, or act.toml",
            dir.display()
        )
    })
}

/// Apply RFC 7396 JSON Merge Patch: serialize base to JSON, merge patch, deserialize back.
fn apply_merge_patch(base: ComponentInfo, patch: &serde_json::Value) -> Result<ComponentInfo> {
    let mut base_json = serde_json::to_value(&base).context("serializing base to JSON")?;
    json_patch::merge(&mut base_json, patch);
    serde_json::from_value(base_json).context("deserializing merged metadata")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn act_toml_standalone() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("act.toml"),
            "[std]\nname = \"my-component\"\nversion = \"1.0.0\"\ndescription = \"A standalone component\"\n",
        ).unwrap();

        let info = resolve(dir.path()).unwrap();
        assert_eq!(info.std.name, "my-component");
        assert_eq!(info.std.version, "1.0.0");
        assert_eq!(info.std.description, "A standalone component");
    }

    #[test]
    fn cargo_toml_base_with_act_toml_patch() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"my-crate\"\nversion = \"0.2.0\"\nedition = \"2024\"\ndescription = \"A Rust component\"\n",
        ).unwrap();
        fs::write(
            dir.path().join("act.toml"),
            "[std.capabilities.\"wasi:http\"]\n",
        )
        .unwrap();

        let info = resolve(dir.path()).unwrap();
        assert_eq!(info.std.name, "my-crate");
        assert_eq!(info.std.version, "0.2.0");
        assert_eq!(info.std.description, "A Rust component");
        assert!(info.std.capabilities.has("wasi:http"));
    }

    #[test]
    fn cargo_toml_inline_metadata() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"inline-test\"\nversion = \"0.3.0\"\nedition = \"2024\"\ndescription = \"Inline metadata test\"\n\n[package.metadata.act.std.capabilities.\"wasi:http\"]\n",
        ).unwrap();

        let info = resolve(dir.path()).unwrap();
        assert_eq!(info.std.name, "inline-test");
        assert_eq!(info.std.version, "0.3.0");
        assert!(info.std.capabilities.has("wasi:http"));
    }

    #[test]
    fn pyproject_toml_base_with_inline() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname = \"py-component\"\nversion = \"0.1.0\"\ndescription = \"A Python component\"\n\n[tool.act.std.capabilities.\"wasi:filesystem\"]\n",
        ).unwrap();

        let info = resolve(dir.path()).unwrap();
        assert_eq!(info.std.name, "py-component");
        assert_eq!(info.std.version, "0.1.0");
        assert_eq!(info.std.description, "A Python component");
        assert!(info.std.capabilities.has("wasi:filesystem"));
    }

    #[test]
    fn no_metadata_is_error() {
        let dir = TempDir::new().unwrap();
        let result = resolve(dir.path());
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("no component metadata found")
        );
    }

    /// Resolve an `act.toml`-only project through the same resolve + validate
    /// pipeline `pack::run` uses, for tests that only care about that layer.
    fn parse_act_toml(act_toml_src: &str) -> Result<ComponentInfo> {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("act.toml"), act_toml_src).unwrap();
        let info = resolve(dir.path())?;
        validate::validate(&info.std.capabilities, &info.std.credentials)?;
        Ok(info)
    }

    #[test]
    fn credentials_are_packed_from_act_toml() {
        let info = parse_act_toml(
            r#"
[std.capabilities."act:credentials"]

[[std.credentials]]
key = "default"

[[std.credentials.fields]]
key = "acme:tenant"
label = "Tenant"
type = "std:string"
secret = false
"#,
        )
        .expect("parses");
        let c = &info.std.credentials[0];
        assert_eq!(c.key, "default");
        assert_eq!(c.fields[0].key, "acme:tenant");
        assert_eq!(c.fields[0].field_type, "std:string");
        assert!(!c.fields[0].secret);
        assert!(c.fields[0].required, "required defaults to true");
    }

    #[test]
    fn declaring_credentials_without_the_capability_is_rejected() {
        // The authoring mistake this check exists for: the credential is
        // provisioned correctly, and the component is then denied at runtime
        // for a reason neither the user nor the author can see.
        let err = parse_act_toml(
            r#"
[[std.credentials]]
key = "default"
"#,
        )
        .expect_err("must not pack");
        let msg = err.to_string();
        assert!(
            msg.contains("act:credentials") && msg.contains("capabilit"),
            "the error must name what to add: {msg}"
        );
    }
}
