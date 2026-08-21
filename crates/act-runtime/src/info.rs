//! Reading `act:component` out of a wasm binary, and the error type every
//! call surface returns.

use anyhow::Result;

use crate::act;

pub use act_types::ComponentInfo;
/// Read component info from the `act:component` custom section (CBOR-encoded)
/// and standard WASM metadata sections (`version`, `description`) as fallback.
pub fn read_component_info(component_bytes: &[u8]) -> Result<ComponentInfo> {
    let mut info = ComponentInfo::default();

    for payload in wasmparser::Parser::new(0).parse_all(component_bytes) {
        if let Ok(wasmparser::Payload::CustomSection(section)) = payload {
            match section.name() {
                act_types::constants::SECTION_ACT_COMPONENT => {
                    info = ciborium::from_reader(section.data())
                        .map_err(|e| anyhow::anyhow!("failed to decode act:component CBOR: {e}"))?;
                }
                "version" if info.std.version.is_empty() => {
                    info.std.version = String::from_utf8_lossy(section.data()).into_owned();
                }
                "description" if info.std.description.is_empty() => {
                    info.std.description = String::from_utf8_lossy(section.data()).into_owned();
                }
                _ => {}
            }
        }
    }

    if info.std.name.is_empty() {
        info.std.name = "unknown".to_string();
    }

    Ok(info)
}

// ── Conversion helpers ──
impl From<&act::core::types::LocalizedString> for act_types::types::LocalizedString {
    fn from(ls: &act::core::types::LocalizedString) -> Self {
        match ls {
            act::core::types::LocalizedString::Plain(s) => Self::Plain(s.clone()),
            act::core::types::LocalizedString::Localized(pairs) => Self::from(pairs.clone()),
        }
    }
}

// ── Actor types ──
/// Errors from component calls.
///
/// The split is what a host has to act on: [`Self::Tool`] is the component
/// answering — it ran, and it said no — while [`Self::Internal`] is the host
/// failing to run it at all. Reporting one as the other is how a sandbox
/// failure comes to look like a tool's opinion.
#[derive(Debug)]
pub enum ComponentError {
    /// Structured tool error from the component (has kind, message, metadata).
    Tool(act::core::types::Error),
    /// Infrastructure error (wasmtime, actor channel, etc.).
    Internal(anyhow::Error),
}

impl std::fmt::Display for ComponentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Same shape the CLI has always printed: the guest's kind, then
            // whichever localization of its message is available.
            Self::Tool(e) => {
                let message = act_types::types::LocalizedString::from(&e.message);
                write!(f, "{}: {}", e.kind, message.any_text())
            }
            Self::Internal(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ComponentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Tool(_) => None,
            Self::Internal(e) => Some(e.as_ref()),
        }
    }
}
