use crate::runtime;
use rmcp::ServerHandler;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};

#[allow(dead_code)]
pub struct ActRmcpBridge {
    pub handle: runtime::ComponentHandle,
    pub info: runtime::ComponentInfo,
    pub metadata: runtime::Metadata,
    pub metadata_schema: Option<String>,
}

impl ServerHandler for ActRmcpBridge {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_server_info(
            Implementation::new(self.info.std.name.clone(), self.info.std.version.clone()),
        )
    }
}

use act_types::cbor;
use act_types::constants::{ERR_CAPABILITY_DENIED, ERR_INVALID_ARGS, ERR_NOT_FOUND};
use rmcp::ErrorData;
use rmcp::model::{Content, ErrorCode};
use serde_json::Value;

#[allow(dead_code)]
fn map_content_part(part: &runtime::act::core::types::ContentPart) -> Content {
    let mime = part.mime_type.as_deref().unwrap_or("");

    if mime.starts_with("text/") {
        let text = String::from_utf8_lossy(&part.data).into_owned();
        return Content::text(text);
    }

    if mime.starts_with("image/") {
        use base64::Engine as _;
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(&part.data);
        return Content::image(data_b64, mime.to_string());
    }

    // Non-text / non-image: try CBOR → JSON text, then base64 fallback.
    let text = match cbor::cbor_to_json(&part.data) {
        Ok(Value::String(s)) => s,
        Ok(v) => serde_json::to_string(&v).unwrap_or_default(),
        Err(_) => {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(&part.data)
        }
    };
    Content::text(text)
}

#[allow(dead_code)]
fn component_error_to_mcp(err: runtime::ComponentError) -> ErrorData {
    match err {
        runtime::ComponentError::Tool(te) => {
            let message = act_types::types::LocalizedString::from(&te.message)
                .any_text()
                .to_string();
            let code = match te.kind.as_str() {
                ERR_INVALID_ARGS => ErrorCode::INVALID_PARAMS,
                ERR_NOT_FOUND => ErrorCode::METHOD_NOT_FOUND,
                ERR_CAPABILITY_DENIED => ErrorCode::INVALID_REQUEST,
                _ => ErrorCode::INTERNAL_ERROR,
            };
            ErrorData::new(code, message, None)
        }
        runtime::ComponentError::Internal(e) => {
            ErrorData::new(ErrorCode::INTERNAL_ERROR, e.to_string(), None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::act::core::types::{ContentPart, LocalizedString, ToolError};
    use rmcp::model::{Content, ErrorCode, RawContent};

    fn part(mime: Option<&str>, data: &[u8]) -> ContentPart {
        ContentPart {
            data: data.to_vec(),
            mime_type: mime.map(str::to_string),
            metadata: vec![],
        }
    }

    fn content_text(c: &Content) -> Option<&str> {
        match &c.raw {
            RawContent::Text(t) => Some(&t.text),
            _ => None,
        }
    }

    #[test]
    fn map_content_text_plain() {
        let c = map_content_part(&part(Some("text/plain"), b"hello world"));
        assert_eq!(content_text(&c), Some("hello world"));
    }

    #[test]
    fn map_content_image_png() {
        let c = map_content_part(&part(Some("image/png"), &[0x89, 0x50, 0x4E, 0x47]));
        match &c.raw {
            RawContent::Image(img) => {
                assert_eq!(img.mime_type, "image/png");
                use base64::Engine as _;
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(&img.data)
                    .unwrap();
                assert_eq!(decoded, vec![0x89, 0x50, 0x4E, 0x47]);
            }
            _ => panic!("expected image content"),
        }
    }

    #[test]
    fn map_content_cbor_decodes_to_text_json() {
        // CBOR-encoded {"key": "value"}
        let mut buf = Vec::new();
        ciborium::into_writer(&serde_json::json!({"key": "value"}), &mut buf).unwrap();
        let c = map_content_part(&part(Some("application/cbor"), &buf));
        let text = content_text(&c).expect("cbor must decode to text");
        assert!(
            text.contains("key") && text.contains("value"),
            "got: {text}"
        );
    }

    #[test]
    fn map_content_opaque_falls_back_to_base64() {
        let bytes = vec![0xFF, 0xD8, 0xFF, 0xE0];
        let c = map_content_part(&part(None, &bytes));
        let text = content_text(&c).expect("opaque must become text");
        use base64::Engine as _;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(text)
            .unwrap();
        assert_eq!(decoded, bytes);
    }

    fn fake_info() -> runtime::ComponentInfo {
        let mut info = runtime::ComponentInfo::default();
        info.std.name = "example".to_string();
        info.std.version = "1.2.3".to_string();
        info
    }

    fn fake_handle() -> runtime::ComponentHandle {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        tx
    }

    #[test]
    fn get_info_exposes_server_name_version_and_tools_capability() {
        let bridge = ActRmcpBridge {
            handle: fake_handle(),
            info: fake_info(),
            metadata: runtime::Metadata::default(),
            metadata_schema: None,
        };
        let info = rmcp::ServerHandler::get_info(&bridge);
        assert_eq!(info.server_info.name, "example");
        assert_eq!(info.server_info.version, "1.2.3");
        assert!(
            info.capabilities.tools.is_some(),
            "tools capability must be advertised"
        );
    }

    #[test]
    fn map_internal_error_becomes_internal_error_code() {
        let err = runtime::ComponentError::Internal(anyhow::anyhow!("boom"));
        let mapped = component_error_to_mcp(err);
        assert_eq!(mapped.code, ErrorCode::INTERNAL_ERROR);
        assert!(mapped.message.contains("boom"));
    }

    #[test]
    fn map_tool_invalid_argument_becomes_invalid_params() {
        let err = runtime::ComponentError::Tool(ToolError {
            kind: act_types::constants::ERR_INVALID_ARGS.to_string(),
            message: LocalizedString::Plain("bad arg".into()),
            metadata: vec![],
        });
        let mapped = component_error_to_mcp(err);
        assert_eq!(mapped.code, ErrorCode::INVALID_PARAMS);
        assert!(mapped.message.contains("bad arg"));
    }

    #[test]
    fn map_tool_not_found_becomes_method_not_found() {
        let err = runtime::ComponentError::Tool(ToolError {
            kind: act_types::constants::ERR_NOT_FOUND.to_string(),
            message: LocalizedString::Plain("no such tool".into()),
            metadata: vec![],
        });
        let mapped = component_error_to_mcp(err);
        assert_eq!(mapped.code, ErrorCode::METHOD_NOT_FOUND);
    }

    #[test]
    fn map_tool_capability_denied_becomes_invalid_request() {
        let err = runtime::ComponentError::Tool(ToolError {
            kind: act_types::constants::ERR_CAPABILITY_DENIED.to_string(),
            message: LocalizedString::Plain("not allowed".into()),
            metadata: vec![],
        });
        let mapped = component_error_to_mcp(err);
        assert_eq!(mapped.code, ErrorCode::INVALID_REQUEST);
    }
}
