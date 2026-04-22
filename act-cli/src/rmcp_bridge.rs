use crate::runtime;
use act_types::cbor;
use act_types::constants::{ERR_CAPABILITY_DENIED, ERR_INVALID_ARGS, ERR_NOT_FOUND};
use rmcp::ErrorData;
use rmcp::model::{Content, ErrorCode, Tool};
use serde_json::Value;
use std::borrow::Cow;
use std::sync::Arc;

pub struct ActRmcpBridge {
    pub handle: runtime::ComponentHandle,
    pub info: runtime::ComponentInfo,
    pub metadata: runtime::Metadata,
}

fn map_content_part(part: &runtime::exports::act::tools::tool_provider::ContentPart) -> Content {
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

// ── list_tools helpers ──────────────────────────────────────────────────────

fn convert_tool_definitions(
    defs: &[runtime::exports::act::tools::tool_provider::ToolDefinition],
) -> Vec<Tool> {
    defs.iter()
        .map(|td| {
            let description = act_types::types::LocalizedString::from(&td.description)
                .any_text()
                .to_string();

            let input_schema: Value = serde_json::from_str(&td.parameters_schema)
                .unwrap_or_else(|_| serde_json::json!({"type": "object"}));

            let schema_map: serde_json::Map<String, Value> =
                input_schema.as_object().cloned().unwrap_or_default();

            let mut tool = Tool::new(
                Cow::Owned(td.name.clone()),
                Cow::Owned(description),
                Arc::new(schema_map),
            );

            if let Some(ann) = build_annotations(&td.metadata) {
                tool = tool.with_annotations(ann);
            }

            tool
        })
        .collect()
}

fn build_annotations(metadata: &[(String, Vec<u8>)]) -> Option<rmcp::model::ToolAnnotations> {
    use act_types::constants::*;
    let meta = act_types::types::Metadata::from(metadata.to_vec());

    let read_only_hint = meta.get_as::<bool>(META_READ_ONLY);
    let idempotent_hint = meta.get_as::<bool>(META_IDEMPOTENT);
    let destructive_hint = meta.get_as::<bool>(META_DESTRUCTIVE);

    if read_only_hint.is_none() && idempotent_hint.is_none() && destructive_hint.is_none() {
        return None;
    }

    Some(rmcp::model::ToolAnnotations::from_raw(
        None,
        read_only_hint,
        destructive_hint,
        idempotent_hint,
        None,
    ))
}

// ── fold_events_to_result ───────────────────────────────────────────────────

fn fold_events_to_result(result: runtime::CallToolResult) -> rmcp::model::CallToolResult {
    let mut content = Vec::new();
    let mut is_error = false;

    for event in &result.events {
        match event {
            runtime::exports::act::tools::tool_provider::ToolEvent::Content(part) => {
                content.push(map_content_part(part));
            }
            runtime::exports::act::tools::tool_provider::ToolEvent::Error(err) => {
                is_error = true;
                let message = act_types::types::LocalizedString::from(&err.message)
                    .any_text()
                    .to_string();
                content.push(rmcp::model::Content::text(message));
            }
        }
    }

    if is_error {
        rmcp::model::CallToolResult::error(content)
    } else {
        rmcp::model::CallToolResult::success(content)
    }
}

// ── Public entry point ──────────────────────────────────────────────────────

pub async fn run_stdio(
    info: runtime::ComponentInfo,
    handle: runtime::ComponentHandle,
    metadata: runtime::Metadata,
) -> anyhow::Result<()> {
    let bridge = ActRmcpBridge {
        handle,
        info,
        metadata,
    };

    let service = rmcp::serve_server(bridge, (tokio::io::stdin(), tokio::io::stdout()))
        .await
        .map_err(|e| anyhow::anyhow!("rmcp serve_server failed: {e}"))?;

    service
        .waiting()
        .await
        .map_err(|e| anyhow::anyhow!("rmcp service error: {e}"))?;

    Ok(())
}

// ── ServerHandler impl ──────────────────────────────────────────────────────

impl ActRmcpBridge {
    async fn list_tools_impl(&self) -> Result<rmcp::model::ListToolsResult, rmcp::ErrorData> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let req = runtime::ComponentRequest::ListTools {
            metadata: self.metadata.clone(),
            reply: reply_tx,
        };

        self.handle.send(req).await.map_err(|_| {
            rmcp::ErrorData::new(
                rmcp::model::ErrorCode::INTERNAL_ERROR,
                "component actor unavailable",
                None,
            )
        })?;

        let list = reply_rx
            .await
            .map_err(|_| {
                rmcp::ErrorData::new(
                    rmcp::model::ErrorCode::INTERNAL_ERROR,
                    "component actor dropped reply",
                    None,
                )
            })?
            .map_err(component_error_to_mcp)?;

        let tools = convert_tool_definitions(&list.tools);
        Ok(rmcp::model::ListToolsResult {
            tools,
            next_cursor: None,
            meta: None,
        })
    }

    async fn call_tool_impl(
        &self,
        request: rmcp::model::CallToolRequestParams,
    ) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
        use rmcp::model::ErrorCode;

        let mut arguments = request
            .arguments
            .map(Value::Object)
            .unwrap_or_else(|| serde_json::json!({}));

        let mut call_metadata = self.metadata.clone();
        if let Some(obj) = arguments.as_object_mut()
            && let Some(Value::Object(extra)) = obj.remove("_metadata")
        {
            call_metadata.extend(act_types::types::Metadata::from(Value::Object(extra)));
        }

        let cbor_args = act_types::cbor::json_to_cbor(&arguments).map_err(|_| {
            rmcp::ErrorData::new(ErrorCode::INVALID_PARAMS, "invalid arguments", None)
        })?;

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let req = runtime::ComponentRequest::CallTool {
            name: request.name.to_string(),
            arguments: cbor_args,
            metadata: call_metadata.into(),
            reply: reply_tx,
        };

        self.handle.send(req).await.map_err(|_| {
            rmcp::ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                "component actor unavailable",
                None,
            )
        })?;

        let result = reply_rx
            .await
            .map_err(|_| {
                rmcp::ErrorData::new(
                    ErrorCode::INTERNAL_ERROR,
                    "component actor dropped reply",
                    None,
                )
            })?
            .map_err(component_error_to_mcp)?;

        Ok(fold_events_to_result(result))
    }
}

impl rmcp::ServerHandler for ActRmcpBridge {
    fn get_info(&self) -> rmcp::model::ServerInfo {
        rmcp::model::ServerInfo::new(
            rmcp::model::ServerCapabilities::builder()
                .enable_tools()
                .build(),
        )
        .with_server_info(rmcp::model::Implementation::new(
            self.info.std.name.clone(),
            self.info.std.version.clone(),
        ))
    }

    fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl std::future::Future<Output = Result<rmcp::model::ListToolsResult, rmcp::ErrorData>>
    + Send
    + '_ {
        self.list_tools_impl()
    }

    fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl std::future::Future<Output = Result<rmcp::model::CallToolResult, rmcp::ErrorData>>
    + Send
    + '_ {
        self.call_tool_impl(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::exports::act::tools::tool_provider as runtime_types;
    use crate::runtime::exports::act::tools::tool_provider::{
        ContentPart, Error, LocalizedString, ToolDefinition,
    };
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
        let err = runtime::ComponentError::Tool(Error {
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
        let err = runtime::ComponentError::Tool(Error {
            kind: act_types::constants::ERR_NOT_FOUND.to_string(),
            message: LocalizedString::Plain("no such tool".into()),
            metadata: vec![],
        });
        let mapped = component_error_to_mcp(err);
        assert_eq!(mapped.code, ErrorCode::METHOD_NOT_FOUND);
    }

    #[test]
    fn map_tool_capability_denied_becomes_invalid_request() {
        let err = runtime::ComponentError::Tool(Error {
            kind: act_types::constants::ERR_CAPABILITY_DENIED.to_string(),
            message: LocalizedString::Plain("not allowed".into()),
            metadata: vec![],
        });
        let mapped = component_error_to_mcp(err);
        assert_eq!(mapped.code, ErrorCode::INVALID_REQUEST);
    }

    fn fake_tool(name: &str) -> ToolDefinition {
        ToolDefinition {
            name: name.into(),
            description: LocalizedString::Plain(format!("{name} tool")),
            parameters_schema: r#"{"type":"object","properties":{"n":{"type":"integer"}}}"#.into(),
            metadata: vec![],
        }
    }

    #[test]
    fn list_tools_maps_definitions() {
        let defs = vec![fake_tool("alpha"), fake_tool("beta")];
        let tools = convert_tool_definitions(&defs);

        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name.as_ref(), "alpha");
        assert_eq!(tools[0].description.as_deref(), Some("alpha tool"));

        let schema: &serde_json::Map<String, serde_json::Value> = tools[0].input_schema.as_ref();
        let props = schema["properties"].as_object().unwrap();
        assert!(
            props.contains_key("n"),
            "original property must be preserved"
        );
    }

    use crate::runtime::CallToolResult as ActCallToolResult;

    #[test]
    fn fold_events_text_content_and_error_sets_is_error() {
        let events = vec![
            runtime_types::ToolEvent::Content(runtime_types::ContentPart {
                data: b"partial ok".to_vec(),
                mime_type: Some("text/plain".into()),
                metadata: vec![],
            }),
            runtime_types::ToolEvent::Error(runtime_types::Error {
                kind: act_types::constants::ERR_INTERNAL.to_string(),
                message: runtime_types::LocalizedString::Plain("boom mid-stream".into()),
                metadata: vec![],
            }),
        ];
        let result = fold_events_to_result(ActCallToolResult { events });
        assert_eq!(result.is_error, Some(true));
        assert_eq!(result.content.len(), 2);
        match &result.content[1].raw {
            RawContent::Text(t) => assert!(t.text.contains("boom mid-stream")),
            _ => panic!("expected text content for error"),
        }
    }

    #[test]
    fn fold_events_all_content_no_error_leaves_is_error_none_or_false() {
        let events = vec![runtime_types::ToolEvent::Content(
            runtime_types::ContentPart {
                data: b"ok".to_vec(),
                mime_type: Some("text/plain".into()),
                metadata: vec![],
            },
        )];
        let result = fold_events_to_result(ActCallToolResult { events });
        assert!(!result.is_error.unwrap_or(false));
        assert_eq!(result.content.len(), 1);
    }
}
