use crate::runtime;
use act_types::cbor;
use act_types::jsonrpc::{Request as JsonRpcRequest, Response as JsonRpcResponse};
use act_types::mcp::{
    self, CallToolParams, CallToolResult, ContentItem, ImageContent, InitializeResult,
    ListToolsResult, ServerCapabilities, ServerInfo, TextContent, ToolAnnotations, ToolDefinition,
};
use act_types::types::Metadata;
use anyhow::Result;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

// ── Helpers ──

async fn fetch_metadata_schema(
    handle: &runtime::ComponentHandle,
    metadata: &runtime::Metadata,
) -> Option<String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let req = runtime::ComponentRequest::GetMetadataSchema {
        metadata: metadata.clone(),
        reply: tx,
    };
    handle.send(req).await.ok()?;
    rx.await.ok()?.ok()?
}

// ── Stdio loop ──

pub async fn run_stdio(
    info: runtime::ComponentInfo,
    handle: runtime::ComponentHandle,
    metadata: runtime::Metadata,
) -> Result<()> {
    // Fetch metadata schema once at startup for _metadata injection in tool schemas
    let metadata_schema = fetch_metadata_schema(&handle, &metadata).await;

    let stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();
    let mut lines = stdin.lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = JsonRpcResponse::error(Value::Null, -32700, format!("Parse error: {e}"));
                write_response(&mut stdout, &resp).await?;
                continue;
            }
        };

        let response = handle_request(
            &request,
            &info,
            &handle,
            &metadata,
            metadata_schema.as_deref(),
        )
        .await;
        if let Some(resp) = response {
            write_response(&mut stdout, &resp).await?;
        }
    }

    Ok(())
}

async fn write_response(stdout: &mut tokio::io::Stdout, resp: &JsonRpcResponse) -> Result<()> {
    let json = serde_json::to_string(resp)?;
    stdout.write_all(json.as_bytes()).await?;
    stdout.write_all(b"\n").await?;
    stdout.flush().await?;
    Ok(())
}

// ── Method dispatch ──

async fn handle_request(
    req: &JsonRpcRequest,
    info: &runtime::ComponentInfo,
    handle: &runtime::ComponentHandle,
    metadata: &runtime::Metadata,
    metadata_schema: Option<&str>,
) -> Option<JsonRpcResponse> {
    let id = req.id.clone().unwrap_or(Value::Null);

    match req.method.as_str() {
        "initialize" => Some(handle_initialize(id, info)),
        "notifications/initialized" => None,
        "ping" => Some(JsonRpcResponse::success(id, serde_json::json!({}))),
        "tools/list" => Some(handle_tools_list(id, handle, metadata, metadata_schema).await),
        "tools/call" => Some(handle_tools_call(id, req, handle, metadata).await),
        _ => {
            if req.method.starts_with("notifications/") {
                None
            } else {
                Some(JsonRpcResponse::error(
                    id,
                    -32601,
                    format!("Method not found: {}", req.method),
                ))
            }
        }
    }
}

// ── initialize ──

fn handle_initialize(id: Value, info: &runtime::ComponentInfo) -> JsonRpcResponse {
    let result = InitializeResult {
        protocol_version: mcp::PROTOCOL_VERSION.to_string(),
        server_info: ServerInfo {
            name: info.std.name.clone(),
            version: Some(info.std.version.clone()),
        },
        capabilities: Some(ServerCapabilities {
            tools: Some(serde_json::json!({})),
            ..Default::default()
        }),
    };
    JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
}

// ── tools/list ──

async fn handle_tools_list(
    id: Value,
    handle: &runtime::ComponentHandle,
    metadata: &runtime::Metadata,
    metadata_schema: Option<&str>,
) -> JsonRpcResponse {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::ListTools {
        metadata: metadata.clone(),
        reply: reply_tx,
    };

    if handle.send(request).await.is_err() {
        return JsonRpcResponse::error(id, -32603, "component actor unavailable");
    }

    match reply_rx.await {
        Ok(Ok(list_response)) => {
            let tools: Vec<ToolDefinition> = list_response
                .tools
                .iter()
                .map(|td| {
                    let description = act_types::types::LocalizedString::from(&td.description)
                        .any_text()
                        .to_string();
                    let mut input_schema: Value = serde_json::from_str(&td.parameters_schema)
                        .unwrap_or(serde_json::json!({"type": "object"}));

                    // Inject _metadata property with actual component metadata schema
                    if let Some(obj) = input_schema.as_object_mut() {
                        let props = obj
                            .entry("properties")
                            .or_insert_with(|| serde_json::json!({}));
                        if let Some(props) = props.as_object_mut() {
                            let meta_schema = metadata_schema
                                .and_then(|s| serde_json::from_str::<Value>(s).ok())
                                .unwrap_or_else(|| serde_json::json!({"type": "object"}));
                            props.insert("_metadata".to_string(), meta_schema);
                        }
                    }

                    let annotations = build_annotations(&td.metadata);

                    ToolDefinition {
                        name: td.name.clone(),
                        description: Some(description),
                        input_schema,
                        annotations,
                    }
                })
                .collect();

            let result = ListToolsResult {
                tools,
                next_cursor: None,
            };
            JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
        }
        Ok(Err(e)) => component_error_to_jsonrpc(id, e),
        Err(_) => JsonRpcResponse::error(id, -32603, "component actor dropped reply"),
    }
}

fn build_annotations(metadata: &[(String, Vec<u8>)]) -> Option<ToolAnnotations> {
    use act_types::constants::*;
    let meta = Metadata::from(metadata.to_vec());

    let read_only_hint = meta.get_as::<bool>(META_READ_ONLY);
    let idempotent_hint = meta.get_as::<bool>(META_IDEMPOTENT);
    let destructive_hint = meta.get_as::<bool>(META_DESTRUCTIVE);

    if read_only_hint.is_none() && idempotent_hint.is_none() && destructive_hint.is_none() {
        return None;
    }

    Some(ToolAnnotations {
        read_only_hint,
        idempotent_hint,
        destructive_hint,
        open_world_hint: None,
    })
}

// ── tools/call ──

async fn handle_tools_call(
    id: Value,
    req: &JsonRpcRequest,
    handle: &runtime::ComponentHandle,
    metadata: &runtime::Metadata,
) -> JsonRpcResponse {
    let call_params: CallToolParams = match req.params.as_ref() {
        Some(p) => match serde_json::from_value(p.clone()) {
            Ok(p) => p,
            Err(_) => return JsonRpcResponse::error(id, -32602, "invalid params"),
        },
        None => return JsonRpcResponse::error(id, -32602, "missing params"),
    };

    let mut arguments = call_params.arguments.unwrap_or(serde_json::json!({}));

    // Extract _metadata from arguments for per-call metadata override
    let mut call_metadata = metadata.clone();
    if let Some(obj) = arguments.as_object_mut()
        && let Some(Value::Object(extra)) = obj.remove("_metadata")
    {
        call_metadata.extend(Metadata::from(Value::Object(extra)));
    }

    let cbor_args = match cbor::json_to_cbor(&arguments) {
        Ok(bytes) => bytes,
        Err(_) => return JsonRpcResponse::error(id, -32602, "invalid arguments"),
    };

    let tool_call = runtime::act::core::types::ToolCall {
        name: call_params.name,
        arguments: cbor_args,
        metadata: call_metadata.into(),
    };

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::CallTool {
        call: tool_call,
        reply: reply_tx,
    };

    if handle.send(request).await.is_err() {
        return JsonRpcResponse::error(id, -32603, "component actor unavailable");
    }

    match reply_rx.await {
        Ok(Ok(result)) => {
            let mut content = Vec::new();
            let mut is_error = false;

            for event in &result.events {
                match event {
                    runtime::act::core::types::StreamEvent::Content(part) => {
                        content.push(map_content_part(part));
                    }
                    runtime::act::core::types::StreamEvent::Error(err) => {
                        is_error = true;
                        let message = act_types::types::LocalizedString::from(&err.message)
                            .any_text()
                            .to_string();
                        content.push(ContentItem::Text(TextContent { text: message }));
                    }
                }
            }

            let result = CallToolResult {
                content,
                is_error: if is_error { Some(true) } else { None },
            };
            JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
        }
        Ok(Err(e)) => component_error_to_jsonrpc(id, e),
        Err(_) => JsonRpcResponse::error(id, -32603, "component actor dropped reply"),
    }
}

// ── Content mapping (ACT-MCP.md §2.2) ──

fn map_content_part(part: &runtime::act::core::types::ContentPart) -> ContentItem {
    let mime = part.mime_type.as_deref().unwrap_or("");

    match mime {
        m if m.starts_with("text/") => {
            let text = String::from_utf8_lossy(&part.data).into_owned();
            ContentItem::Text(TextContent { text })
        }
        m if m.starts_with("image/") => ContentItem::Image(ImageContent {
            data: part.data.clone(),
            mime_type: m.to_string(),
        }),
        _ => {
            let text = match cbor::cbor_to_json(&part.data) {
                Ok(Value::String(s)) => s,
                Ok(v) => serde_json::to_string(&v).unwrap_or_default(),
                Err(_) => {
                    use base64::Engine as _;
                    base64::engine::general_purpose::STANDARD.encode(&part.data)
                }
            };
            ContentItem::Text(TextContent { text })
        }
    }
}

// ── Error mapping ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_text_content() {
        let part = runtime::act::core::types::ContentPart {
            data: b"hello world".to_vec(),
            mime_type: Some("text/plain".to_string()),
            metadata: vec![],
        };
        match map_content_part(&part) {
            ContentItem::Text(tc) => assert_eq!(tc.text, "hello world"),
            _ => panic!("expected TextContent"),
        }
    }

    #[test]
    fn map_image_content() {
        let part = runtime::act::core::types::ContentPart {
            data: vec![0x89, 0x50, 0x4E, 0x47],
            mime_type: Some("image/png".to_string()),
            metadata: vec![],
        };
        match map_content_part(&part) {
            ContentItem::Image(ic) => {
                assert_eq!(ic.mime_type, "image/png");
                assert_eq!(ic.data, vec![0x89, 0x50, 0x4E, 0x47]);
            }
            _ => panic!("expected ImageContent"),
        }
    }

    #[test]
    fn build_annotations_empty_metadata() {
        assert!(build_annotations(&[]).is_none());
    }

    #[test]
    fn build_annotations_with_read_only() {
        use act_types::constants::META_READ_ONLY;
        let cbor_true = {
            let mut buf = Vec::new();
            ciborium::into_writer(&true, &mut buf).unwrap();
            buf
        };
        let metadata = vec![(META_READ_ONLY.to_string(), cbor_true)];
        let annotations = build_annotations(&metadata).unwrap();
        assert_eq!(annotations.read_only_hint, Some(true));
    }
}

fn component_error_to_jsonrpc(id: Value, err: runtime::ComponentError) -> JsonRpcResponse {
    match err {
        runtime::ComponentError::Tool(te) => {
            let message = act_types::types::LocalizedString::from(&te.message)
                .any_text()
                .to_string();
            JsonRpcResponse::error(id, mcp::error_kind_to_jsonrpc_code(&te.kind), message)
        }
        runtime::ComponentError::Internal(e) => JsonRpcResponse::error(id, -32603, e.to_string()),
    }
}
