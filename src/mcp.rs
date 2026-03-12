use act_types::cbor;
use act_types::types::Metadata;
use crate::runtime;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

// ── JSON-RPC types ──

#[derive(Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

#[derive(Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Value,
    #[serde(flatten)]
    body: JsonRpcBody,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum JsonRpcBody {
    Result(Value),
    Error(JsonRpcError),
}

#[derive(Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

impl JsonRpcResponse {
    fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            body: JsonRpcBody::Result(result),
        }
    }
    fn error(id: Value, code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            body: JsonRpcBody::Error(JsonRpcError { code, message }),
        }
    }
}

// ── Stdio loop ──

pub async fn run_stdio(
    info: runtime::act::core::types::ComponentInfo,
    handle: runtime::ComponentHandle,
    config: Option<Vec<u8>>,
) -> Result<()> {
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

        let response = handle_request(&request, &info, &handle, &config).await;
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
    info: &runtime::act::core::types::ComponentInfo,
    handle: &runtime::ComponentHandle,
    config: &Option<Vec<u8>>,
) -> Option<JsonRpcResponse> {
    let id = req.id.clone().unwrap_or(Value::Null);

    match req.method.as_str() {
        "initialize" => Some(handle_initialize(id, info)),
        "notifications/initialized" => None,
        "ping" => Some(JsonRpcResponse::success(id, serde_json::json!({}))),
        "tools/list" => Some(handle_tools_list(id, handle, config).await),
        "tools/call" => Some(handle_tools_call(id, req, handle, config).await),
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

fn handle_initialize(
    id: Value,
    info: &runtime::act::core::types::ComponentInfo,
) -> JsonRpcResponse {
    JsonRpcResponse::success(
        id,
        serde_json::json!({
            "protocolVersion": "2025-11-25",
            "serverInfo": {
                "name": info.name,
                "version": info.version,
            },
            "capabilities": {
                "tools": {},
            },
        }),
    )
}

// ── tools/list ──

async fn handle_tools_list(
    id: Value,
    handle: &runtime::ComponentHandle,
    config: &Option<Vec<u8>>,
) -> JsonRpcResponse {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::ListTools {
        config: config.clone(),
        reply: reply_tx,
    };

    if handle.send(request).await.is_err() {
        return JsonRpcResponse::error(id, -32603, "component actor unavailable".to_string());
    }

    match reply_rx.await {
        Ok(Ok(list_response)) => {
            let tools: Vec<Value> = list_response
                .tools
                .iter()
                .map(|td| {
                    let description = act_types::types::LocalizedString::from(&td.description).any_text().to_string();
                    let input_schema: Value = serde_json::from_str(&td.parameters_schema)
                        .unwrap_or(serde_json::json!({"type": "object"}));

                    let mut tool = serde_json::json!({
                        "name": td.name,
                        "description": description,
                        "inputSchema": input_schema,
                    });

                    let annotations = build_annotations(&td.metadata);
                    if !annotations.is_empty() {
                        tool.as_object_mut()
                            .expect("tool is a JSON object")
                            .insert("annotations".to_string(), Value::Object(annotations));
                    }

                    tool
                })
                .collect();

            JsonRpcResponse::success(id, serde_json::json!({ "tools": tools }))
        }
        Ok(Err(e)) => component_error_to_jsonrpc(id, e),
        Err(_) => JsonRpcResponse::error(id, -32603, "component actor dropped reply".to_string()),
    }
}

fn build_annotations(metadata: &[(String, Vec<u8>)]) -> serde_json::Map<String, Value> {
    use act_types::constants::*;
    let meta = Metadata::from(metadata.to_vec());
    let mut annotations = serde_json::Map::new();
    if let Some(v) = meta.get::<bool>(META_READ_ONLY) {
        annotations.insert("readOnlyHint".to_string(), Value::Bool(v));
    }
    if let Some(v) = meta.get::<bool>(META_IDEMPOTENT) {
        annotations.insert("idempotentHint".to_string(), Value::Bool(v));
    }
    if let Some(v) = meta.get::<bool>(META_DESTRUCTIVE) {
        annotations.insert("destructiveHint".to_string(), Value::Bool(v));
    }
    annotations
}

// ── tools/call ──

async fn handle_tools_call(
    id: Value,
    req: &JsonRpcRequest,
    handle: &runtime::ComponentHandle,
    config: &Option<Vec<u8>>,
) -> JsonRpcResponse {
    let params = req.params.as_ref();
    let tool_name = params
        .and_then(|p| p.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let arguments = params
        .and_then(|p| p.get("arguments"))
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let cbor_args = match cbor::json_to_cbor(&arguments) {
        Ok(bytes) => bytes,
        Err(_) => return JsonRpcResponse::error(id, -32602, "invalid arguments".to_string()),
    };

    let tool_call = runtime::act::core::types::ToolCall {
        name: tool_name.to_string(),
        arguments: cbor_args,
        metadata: Vec::new(),
    };

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::CallTool {
        config: config.clone(),
        call: tool_call,
        reply: reply_tx,
    };

    if handle.send(request).await.is_err() {
        return JsonRpcResponse::error(id, -32603, "component actor unavailable".to_string());
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
                        let message = act_types::types::LocalizedString::from(&err.message).any_text().to_string();
                        content.push(serde_json::json!({
                            "type": "text",
                            "text": message,
                        }));
                    }
                }
            }

            let mut result = serde_json::json!({ "content": content });
            if is_error {
                result
                    .as_object_mut()
                    .expect("result is a JSON object")
                    .insert("isError".to_string(), Value::Bool(true));
            }
            JsonRpcResponse::success(id, result)
        }
        Ok(Err(e)) => component_error_to_jsonrpc(id, e),
        Err(_) => JsonRpcResponse::error(id, -32603, "component actor dropped reply".to_string()),
    }
}

// ── Content mapping (ACT-MCP.md §2.2) ──

fn map_content_part(part: &runtime::act::core::types::ContentPart) -> Value {
    use base64::Engine as _;
    let mime = part.mime_type.as_deref().unwrap_or("");

    match mime {
        m if m.starts_with("text/") => {
            let text = String::from_utf8_lossy(&part.data);
            serde_json::json!({ "type": "text", "text": text })
        }
        m if m.starts_with("image/") => {
            let b64 = base64::engine::general_purpose::STANDARD.encode(&part.data);
            serde_json::json!({ "type": "image", "data": b64, "mimeType": m })
        }
        _ => {
            let text = match cbor::cbor_to_json(&part.data) {
                Ok(Value::String(s)) => s,
                Ok(v) => serde_json::to_string(&v).unwrap_or_default(),
                Err(_) => base64::engine::general_purpose::STANDARD.encode(&part.data),
            };
            serde_json::json!({ "type": "text", "text": text })
        }
    }
}

// ── Error mapping ──

fn error_kind_to_jsonrpc_code(kind: &str) -> i32 {
    use act_types::constants::*;
    match kind {
        ERR_NOT_FOUND => -32601,
        ERR_INVALID_ARGS => -32602,
        ERR_INTERNAL => -32603,
        _ => -32000,
    }
}

fn component_error_to_jsonrpc(id: Value, err: runtime::ComponentError) -> JsonRpcResponse {
    match err {
        runtime::ComponentError::Tool(te) => {
            let message = act_types::types::LocalizedString::from(&te.message).any_text().to_string();
            JsonRpcResponse::error(id, error_kind_to_jsonrpc_code(&te.kind), message)
        }
        runtime::ComponentError::Internal(e) => {
            JsonRpcResponse::error(id, -32603, e.to_string())
        }
    }
}
