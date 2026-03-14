use act_types::cbor;
use act_types::constants::*;
use act_types::http as act_http;
use act_types::types::{Config, Metadata};
use axum::{
    Json, Router,
    extract::{Path, Request, State},
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::{
        IntoResponse,
        sse::{Event, Sse},
    },
    routing::get,
};
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;

use crate::runtime;

// ── App state ──

pub struct AppState {
    pub info: act_http::ServerInfo,
    pub config_schema: Option<String>,
    pub component: runtime::ComponentHandle,
}

// ── Conversion helpers ──

/// Map an ACT error kind string to an HTTP status code.
fn error_kind_to_status(kind: &str) -> StatusCode {
    StatusCode::from_u16(act_http::error_kind_to_status(kind))
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

/// Convert a ComponentError to an HTTP response with appropriate status code.
fn component_error_response(err: runtime::ComponentError) -> axum::response::Response {
    match err {
        runtime::ComponentError::Tool(tool_error) => {
            let ls = act_types::types::LocalizedString::from(&tool_error.message);
            let message = ls.any_text().to_string();
            tracing::warn!(kind = %tool_error.kind, %message, "Tool error");
            (
                error_kind_to_status(&tool_error.kind),
                Json(act_http::ErrorResponse {
                    error: act_http::ToolError {
                        kind: tool_error.kind,
                        message,
                        metadata: None,
                    },
                }),
            )
                .into_response()
        }
        runtime::ComponentError::Internal(e) => {
            tracing::error!(error = %e, "Internal error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(act_http::ErrorResponse {
                    error: act_http::ToolError {
                        kind: ERR_INTERNAL.to_string(),
                        message: e.to_string(),
                        metadata: None,
                    },
                }),
            )
                .into_response()
        }
    }
}

fn internal_error_response(message: &str) -> axum::response::Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(act_http::ErrorResponse {
            error: act_http::ToolError {
                kind: ERR_INTERNAL.to_string(),
                message: message.to_string(),
                metadata: None,
            },
        }),
    )
        .into_response()
}

/// Format an SseEvent as an axum SSE Event.
fn sse_event_to_axum(event: runtime::SseEvent) -> Option<Result<Event, std::convert::Infallible>> {
    match event {
        runtime::SseEvent::Stream(stream_event) => match stream_event {
            runtime::act::core::types::StreamEvent::Content(part) => {
                let data = cbor::decode_content_data(&part.data, part.mime_type.as_deref());
                let json = serde_json::json!({
                    "data": data,
                    "mime_type": part.mime_type,
                });
                Some(Ok(Event::default()
                    .event("content")
                    .json_data(json)
                    .expect("json_data with serde_json::Value is infallible")))
            }
            runtime::act::core::types::StreamEvent::Error(err) => {
                let ls = act_types::types::LocalizedString::from(&err.message);
                let message = ls.any_text().to_string();
                tracing::warn!(kind = %err.kind, %message, "Stream error (SSE)");
                let json = serde_json::json!({
                    "kind": err.kind,
                    "message": message,
                });
                Some(Ok(Event::default()
                    .event("error")
                    .json_data(json)
                    .expect("json_data with serde_json::Value is infallible")))
            }
        },
        runtime::SseEvent::Done => Some(Ok(Event::default()
            .event("done")
            .json_data(serde_json::json!({}))
            .expect("infallible"))),
        runtime::SseEvent::Error(e) => {
            let (kind, message) = match e {
                runtime::ComponentError::Tool(ref te) => (
                    te.kind.clone(),
                    act_types::types::LocalizedString::from(&te.message)
                        .any_text()
                        .to_string(),
                ),
                runtime::ComponentError::Internal(ref e) => {
                    (ERR_INTERNAL.to_string(), e.to_string())
                }
            };
            Some(Ok(Event::default()
                .event("error")
                .json_data(serde_json::json!({"kind": kind, "message": message}))
                .expect("infallible")))
        }
    }
}

// ── Handlers ──

async fn get_info(State(state): State<Arc<AppState>>) -> Json<act_http::ServerInfo> {
    Json(state.info.clone())
}

async fn get_config_schema(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match &state.config_schema {
        Some(schema) => (
            StatusCode::OK,
            [("content-type", MIME_JSON)],
            schema.clone(),
        )
            .into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

async fn list_tools_inner(
    state: &AppState,
    config: Option<serde_json::Value>,
) -> axum::response::Response {
    let cbor_config = match Config::from_json_opt(&config) {
        Ok(c) => c.map(Vec::from),
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::ListTools {
        config: cbor_config,
        reply: reply_tx,
    };

    if state.component.send(request).await.is_err() {
        return internal_error_response("component actor unavailable");
    }

    match reply_rx.await {
        Ok(Ok(list_response)) => {
            let tools: Vec<act_http::ToolDefinition> = list_response
                .tools
                .iter()
                .map(|td| {
                    let ls = act_types::types::LocalizedString::from(&td.description);
                    let meta = Metadata::from(td.metadata.clone());
                    act_http::ToolDefinition {
                        name: td.name.clone(),
                        description: ls.any_text().to_string(),
                        parameters_schema: serde_json::from_str(&td.parameters_schema)
                            .unwrap_or(serde_json::Value::Object(Default::default())),
                        metadata: meta.to_json(),
                    }
                })
                .collect();
            Json(act_http::ListToolsResponse {
                tools,
                metadata: None,
            })
            .into_response()
        }
        Ok(Err(e)) => component_error_response(e),
        Err(_) => component_error_response(runtime::ComponentError::Internal(anyhow::anyhow!(
            "component actor dropped reply"
        ))),
    }
}

async fn call_tool_buffered(
    state: Arc<AppState>,
    tool_call: runtime::act::core::types::ToolCall,
    cbor_config: Option<Vec<u8>>,
) -> axum::response::Response {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::CallTool {
        config: cbor_config,
        call: tool_call,
        reply: reply_tx,
    };

    if state.component.send(request).await.is_err() {
        return internal_error_response("component actor unavailable");
    }

    match reply_rx.await {
        Ok(Ok(result)) => {
            let content: Vec<act_http::ContentPart> = result
                .events
                .iter()
                .filter_map(|event| match event {
                    runtime::act::core::types::StreamEvent::Content(part) => {
                        let data = cbor::decode_content_data(&part.data, part.mime_type.as_deref());
                        Some(act_http::ContentPart {
                            data,
                            mime_type: part.mime_type.clone(),
                            metadata: None,
                        })
                    }
                    runtime::act::core::types::StreamEvent::Error(_) => None,
                })
                .collect();

            let stream_error = result.events.iter().find_map(|event| match event {
                runtime::act::core::types::StreamEvent::Error(e) => Some(e),
                _ => None,
            });

            if let Some(err) = stream_error {
                let ls = act_types::types::LocalizedString::from(&err.message);
                let message = ls.any_text().to_string();
                tracing::warn!(kind = %err.kind, %message, "Stream error");
                return (
                    error_kind_to_status(&err.kind),
                    Json(act_http::ErrorResponse {
                        error: act_http::ToolError {
                            kind: err.kind.clone(),
                            message,
                            metadata: None,
                        },
                    }),
                )
                    .into_response();
            }

            Json(act_http::ToolCallResponse {
                content,
                metadata: None,
            })
            .into_response()
        }
        Ok(Err(e)) => component_error_response(e),
        Err(_) => component_error_response(runtime::ComponentError::Internal(anyhow::anyhow!(
            "component actor dropped reply"
        ))),
    }
}

async fn call_tool_sse(
    state: Arc<AppState>,
    tool_call: runtime::act::core::types::ToolCall,
    cbor_config: Option<Vec<u8>>,
) -> axum::response::Response {
    tracing::debug!(tool = %tool_call.name, "SSE streaming requested");

    let (event_tx, event_rx) = tokio::sync::mpsc::channel(32);

    let request = runtime::ComponentRequest::CallToolStreaming {
        config: cbor_config,
        call: tool_call,
        event_tx,
    };

    if state.component.send(request).await.is_err() {
        return internal_error_response("component actor unavailable");
    }

    let stream = ReceiverStream::new(event_rx);
    let sse_stream = tokio_stream::StreamExt::filter_map(stream, sse_event_to_axum);

    Sse::new(sse_stream).into_response()
}

/// Parse a JSON body with config, accepting empty body as no config.
async fn parse_config_body(request: Request) -> Result<Option<serde_json::Value>, StatusCode> {
    let body_bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if body_bytes.is_empty() {
        return Ok(None);
    }
    let body: act_http::ConfigRequest =
        serde_json::from_slice(&body_bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(body.config)
}

/// Handler for the /tools route that dispatches POST and QUERY methods.
async fn tools_dispatcher(
    state: State<Arc<AppState>>,
    request: Request,
) -> axum::response::Response {
    if request.method() == Method::POST || request.method() == query_method() {
        let config = match parse_config_body(request).await {
            Ok(c) => c,
            Err(status) => return status.into_response(),
        };
        list_tools_inner(&state, config).await
    } else {
        StatusCode::METHOD_NOT_ALLOWED.into_response()
    }
}

/// Handler for /tools/{name} that dispatches POST and QUERY methods.
async fn tool_call_dispatcher(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    request: Request,
) -> axum::response::Response {
    let is_query = request.method() == query_method();

    if request.method() != Method::POST && !is_query {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    let headers = request.headers().clone();
    let body_bytes = match axum::body::to_bytes(request.into_body(), 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let body: act_http::ToolCallRequest = match serde_json::from_slice(&body_bytes) {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    // TODO: For QUERY, check that the tool is read-only + idempotent, else 405

    let wants_sse = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains(MIME_SSE));

    let cbor_config = match Config::from_json_opt(&body.config) {
        Ok(c) => c.map(Vec::from),
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let cbor_args = match cbor::json_to_cbor(&body.arguments) {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let tool_call = runtime::act::core::types::ToolCall {
        name,
        arguments: cbor_args,
        metadata: Vec::new(),
    };

    if wants_sse {
        call_tool_sse(state, tool_call, cbor_config).await
    } else {
        call_tool_buffered(state, tool_call, cbor_config).await
    }
}

fn query_method() -> &'static Method {
    static QUERY: std::sync::LazyLock<Method> =
        std::sync::LazyLock::new(|| Method::from_bytes(b"QUERY").expect("QUERY is a valid method"));
    &QUERY
}

// ── Protocol version middleware ──

async fn protocol_version_layer(request: Request, next: Next) -> axum::response::Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        act_http::HEADER_PROTOCOL_VERSION,
        act_http::PROTOCOL_VERSION
            .parse()
            .expect("valid header value"),
    );
    response
}

// ── Router ──

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/info", get(get_info))
        .route("/config-schema", get(get_config_schema))
        .route("/tools", axum::routing::any(tools_dispatcher))
        .route("/tools/{name}", axum::routing::any(tool_call_dispatcher))
        .layer(middleware::from_fn(protocol_version_layer))
        .with_state(state)
}
