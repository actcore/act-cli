use act_types::cbor;
use act_types::constants::*;
use act_types::http as act_http;
use act_types::types::Metadata;
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
    pub info: act_types::ComponentInfo,
    pub component: runtime::ComponentHandle,
    pub metadata: Metadata,
    /// When `Some`, a single default session was pre-opened (session-of-1,
    /// ACT-SESSIONS §3): `/sessions*` routes are unregistered and this id is
    /// forced into every call's `std:session-id` metadata.
    pub default_session_id: Option<String>,
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

/// Force `std:session-id` to the default when in session-of-1 mode, overriding
/// any body-supplied value (ACT-SESSIONS §3 "session-of-1").
fn apply_default_session(meta: &mut Metadata, default: &Option<String>) {
    if let Some(id) = default {
        meta.insert(META_SESSION_ID, serde_json::Value::String(id.clone()));
    }
}

/// Format an SseEvent as an axum SSE Event.
fn sse_event_to_axum(event: runtime::SseEvent) -> Option<Result<Event, std::convert::Infallible>> {
    match event {
        runtime::SseEvent::Stream(stream_event) => match stream_event {
            runtime::act::tools::types::ToolEvent::Content(part) => {
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
            runtime::act::tools::types::ToolEvent::Error(err) => {
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

async fn get_info(State(state): State<Arc<AppState>>) -> Json<act_types::ComponentInfo> {
    Json(state.info.clone())
}

async fn list_tools_inner(
    state: &AppState,
    metadata: Option<serde_json::Value>,
) -> axum::response::Response {
    let mut meta = state.metadata.clone();
    if let Some(value) = metadata {
        meta.extend(runtime::Metadata::from(value));
    }
    apply_default_session(&mut meta, &state.default_session_id);

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::ListTools {
        metadata: meta,
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
                        metadata: if meta.is_empty() {
                            None
                        } else {
                            Some(meta.into())
                        },
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
    name: String,
    arguments: Vec<u8>,
    metadata: Vec<(String, Vec<u8>)>,
) -> axum::response::Response {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::CallTool {
        name,
        arguments,
        metadata,
        reply: reply_tx,
        // ACT-HTTP has no interactive channel back to the caller; `ask` is
        // resolved by the DenyPrompter before it ever reaches a sink.
        consent: None,
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
                    runtime::act::tools::types::ToolEvent::Content(part) => {
                        let data = cbor::decode_content_data(&part.data, part.mime_type.as_deref());
                        Some(act_http::ContentPart {
                            data,
                            mime_type: part.mime_type.clone(),
                            metadata: None,
                        })
                    }
                    runtime::act::tools::types::ToolEvent::Error(_) => None,
                })
                .collect();

            let stream_error = result.events.iter().find_map(|event| match event {
                runtime::act::tools::types::ToolEvent::Error(e) => Some(e),
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
    name: String,
    arguments: Vec<u8>,
    metadata: Vec<(String, Vec<u8>)>,
) -> axum::response::Response {
    tracing::debug!(tool = %name, "SSE streaming requested");

    let (event_tx, event_rx) = tokio::sync::mpsc::channel(32);

    let request = runtime::ComponentRequest::CallToolStreaming {
        name,
        arguments,
        metadata,
        event_tx,
    };

    if state.component.send(request).await.is_err() {
        return internal_error_response("component actor unavailable");
    }

    let stream = ReceiverStream::new(event_rx);
    let sse_stream = tokio_stream::StreamExt::filter_map(stream, sse_event_to_axum);

    Sse::new(sse_stream).into_response()
}

/// Parse a JSON body with metadata, accepting empty body as no metadata.
async fn parse_metadata_body(request: Request) -> Result<Option<serde_json::Value>, StatusCode> {
    let body_bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if body_bytes.is_empty() {
        return Ok(None);
    }
    let body: act_http::MetadataRequest =
        serde_json::from_slice(&body_bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(body.metadata)
}

/// Handler for the /tools route that dispatches POST and QUERY methods.
async fn tools_dispatcher(
    state: State<Arc<AppState>>,
    request: Request,
) -> axum::response::Response {
    if request.method() == Method::POST || request.method() == query_method() {
        let metadata = match parse_metadata_body(request).await {
            Ok(m) => m,
            Err(status) => return status.into_response(),
        };
        list_tools_inner(&state, metadata).await
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

    let cbor_args = match cbor::json_to_cbor(&body.arguments) {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let mut metadata = state.metadata.clone();
    if let Some(value) = body.metadata {
        metadata.extend(Metadata::from(value));
    }
    apply_default_session(&mut metadata, &state.default_session_id);

    let metadata_wit: Vec<(String, Vec<u8>)> = metadata.into();

    if wants_sse {
        call_tool_sse(state, name, cbor_args, metadata_wit).await
    } else {
        call_tool_buffered(state, name, cbor_args, metadata_wit).await
    }
}

fn query_method() -> &'static Method {
    static QUERY: std::sync::LazyLock<Method> =
        std::sync::LazyLock::new(|| Method::from_bytes(b"QUERY").expect("QUERY is a valid method"));
    &QUERY
}

// ── Session helpers ────────────────────────────────────────────────────────
//
// Wire types live in `act_types::http` (OpenSessionRequest, OpenSessionResponse).
// Per ACT-SESSIONS.md §6.2.

/// Convert `Metadata` (Vec<(String, CborBytes)>) to a JSON object, dropping
/// entries whose CBOR can't be decoded.
fn metadata_pairs_to_json(
    pairs: &[(String, Vec<u8>)],
) -> serde_json::Map<String, serde_json::Value> {
    pairs
        .iter()
        .filter_map(|(k, v)| Some((k.clone(), cbor::cbor_to_json(v).ok()?)))
        .collect()
}

// ── Session handlers ───────────────────────────────────────────────────────

async fn session_open_args_schema_dispatcher(
    state: State<Arc<AppState>>,
    request: Request,
) -> axum::response::Response {
    if request.method() != Method::POST && request.method() != query_method() {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let metadata_value = match parse_metadata_body(request).await {
        Ok(m) => m,
        Err(status) => return status.into_response(),
    };

    let mut meta = state.metadata.clone();
    if let Some(value) = metadata_value {
        meta.extend(Metadata::from(value));
    }

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::GetOpenSessionArgsSchema {
        metadata: meta.into(),
        reply: reply_tx,
    };

    if state.component.send(request).await.is_err() {
        return internal_error_response("component actor unavailable");
    }

    match reply_rx.await {
        Ok(Ok(schema)) => match serde_json::from_str::<serde_json::Value>(&schema) {
            Ok(v) => Json(v).into_response(),
            Err(_) => internal_error_response("component returned non-JSON schema"),
        },
        Ok(Err(e)) => component_error_response(e),
        Err(_) => internal_error_response("component actor dropped reply"),
    }
}

async fn session_open(
    State(state): State<Arc<AppState>>,
    Json(body): Json<act_http::OpenSessionRequest>,
) -> axum::response::Response {
    let serde_json::Value::Object(args_obj) = body.arguments else {
        return (
            StatusCode::BAD_REQUEST,
            Json(act_http::ErrorResponse {
                error: act_http::ToolError {
                    kind: ERR_INVALID_ARGS.to_string(),
                    message: "arguments must be a JSON object".to_string(),
                    metadata: None,
                },
            }),
        )
            .into_response();
    };

    let mut wit_args: Vec<(String, Vec<u8>)> = Vec::with_capacity(args_obj.len());
    for (key, value) in args_obj {
        match cbor::json_to_cbor(&value) {
            Ok(bytes) => wit_args.push((key, bytes)),
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        }
    }

    let mut meta = state.metadata.clone();
    if let Some(value) = body.metadata {
        meta.extend(Metadata::from(value));
    }

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::OpenSession {
        args: wit_args,
        metadata: meta.into(),
        reply: reply_tx,
        // ACT-HTTP has no interactive channel back to the caller.
        consent: None,
    };

    if state.component.send(request).await.is_err() {
        return internal_error_response("component actor unavailable");
    }

    match reply_rx.await {
        Ok(Ok(session)) => {
            let resp = act_http::OpenSessionResponse {
                id: session.id,
                metadata: metadata_pairs_to_json(&session.metadata),
            };
            (StatusCode::CREATED, Json(resp)).into_response()
        }
        Ok(Err(e)) => component_error_response(e),
        Err(_) => internal_error_response("component actor dropped reply"),
    }
}

async fn session_close(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> axum::response::Response {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::CloseSession {
        session_id,
        reply: reply_tx,
    };

    if state.component.send(request).await.is_err() {
        return internal_error_response("component actor unavailable");
    }

    match reply_rx.await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => component_error_response(e),
        Err(_) => internal_error_response("component actor dropped reply"),
    }
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

pub fn create_router(state: Arc<AppState>) -> Router {
    let mut router = Router::new()
        .route("/info", get(get_info))
        .route("/tools", axum::routing::any(tools_dispatcher))
        .route("/tools/{name}", axum::routing::any(tool_call_dispatcher));

    // Session-of-1 hides the session machinery (ACT-SESSIONS §3): when a
    // default session is pre-opened, the component looks stateless and the
    // lifecycle endpoints are absent (404).
    if state.default_session_id.is_none() {
        router = router
            .route(
                "/sessions/open-args-schema",
                axum::routing::any(session_open_args_schema_dispatcher),
            )
            .route("/sessions", axum::routing::post(session_open))
            .route("/sessions/{id}", axum::routing::delete(session_close));
    }

    router
        .layer(middleware::from_fn(protocol_version_layer))
        .with_state(state)
}

// ── Router ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kind_maps_not_found() {
        assert_eq!(error_kind_to_status("std:not-found"), StatusCode::NOT_FOUND);
    }

    #[test]
    fn error_kind_maps_invalid_args() {
        assert_eq!(
            error_kind_to_status("std:invalid-args"),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[test]
    fn error_kind_maps_unknown_to_500() {
        assert_eq!(
            error_kind_to_status("something_unknown"),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn query_method_is_valid() {
        assert_eq!(query_method().as_str(), "QUERY");
    }

    #[test]
    fn apply_default_session_overrides_and_skips() {
        // Some(id): inject, overriding any existing value.
        let mut meta = Metadata::from(serde_json::json!({"std:session-id": "client"}));
        apply_default_session(&mut meta, &Some("sid_default".to_string()));
        assert_eq!(
            meta.get_as::<String>(META_SESSION_ID).as_deref(),
            Some("sid_default")
        );

        // None: leave metadata untouched.
        let mut meta2 = Metadata::from(serde_json::json!({"std:session-id": "client"}));
        apply_default_session(&mut meta2, &None);
        assert_eq!(
            meta2.get_as::<String>(META_SESSION_ID).as_deref(),
            Some("client")
        );
    }
}
