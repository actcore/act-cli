use crate::runtime;
use act_types::cbor;
use act_types::constants::{
    ERR_CAPABILITY_DENIED, ERR_INVALID_ARGS, ERR_NOT_FOUND, META_SESSION_OP,
};
use rmcp::ErrorData;
use rmcp::model::{ContentBlock, ErrorCode, Tool};
use serde_json::Value;
use std::borrow::Cow;
use std::sync::Arc;

/// Synthetic MCP tool name that maps to `session-provider.open-session`.
/// Per ACT-MCP §4.1 / ACT-CONSTANTS §3.1 these names are reserved.
const VIRTUAL_OPEN_SESSION: &str = "open_session";
const VIRTUAL_CLOSE_SESSION: &str = "close_session";

/// JSON Schema property name for the argument metadata channel
/// (ACT-MCP §3.2). The adapter strips this from `params.arguments`
/// before forwarding to the component and folds its contents into the
/// WIT `metadata` parameter.
const ARG_META_KEY: &str = "_meta";

const ARG_META_DESCRIPTION: &str = "ACT metadata. Include {\"std:session-id\": \"<id from open_session>\"} for \
     session-bound tools. Other recognized keys: std:traceparent, std:locale.";

/// ACT's MCP `_meta` prefix — reverse-DNS form of `actcore.dev`, per the
/// MCP `_meta` SHOULD ("Implementations SHOULD use reverse DNS notation").
/// Not reserved: reservation applies to prefixes whose *second* label is
/// `modelcontextprotocol` or `mcp`.
const MCP_META_PREFIX: &str = "dev.actcore/";

/// The ACT well-known namespace. `:` is not a legal MCP `_meta` name
/// character, so `std:` keys are respelled with `MCP_META_PREFIX` on the
/// wire. This is a *key* transform only — kind strings, which are values,
/// keep their `std:` form.
const ACT_STD_PREFIX: &str = "std:";

pub struct ActRmcpBridge {
    pub handle: runtime::ComponentHandle,
    pub info: runtime::ComponentInfo,
    pub metadata: runtime::Metadata,
    /// Whether the underlying component exports
    /// `act:sessions/session-provider`. Controls synthesis of virtual
    /// `open_session`/`close_session` tools and routing of those calls.
    pub has_sessions: bool,
    /// When `Some`, the host pre-opened a single default session
    /// (session-of-1, ACT-SESSIONS §3): session machinery is hidden and
    /// this id is forced into every call's `std:session-id` metadata,
    /// overriding any client-supplied value.
    pub default_session_id: Option<String>,
}

fn map_content_part(part: &runtime::act::tools::types::ContentPart) -> ContentBlock {
    let mime = part.mime_type.as_deref().unwrap_or("");

    // UTF-8 text-like payloads surface as MCP text content verbatim. This
    // covers `text/*` and JSON (`application/json`, `application/*+json`) —
    // JSON bytes are UTF-8, not CBOR, so they must not hit the base64 path
    // below. Matches the ACT-HTTP transport, which also treats JSON as text.
    if mime.starts_with("text/") || mime == "application/json" || mime.ends_with("+json") {
        let text = String::from_utf8_lossy(&part.data).into_owned();
        return ContentBlock::text(text);
    }

    if mime.starts_with("image/") {
        use base64::Engine as _;
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(&part.data);
        return ContentBlock::image(data_b64, mime.to_string());
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
    ContentBlock::text(text)
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
    defs: &[runtime::act::tools::types::ToolDefinition],
    inject_arg_meta: bool,
) -> Vec<Tool> {
    defs.iter()
        .map(|td| {
            let description = act_types::types::LocalizedString::from(&td.description)
                .any_text()
                .to_string();

            let input_schema: Value = serde_json::from_str(&td.parameters_schema)
                .unwrap_or_else(|_| serde_json::json!({"type": "object"}));

            let mut schema_map: serde_json::Map<String, Value> =
                input_schema.as_object().cloned().unwrap_or_default();

            if inject_arg_meta {
                inject_arg_meta_property(&mut schema_map);
            }

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

/// Add an optional `_meta` object property to a tool's JSON Schema so
/// the agent can supply `std:*` metadata keys through the argument
/// metadata channel (ACT-MCP §3.2). `_meta` is added as a *known*
/// property; the component-declared `additionalProperties` restriction
/// (if any) on other keys is preserved as-is.
fn inject_arg_meta_property(schema: &mut serde_json::Map<String, Value>) {
    let properties = schema
        .entry("properties".to_string())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));

    if let Value::Object(props) = properties {
        props.insert(
            ARG_META_KEY.to_string(),
            serde_json::json!({
                "type": "object",
                "description": ARG_META_DESCRIPTION,
                "additionalProperties": true,
            }),
        );
    }
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
            runtime::act::tools::types::ToolEvent::Content(part) => {
                content.push(map_content_part(part));
            }
            runtime::act::tools::types::ToolEvent::Error(err) => {
                is_error = true;
                let message = act_types::types::LocalizedString::from(&err.message)
                    .any_text()
                    .to_string();
                content.push(rmcp::model::ContentBlock::text(message));
            }
        }
    }

    if is_error {
        rmcp::model::CallToolResult::error(content)
    } else {
        rmcp::model::CallToolResult::success(content)
    }
}

/// Await the actor's reply while answering consent questions on *this* task.
///
/// From protocol revision `2026-07-28` rmcp refuses a server-to-client request
/// that is not associated with an in-flight client request (SEP-2260), and it
/// tracks that with a task-local it installs around the handler future. The
/// guest runs on the actor task, so its capability gates cannot elicit for
/// themselves — they hand the question here instead. See `runtime::elicit`.
async fn await_reply_servicing_consent<T>(
    context: &rmcp::service::RequestContext<rmcp::RoleServer>,
    mut consent_rx: tokio::sync::mpsc::Receiver<crate::runtime::elicit::ConsentRequest>,
    mut reply_rx: tokio::sync::oneshot::Receiver<T>,
) -> Result<T, rmcp::ErrorData> {
    let capabilities = context.client_capabilities();
    let reply = loop {
        tokio::select! {
            biased;
            // Answer consent first: the guest is blocked until the answer lands.
            Some(ask) = consent_rx.recv() => {
                let decision = crate::runtime::elicit::confirm_via_peer(
                    &context.peer,
                    capabilities.as_ref(),
                    ask.message,
                )
                .await;
                let _ = ask.reply.send(decision);
            }
            reply = &mut reply_rx => break reply,
        }
    };
    reply.map_err(|_| {
        rmcp::ErrorData::new(
            rmcp::model::ErrorCode::INTERNAL_ERROR,
            "component actor dropped reply",
            None,
        )
    })
}

// ── Public entry point ──────────────────────────────────────────────────────

pub async fn run_stdio(
    info: runtime::ComponentInfo,
    handle: runtime::ComponentHandle,
    metadata: runtime::Metadata,
    has_sessions: bool,
    default_session_id: Option<String>,
) -> anyhow::Result<()> {
    let bridge = ActRmcpBridge {
        handle,
        info,
        metadata,
        has_sessions,
        default_session_id,
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

/// Serve the component over MCP Streamable HTTP (the official MCP HTTP
/// transport). Every connection gets its own `ActRmcpBridge` front-end, but
/// they all dispatch into the same `ComponentHandle` — one component instance
/// per process, matching the model the ACT-HTTP server uses.
///
/// Note that MCP's own sessions are not what holds ACT state, and from
/// revision `2026-07-28` they no longer exist at all (`Mcp-Session-Id` was
/// removed so that any instance may serve any request). An ACT session is
/// transient component-level state living in this process: it lasts as long as
/// the instance does, and `std:session-not-found` is an ordinary outcome the
/// client recovers from by reopening. Spreading sessions across instances is a
/// cluster-runtime concern, deliberately outside this host.
pub async fn run_http(
    addr: std::net::SocketAddr,
    info: runtime::ComponentInfo,
    handle: runtime::ComponentHandle,
    metadata: runtime::Metadata,
    has_sessions: bool,
    default_session_id: Option<String>,
) -> anyhow::Result<()> {
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    };

    let service = StreamableHttpService::new(
        move || {
            Ok(ActRmcpBridge {
                handle: handle.clone(),
                info: info.clone(),
                metadata: metadata.clone(),
                has_sessions,
                default_session_id: default_session_id.clone(),
            })
        },
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );

    let router = axum::Router::new().route_service("/mcp", service);

    tracing::info!(%addr, "ACT MCP/HTTP listening on /mcp");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router)
        .await
        .map_err(|e| anyhow::anyhow!("MCP HTTP server error: {e}"))?;
    Ok(())
}

// ── ServerHandler impl ──────────────────────────────────────────────────────

impl ActRmcpBridge {
    /// Whether session lifecycle ops are exposed to clients. False in
    /// session-of-1 mode (a default session is pre-opened and hidden).
    fn expose_sessions(&self) -> bool {
        self.has_sessions && self.default_session_id.is_none()
    }

    /// Base metadata for non-call requests (list-tools, schema fetch),
    /// with the default session-id injected when in session-of-1 mode.
    fn base_metadata(&self) -> runtime::Metadata {
        let mut meta = self.metadata.clone();
        force_session_id(&mut meta, &self.default_session_id);
        meta
    }

    async fn list_tools_impl(&self) -> Result<rmcp::model::ListToolsResult, rmcp::ErrorData> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let req = runtime::ComponentRequest::ListTools {
            metadata: self.base_metadata(),
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

        // Per ACT-MCP §3.2, adapters MUST inject the `_meta` argument
        // property into tools of components exporting session-provider
        // so agents can supply `std:session-id` (and other `std:*`
        // keys) without relying on transport-level `_meta`. In
        // session-of-1 mode the host forces the session-id, so the hint
        // is suppressed — the agent must NOT be prompted to supply it.
        let mut tools = convert_tool_definitions(&list.tools, self.expose_sessions());

        if self.expose_sessions() {
            let open_schema = self.fetch_open_session_args_schema().await?;
            tools.push(virtual_open_session_tool(open_schema));
            tools.push(virtual_close_session_tool());
        }

        // `with_all_items` sets the SEP-2322 `resultType: "complete"`
        // discriminator and leaves the SEP-2549 cache hints (`ttlMs`,
        // `cacheScope`) unset. rmcp strips `resultType` again when the peer
        // negotiated a pre-2026-07-28 version.
        Ok(rmcp::model::ListToolsResult::with_all_items(tools))
    }

    /// Ask the component for its `get-open-session-args-schema` JSON Schema.
    /// Errors bubble up as MCP errors so the agent sees them at list_tools time.
    async fn fetch_open_session_args_schema(&self) -> Result<Value, rmcp::ErrorData> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let req = runtime::ComponentRequest::GetOpenSessionArgsSchema {
            metadata: self.metadata.clone().into(),
            reply: reply_tx,
        };
        self.handle.send(req).await.map_err(|_| {
            rmcp::ErrorData::new(
                rmcp::model::ErrorCode::INTERNAL_ERROR,
                "component actor unavailable",
                None,
            )
        })?;
        let schema = reply_rx
            .await
            .map_err(|_| {
                rmcp::ErrorData::new(
                    rmcp::model::ErrorCode::INTERNAL_ERROR,
                    "component actor dropped reply",
                    None,
                )
            })?
            .map_err(component_error_to_mcp)?;
        serde_json::from_str::<Value>(&schema).map_err(|e| {
            rmcp::ErrorData::new(
                rmcp::model::ErrorCode::INTERNAL_ERROR,
                format!("component returned non-JSON schema: {e}"),
                None,
            )
        })
    }

    async fn call_tool_impl(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: &rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
        use rmcp::model::ErrorCode;

        let ctx_meta = &context.meta;

        // Route reserved virtual tools (`open_session` / `close_session`)
        // before any argument-level `_meta` extraction. Virtual tools
        // are session-lifecycle ops, not session-bound capability calls,
        // so they do not participate in the argument metadata channel.
        if self.expose_sessions() {
            match request.name.as_ref() {
                VIRTUAL_OPEN_SESSION => {
                    let mut call_metadata = self.metadata.clone();
                    apply_transport_meta(&mut call_metadata, ctx_meta);
                    return self
                        .virtual_open_session(request.arguments, call_metadata, context)
                        .await;
                }
                VIRTUAL_CLOSE_SESSION => {
                    let mut call_metadata = self.metadata.clone();
                    apply_transport_meta(&mut call_metadata, ctx_meta);
                    return self
                        .virtual_close_session(request.arguments, call_metadata)
                        .await;
                }
                _ => {}
            }
        }

        // Extract the argument metadata channel (ACT-MCP §3.2): pop
        // `_meta` from `params.arguments` so the component sees only
        // its declared schema, then fold its contents into the WIT
        // metadata. Precedence (ACT-MCP §3.3): adapter-cached <
        // arguments._meta < transport _meta.
        let mut arguments_obj = request.arguments.unwrap_or_default();
        let arg_meta = arguments_obj.remove(ARG_META_KEY);

        let mut call_metadata = self.metadata.clone();
        if let Some(Value::Object(map)) = arg_meta {
            call_metadata.extend(act_types::types::Metadata::from(Value::Object(map)));
        }
        apply_transport_meta(&mut call_metadata, ctx_meta);
        // Session-of-1: force the pre-opened default id over any
        // client-supplied std:session-id so the façade stays stateless.
        force_session_id(&mut call_metadata, &self.default_session_id);

        let cbor_args =
            act_types::cbor::json_to_cbor(&Value::Object(arguments_obj)).map_err(|_| {
                rmcp::ErrorData::new(ErrorCode::INVALID_PARAMS, "invalid arguments", None)
            })?;

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        // Capability gates fire on the actor task, which is outside the scope
        // rmcp requires for a server-to-client request (SEP-2260). They send
        // their question here instead, so the elicitation is issued on *this*
        // task — the one handling the originating `tools/call`. Depth 1: the
        // actor runs one call at a time and blocks on each answer.
        let (consent_tx, consent_rx) =
            tokio::sync::mpsc::channel::<crate::runtime::elicit::ConsentRequest>(1);

        let req = runtime::ComponentRequest::CallTool {
            name: request.name.to_string(),
            arguments: cbor_args,
            metadata: call_metadata.into(),
            reply: reply_tx,
            consent: Some(consent_tx),
        };

        self.handle.send(req).await.map_err(|_| {
            rmcp::ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                "component actor unavailable",
                None,
            )
        })?;

        let result = await_reply_servicing_consent(context, consent_rx, reply_rx)
            .await?
            .map_err(component_error_to_mcp)?;

        Ok(fold_events_to_result(result))
    }

    async fn virtual_open_session(
        &self,
        arguments: Option<rmcp::model::JsonObject>,
        metadata: runtime::Metadata,
        context: &rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
        let args_obj = arguments.unwrap_or_default();
        let mut wit_args: Vec<(String, Vec<u8>)> = Vec::with_capacity(args_obj.len());
        for (key, value) in args_obj {
            let cbor_bytes = cbor::json_to_cbor(&value).map_err(|_| {
                rmcp::ErrorData::new(
                    rmcp::model::ErrorCode::INVALID_PARAMS,
                    format!("encoding `{key}` as CBOR failed"),
                    None,
                )
            })?;
            wit_args.push((key, cbor_bytes));
        }

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        // A bridge does its network I/O while opening the session, so this is
        // where its capability gate usually fires — route consent the same way.
        let (consent_tx, consent_rx) =
            tokio::sync::mpsc::channel::<crate::runtime::elicit::ConsentRequest>(1);
        let req = runtime::ComponentRequest::OpenSession {
            args: wit_args,
            metadata: metadata.into(),
            reply: reply_tx,
            consent: Some(consent_tx),
        };
        self.handle.send(req).await.map_err(|_| {
            rmcp::ErrorData::new(
                rmcp::model::ErrorCode::INTERNAL_ERROR,
                "component actor unavailable",
                None,
            )
        })?;
        let session = await_reply_servicing_consent(context, consent_rx, reply_rx)
            .await?
            .map_err(component_error_to_mcp)?;

        let metadata_json: serde_json::Map<String, Value> = session
            .metadata
            .iter()
            .filter_map(|(k, v)| Some((k.clone(), cbor::cbor_to_json(v).ok()?)))
            .collect();
        let payload = serde_json::json!({
            "id": session.id,
            "metadata": metadata_json,
        });
        let json_text = serde_json::to_string(&payload).unwrap_or_default();

        Ok(rmcp::model::CallToolResult::success(vec![
            ContentBlock::text(json_text),
        ]))
    }

    async fn virtual_close_session(
        &self,
        arguments: Option<rmcp::model::JsonObject>,
        _metadata: runtime::Metadata,
    ) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
        let session_id = arguments
            .as_ref()
            .and_then(|obj| obj.get("session_id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                rmcp::ErrorData::new(
                    rmcp::model::ErrorCode::INVALID_PARAMS,
                    "close_session requires `session_id` (string)",
                    None,
                )
            })?
            .to_string();

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let req = runtime::ComponentRequest::CloseSession {
            session_id,
            reply: reply_tx,
        };
        self.handle.send(req).await.map_err(|_| {
            rmcp::ErrorData::new(
                rmcp::model::ErrorCode::INTERNAL_ERROR,
                "component actor unavailable",
                None,
            )
        })?;
        reply_rx
            .await
            .map_err(|_| {
                rmcp::ErrorData::new(
                    rmcp::model::ErrorCode::INTERNAL_ERROR,
                    "component actor dropped reply",
                    None,
                )
            })?
            .map_err(component_error_to_mcp)?;
        Ok(rmcp::model::CallToolResult::success(vec![]))
    }
}

/// Build the synthetic `open_session` MCP tool. The args schema comes from
/// `get-open-session-args-schema`. `_meta.std:session-op = "open"`
/// per ACT-CONSTANTS so agents can recognize this is a session-lifecycle
/// tool, not an ordinary capability.
fn virtual_open_session_tool(args_schema: Value) -> Tool {
    let mut schema_map: serde_json::Map<String, Value> =
        args_schema.as_object().cloned().unwrap_or_default();
    schema_map
        .entry("type".to_string())
        .or_insert(Value::String("object".into()));

    let mut tool = Tool::new(
        Cow::Borrowed(VIRTUAL_OPEN_SESSION),
        Cow::Borrowed("Open a new session against this component."),
        Arc::new(schema_map),
    );
    tool = tool.with_meta(session_op_meta("open"));
    tool
}

/// Build the synthetic `close_session` MCP tool. Args is fixed:
/// `{ session_id: string }`. `_meta.std:session-op = "close"`.
fn virtual_close_session_tool() -> Tool {
    let schema_map: serde_json::Map<String, Value> = serde_json::json!({
        "type": "object",
        "properties": {
            "session_id": {
                "type": "string",
                "description": "Session-id returned by `open_session`."
            }
        },
        "required": ["session_id"],
        "additionalProperties": false,
    })
    .as_object()
    .cloned()
    .unwrap_or_default();

    let mut tool = Tool::new(
        Cow::Borrowed(VIRTUAL_CLOSE_SESSION),
        Cow::Borrowed("Close a session previously opened via `open_session`."),
        Arc::new(schema_map),
    );
    tool = tool.with_meta(session_op_meta("close"));
    tool
}

fn session_op_meta(op: &'static str) -> rmcp::model::MetaObject {
    let mut map = serde_json::Map::new();
    map.insert(META_SESSION_OP.to_string(), Value::String(op.to_string()));
    rmcp::model::MetaObject(map)
}

/// Force `std:session-id` to `default` when set, overriding any existing
/// value. Used in session-of-1 mode so the hidden default session wins over
/// client-supplied ids (ACT-SESSIONS §3 "session-of-1").
fn force_session_id(meta: &mut act_types::types::Metadata, default: &Option<String>) {
    if let Some(id) = default {
        meta.insert(
            act_types::constants::META_SESSION_ID,
            Value::String(id.clone()),
        );
    }
}

/// Merge the MCP transport-level `_meta` (lifted by rmcp into
/// `RequestContext::meta`) onto `call_metadata`. Per ACT-MCP §3.3 the
/// transport channel overrides any same-keyed value already present
/// (argument-level `_meta` or adapter-cached defaults).
/// Keys MCP reserves for the protocol itself, which must not reach the guest.
///
/// They describe the transport hop, not the call. From revision `2026-07-28`
/// the `io.modelcontextprotocol/*` keys ride on *every* request (SEP-2575:
/// protocol version, client info, client capabilities, log level), so
/// forwarding them would hand a sandboxed component the connecting client's
/// identity and capabilities on every single call — data the caller never
/// asked to share and the component has no business knowing.
fn is_protocol_reserved(key: &str) -> bool {
    key == "progressToken" || key.starts_with("io.modelcontextprotocol/")
}

/// Respell an inbound MCP `_meta` key as an ACT metadata key.
/// Only the `dev.actcore/` prefix is mapped; everything else crosses
/// verbatim. The outbound counterpart, `act_key_to_mcp`, arrives in Task 2
/// with its first production caller.
fn mcp_key_to_act(key: &str) -> Cow<'_, str> {
    match key.strip_prefix(MCP_META_PREFIX) {
        Some(name) => Cow::Owned(format!("{ACT_STD_PREFIX}{name}")),
        None => Cow::Borrowed(key),
    }
}

/// Merge the transport `_meta` channel (ACT-MCP §3.1) into the call metadata,
/// minus the protocol's own reserved keys.
fn apply_transport_meta(
    call_metadata: &mut act_types::types::Metadata,
    ctx_meta: &rmcp::model::MetaObject,
) {
    let mut forwarded = serde_json::Map::new();

    // Two passes so the conformant spelling deterministically wins when a
    // client sends both: legacy `std:*` first, `dev.actcore/*` second.
    for (key, value) in ctx_meta.0.iter() {
        if !is_protocol_reserved(key) && !key.starts_with(MCP_META_PREFIX) {
            forwarded.insert(key.clone(), value.clone());
        }
    }
    for (key, value) in ctx_meta.0.iter() {
        if !is_protocol_reserved(key) && key.starts_with(MCP_META_PREFIX) {
            forwarded.insert(mcp_key_to_act(key).into_owned(), value.clone());
        }
    }

    if !forwarded.is_empty() {
        call_metadata.extend(act_types::types::Metadata::from(Value::Object(forwarded)));
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
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl std::future::Future<Output = Result<rmcp::model::ListToolsResult, rmcp::ErrorData>>
    + Send
    + '_ {
        // `list-tools` runs without a consent sink: a capability touched here
        // has no in-flight `tools/call` to hang an elicitation off, so the
        // gate denies rather than prompting. See `runtime::elicit`.
        let _ = context;
        self.list_tools_impl()
    }

    /// rmcp 3 widened the return type to `CallToolResponse` (SEP-2322 MRTR /
    /// SEP-2663 Tasks). ACT always completes a `tools/call` in one round trip
    /// — consent is elicited live on this task while the guest runs — so we
    /// only ever produce `CallToolResponse::Complete`.
    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, rmcp::ErrorData> {
        self.call_tool_impl(request, &context)
            .await
            .map(rmcp::model::CallToolResponse::Complete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_meta_drops_protocol_reserved_keys() {
        let mut meta = act_types::types::Metadata::default();
        let ctx = rmcp::model::MetaObject(
            serde_json::json!({
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": {"name": "some-agent"},
                "io.modelcontextprotocol/clientCapabilities": {"elicitation": {}},
                "progressToken": 7,
                "std:session-id": "sid_42",
                "std:traceparent": "00-abc-def-01",
            })
            .as_object()
            .unwrap()
            .clone(),
        );

        apply_transport_meta(&mut meta, &ctx);

        // The caller's own keys still reach the component...
        assert_eq!(meta.get("std:session-id").unwrap(), "sid_42");
        assert_eq!(meta.get("std:traceparent").unwrap(), "00-abc-def-01");
        // ...while the protocol's transport plumbing does not.
        for reserved in [
            "io.modelcontextprotocol/protocolVersion",
            "io.modelcontextprotocol/clientInfo",
            "io.modelcontextprotocol/clientCapabilities",
            "progressToken",
        ] {
            assert!(
                !meta.contains_key(reserved),
                "`{reserved}` must not be forwarded to the guest"
            );
        }
    }

    #[test]
    fn actcore_prefixed_keys_map_back_to_the_std_namespace() {
        assert_eq!(mcp_key_to_act("dev.actcore/session-id"), "std:session-id");

        // Third-party namespaces cross verbatim: ACT does not own them and
        // must not mint keys inside them.
        assert_eq!(mcp_key_to_act("acme:priority"), "acme:priority");
        assert_eq!(mcp_key_to_act("traceparent"), "traceparent");
    }

    #[test]
    fn transport_meta_accepts_both_session_id_spellings() {
        let mut meta = act_types::types::Metadata::default();
        let ctx = rmcp::model::MetaObject(
            serde_json::json!({ "dev.actcore/session-id": "sid_new" })
                .as_object()
                .unwrap()
                .clone(),
        );
        apply_transport_meta(&mut meta, &ctx);
        assert_eq!(meta.get("std:session-id").unwrap(), "sid_new");

        // The legacy spelling keeps working for clients already sending it.
        let mut legacy = act_types::types::Metadata::default();
        let ctx = rmcp::model::MetaObject(
            serde_json::json!({ "std:session-id": "sid_old" })
                .as_object()
                .unwrap()
                .clone(),
        );
        apply_transport_meta(&mut legacy, &ctx);
        assert_eq!(legacy.get("std:session-id").unwrap(), "sid_old");
    }

    #[test]
    fn conformant_session_id_wins_over_the_legacy_spelling() {
        let mut meta = act_types::types::Metadata::default();
        let ctx = rmcp::model::MetaObject(
            serde_json::json!({
                "std:session-id": "sid_legacy",
                "dev.actcore/session-id": "sid_conformant",
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        apply_transport_meta(&mut meta, &ctx);
        assert_eq!(meta.get("std:session-id").unwrap(), "sid_conformant");
    }

    // act:tools@0.2.0 split the data model out of the provider interface into
    // `act:tools/types`; `error` / `localized-string` resolve through `act:core`.
    use crate::runtime::act::core::types as runtime_core;
    use crate::runtime::act::core::types::{Error, LocalizedString};
    use crate::runtime::act::tools::types as runtime_types;
    use crate::runtime::act::tools::types::{ContentPart, ToolDefinition};
    use rmcp::model::{ContentBlock, ErrorCode};

    fn part(mime: Option<&str>, data: &[u8]) -> ContentPart {
        ContentPart {
            data: data.to_vec(),
            mime_type: mime.map(str::to_string),
            metadata: vec![],
        }
    }

    fn content_text(c: &ContentBlock) -> Option<&str> {
        match c {
            ContentBlock::Text(t) => Some(&t.text),
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
        match &c {
            ContentBlock::Image(img) => {
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
    fn map_content_json_decodes_to_text() {
        // application/json content (UTF-8 JSON bytes, as emitted by act-sdk's
        // `Json<T>`) must surface as the literal JSON string — NOT base64.
        let json = br#"{"id":1,"name":"Fixture WS"}"#;
        let c = map_content_part(&part(Some("application/json"), json));
        let text = content_text(&c).expect("json must become text");
        assert_eq!(text, r#"{"id":1,"name":"Fixture WS"}"#);
    }

    #[test]
    fn map_content_json_suffix_decodes_to_text() {
        let body = br#"{"ok":true}"#;
        let c = map_content_part(&part(Some("application/vnd.api+json"), body));
        let text = content_text(&c).expect("+json must become text");
        assert_eq!(text, r#"{"ok":true}"#);
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

    fn bridge_with_default(default: Option<&str>) -> ActRmcpBridge {
        ActRmcpBridge {
            handle: fake_handle(),
            info: fake_info(),
            metadata: runtime::Metadata::default(),
            has_sessions: true,
            default_session_id: default.map(str::to_string),
        }
    }

    #[test]
    fn expose_sessions_false_when_default_set() {
        assert!(
            !bridge_with_default(Some("sid_0")).expose_sessions(),
            "session-of-1 must hide session machinery"
        );
        assert!(
            bridge_with_default(None).expose_sessions(),
            "without a default session, machinery stays exposed"
        );
    }

    #[test]
    fn base_metadata_injects_default_session_id() {
        let meta = bridge_with_default(Some("sid_0")).base_metadata();
        assert_eq!(
            meta.get_as::<String>(act_types::constants::META_SESSION_ID)
                .as_deref(),
            Some("sid_0"),
            "base metadata must carry the default session-id"
        );
        let none = bridge_with_default(None).base_metadata();
        assert!(
            none.get_as::<String>(act_types::constants::META_SESSION_ID)
                .is_none(),
            "no default → no session-id seeded"
        );
    }

    #[test]
    fn force_session_id_overrides_client_value() {
        let mut meta = act_types::types::Metadata::from(serde_json::json!({
            "std:session-id": "client-supplied",
        }));
        force_session_id(&mut meta, &Some("sid_default".to_string()));
        assert_eq!(
            meta.get_as::<String>(act_types::constants::META_SESSION_ID)
                .as_deref(),
            Some("sid_default"),
            "default must override client-supplied session-id"
        );

        let mut meta2 = act_types::types::Metadata::from(serde_json::json!({
            "std:session-id": "client-supplied",
        }));
        force_session_id(&mut meta2, &None);
        assert_eq!(
            meta2
                .get_as::<String>(act_types::constants::META_SESSION_ID)
                .as_deref(),
            Some("client-supplied"),
            "no default → client value preserved"
        );
    }

    #[test]
    fn get_info_exposes_server_name_version_and_tools_capability() {
        let bridge = ActRmcpBridge {
            handle: fake_handle(),
            info: fake_info(),
            metadata: runtime::Metadata::default(),
            has_sessions: false,
            default_session_id: None,
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
        let tools = convert_tool_definitions(&defs, false);

        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name.as_ref(), "alpha");
        assert_eq!(tools[0].description.as_deref(), Some("alpha tool"));

        let schema: &serde_json::Map<String, serde_json::Value> = tools[0].input_schema.as_ref();
        let props = schema["properties"].as_object().unwrap();
        assert!(
            props.contains_key("n"),
            "original property must be preserved"
        );
        assert!(
            !props.contains_key("_meta"),
            "no _meta injection when inject_arg_meta=false"
        );
    }

    #[test]
    fn list_tools_injects_meta_for_session_provider_components() {
        let defs = vec![fake_tool("query")];
        let tools = convert_tool_definitions(&defs, true);

        let schema: &serde_json::Map<String, serde_json::Value> = tools[0].input_schema.as_ref();
        let props = schema["properties"].as_object().unwrap();
        assert!(
            props.contains_key("n"),
            "original property must be preserved"
        );
        let meta_prop = props
            .get("_meta")
            .expect("`_meta` property must be injected (ACT-MCP §3.2)");
        assert_eq!(meta_prop["type"], "object");
        assert_eq!(meta_prop["additionalProperties"], true);
        assert!(
            meta_prop["description"]
                .as_str()
                .unwrap_or("")
                .contains("std:session-id"),
            "description must mention std:session-id so LLM knows the convention"
        );
    }

    #[test]
    fn inject_meta_creates_properties_when_missing() {
        // Bare `{"type":"object"}` schema — no `properties` key at all.
        let mut schema: serde_json::Map<String, Value> = serde_json::json!({"type": "object"})
            .as_object()
            .cloned()
            .unwrap();
        inject_arg_meta_property(&mut schema);
        let props = schema["properties"].as_object().unwrap();
        assert!(props.contains_key("_meta"));
    }

    #[test]
    fn transport_meta_overrides_arguments_meta() {
        // Precedence rule from ACT-MCP §3.3: when both channels carry
        // the same key, transport wins.
        let mut call_metadata = act_types::types::Metadata::default();

        // Argument _meta says session A.
        call_metadata.extend(act_types::types::Metadata::from(serde_json::json!({
            "std:session-id": "from-args",
        })));

        // Transport _meta says session B — must win.
        let ctx = rmcp::model::MetaObject(
            serde_json::json!({"std:session-id": "from-transport"})
                .as_object()
                .cloned()
                .unwrap(),
        );
        apply_transport_meta(&mut call_metadata, &ctx);

        let final_id = call_metadata
            .get_as::<String>(act_types::constants::META_SESSION_ID)
            .expect("std:session-id must be set");
        assert_eq!(
            final_id, "from-transport",
            "transport `_meta` wins over arguments `_meta`"
        );
    }

    #[test]
    fn arguments_meta_supplies_keys_absent_from_transport() {
        // When a key is only in argument _meta, it survives the merge.
        let mut call_metadata = act_types::types::Metadata::default();
        call_metadata.extend(act_types::types::Metadata::from(serde_json::json!({
            "std:session-id": "abc",
            "std:traceparent": "00-...-...",
        })));
        // Transport carries an unrelated key.
        let ctx = rmcp::model::MetaObject(
            serde_json::json!({"std:request-id": "req-99"})
                .as_object()
                .cloned()
                .unwrap(),
        );
        apply_transport_meta(&mut call_metadata, &ctx);

        assert_eq!(
            call_metadata
                .get_as::<String>(act_types::constants::META_SESSION_ID)
                .as_deref(),
            Some("abc")
        );
        assert!(call_metadata.contains_key("std:traceparent"));
        assert!(call_metadata.contains_key("std:request-id"));
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
            runtime_types::ToolEvent::Error(runtime_core::Error {
                kind: act_types::constants::ERR_INTERNAL.to_string(),
                message: runtime_core::LocalizedString::Plain("boom mid-stream".into()),
                metadata: vec![],
            }),
        ];
        let result = fold_events_to_result(ActCallToolResult { events });
        assert_eq!(result.is_error, Some(true));
        assert_eq!(result.content.len(), 2);
        match &result.content[1] {
            ContentBlock::Text(t) => assert!(t.text.contains("boom mid-stream")),
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
