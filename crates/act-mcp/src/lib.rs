//! The projection between ACT components and MCP.
//!
//! Every host that speaks MCP on behalf of an ACT component needs the same
//! translation: tool definitions into `rmcp` tools with the `_meta` argument
//! property ACT-MCP §3.2 requires, content parts into content blocks, tool
//! events folded into a result, component errors into MCP errors, and the
//! synthetic `open_session` / `close_session` tools a session-provider gets.
//!
//! It lives in its own crate because there is more than one such host. The
//! `act` CLI serves a single component; the toolserver serves many at once
//! under one endpoint. A second copy of this would be a second reading of a
//! normative spec, drifting from the first, and the copy without the tests
//! would be the one that rots.
//!
//! What stays with a host is how it is served — transports, the `ServerHandler`
//! it implements, how it finds the component to talk to. Only the translation
//! is here.

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
pub const VIRTUAL_OPEN_SESSION: &str = "open_session";
pub const VIRTUAL_CLOSE_SESSION: &str = "close_session";

/// JSON Schema property name for the argument metadata channel
/// (ACT-MCP §3.2). The adapter strips this from `params.arguments`
/// before forwarding to the component and folds its contents into the
/// WIT `metadata` parameter.
pub const ARG_META_KEY: &str = "_meta";

// `std:traceparent` is deliberately absent from this list: advertising it as
// a recognised argument-channel key would invite exactly the forgery
// `strip_trace_keys` below closes off. Trace context is transport-only.
pub const ARG_META_DESCRIPTION: &str = "ACT metadata. Include {\"std:session-id\": \"<id from open_session>\"} for \
     session-bound tools. Other recognized keys: std:locale.";

/// Trace-context / correlation keys that must be sourced from the transport
/// `_meta` channel exclusively — see `trace_metadata_from_meta` and
/// `strip_trace_keys`.
pub const TRACE_META_KEYS: [&str; 4] = [
    act_types::constants::META_TRACEPARENT,
    act_types::constants::META_TRACESTATE,
    act_types::constants::META_AGENT_ID,
    act_types::constants::META_REQUEST_ID,
];

/// ACT's MCP `_meta` prefix — reverse-DNS form of `actcore.dev`, per the
/// MCP `_meta` SHOULD ("Implementations SHOULD use reverse DNS notation").
/// Not reserved: reservation applies to prefixes whose *second* label is
/// `modelcontextprotocol` or `mcp`.
pub const MCP_META_PREFIX: &str = "dev.actcore/";

/// The ACT well-known namespace. `:` is not a legal MCP `_meta` name
/// character, so `std:` keys are respelled with `MCP_META_PREFIX` on the
/// wire. This is a *key* transform only — kind strings, which are values,
/// keep their `std:` form.
pub const ACT_STD_PREFIX: &str = "std:";

pub const MCP_ERROR_KIND: &str = "dev.actcore/error-kind";
pub const MCP_ERROR_METADATA: &str = "dev.actcore/error-metadata";

pub const MCP_MIME_TYPE: &str = "dev.actcore/mime-type";

/// UTF-8 JSON payloads, which must not take the CBOR or base64 paths.
pub fn is_json_mime(mime: &str) -> bool {
    mime == "application/json" || mime.ends_with("+json")
}

/// Build the `_meta` object for a content block: every entry of
/// `content-part.metadata` with its keys respelled for the channel, plus the
/// part's mime-type when the MCP block type does not carry it natively.
///
/// The mime is inserted *last*, after metadata, so it always wins over a
/// colliding metadata entry (e.g. a component-supplied `std:mime-type`):
/// `dev.actcore/mime-type` reflects `content-part.mime-type` unconditionally.
///
/// Returns `None` when there is nothing to say, so a bare part serialises
/// without a `_meta` key at all.
pub fn part_meta(
    part: &act_runtime::act::tools::types::ContentPart,
    include_mime: bool,
) -> Option<rmcp::model::MetaObject> {
    let mut map = serde_json::Map::new();

    if !part.metadata.is_empty() {
        let decoded = act_types::types::Metadata::from(part.metadata.clone());
        for (key, value) in decoded.iter() {
            map.insert(act_key_to_mcp(key).into_owned(), value.clone());
        }
    }

    if include_mime && let Some(mime) = part.mime_type.as_deref() {
        map.insert(MCP_MIME_TYPE.to_string(), Value::String(mime.to_string()));
    } else {
        // A colliding `std:mime-type` metadata entry respells to this same
        // key. When the block type carries mime natively (`include_mime`
        // false), that entry must not survive under `MCP_MIME_TYPE` — the
        // key must be either the real projected mime or absent, never a
        // metadata value smuggled in under the projection's key.
        map.remove(MCP_MIME_TYPE);
    }

    (!map.is_empty()).then(|| rmcp::model::MetaObject(map))
}

pub fn map_content_part(part: &act_runtime::act::tools::types::ContentPart) -> ContentBlock {
    let mime = part.mime_type.as_deref().unwrap_or("");

    // UTF-8 text-like payloads surface as MCP text content verbatim. This
    // covers `text/*` and JSON (`application/json`, `application/*+json`) —
    // JSON bytes are UTF-8, not CBOR, so they must not hit the base64 path
    // below. Matches the ACT-HTTP transport, which also treats JSON as text.
    if mime.starts_with("text/") || is_json_mime(mime) {
        let text = String::from_utf8_lossy(&part.data).into_owned();
        return text_block(text, part);
    }

    if mime.starts_with("image/") {
        use base64::Engine as _;
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(&part.data);
        let mut img = rmcp::model::ImageContent::new(data_b64, mime.to_string());
        // `include_mime: false` — an image block carries `mimeType` natively.
        img.meta = part_meta(part, false);
        return ContentBlock::Image(img);
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
    text_block(text, part)
}

/// A text block carrying the part's mime and metadata in `_meta`. MCP text
/// content has no native mime field, so `include_mime: true`.
pub fn text_block(
    text: String,
    part: &act_runtime::act::tools::types::ContentPart,
) -> ContentBlock {
    let mut content = rmcp::model::TextContent::new(text);
    content.meta = part_meta(part, true);
    ContentBlock::Text(content)
}

/// Project an ACT `error`'s non-message fields into a JSON object shared by
/// both error paths: `ErrorData.data` for an early error, `CallToolResult`
/// `_meta` for a mid-stream one. A client therefore reads the same key,
/// `dev.actcore/error-kind`, whichever path produced the failure.
///
/// The kind is a *value* and keeps its `std:` spelling; only metadata *keys*
/// are respelled for the `_meta` channel.
pub fn error_detail_json(kind: &str, metadata: &[(String, Vec<u8>)]) -> Value {
    let mut detail = serde_json::Map::new();
    detail.insert(MCP_ERROR_KIND.to_string(), Value::String(kind.to_string()));

    if !metadata.is_empty() {
        let decoded = act_types::types::Metadata::from(metadata.to_vec());
        let mapped: serde_json::Map<String, Value> = decoded
            .iter()
            .map(|(k, v)| (act_key_to_mcp(k).into_owned(), v.clone()))
            .collect();
        if !mapped.is_empty() {
            detail.insert(MCP_ERROR_METADATA.to_string(), Value::Object(mapped));
        }
    }

    Value::Object(detail)
}

pub fn component_error_to_mcp(err: act_runtime::ComponentError) -> ErrorData {
    match err {
        act_runtime::ComponentError::Tool(te) => {
            let message = act_types::types::LocalizedString::from(&te.message)
                .any_text()
                .to_string();
            let code = match te.kind.as_str() {
                ERR_INVALID_ARGS => ErrorCode::INVALID_PARAMS,
                ERR_NOT_FOUND => ErrorCode::METHOD_NOT_FOUND,
                ERR_CAPABILITY_DENIED => ErrorCode::INVALID_REQUEST,
                _ => ErrorCode::INTERNAL_ERROR,
            };
            let detail = error_detail_json(&te.kind, &te.metadata);
            ErrorData::new(code, message, Some(detail))
        }
        act_runtime::ComponentError::Internal(e) => {
            // A host-side failure has no guest-supplied kind; report the
            // registry's own value so the lookup key is always present.
            let detail = error_detail_json(act_types::constants::ERR_INTERNAL, &[]);
            ErrorData::new(ErrorCode::INTERNAL_ERROR, e.to_string(), Some(detail))
        }
    }
}

// ── list_tools helpers ──────────────────────────────────────────────────────

pub fn convert_tool_definitions(
    defs: &[act_runtime::act::tools::types::ToolDefinition],
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
pub fn inject_arg_meta_property(schema: &mut serde_json::Map<String, Value>) {
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

pub fn build_annotations(metadata: &[(String, Vec<u8>)]) -> Option<rmcp::model::ToolAnnotations> {
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

/// Pick a `structuredContent` payload, per design §3.4: exactly one content
/// part, a structured mime, and an object at the top level.
///
/// Deliberately conservative. `act:tools@0.2.0` `tool-definition` has no
/// output schema, so nothing describes this value to the client; inventing a
/// `{"parts": [...]}` envelope for the multi-part case would assert a shape
/// no schema declares.
pub fn structured_content_for(
    events: &[act_runtime::act::tools::types::ToolEvent],
) -> Option<Value> {
    let mut parts = events.iter().filter_map(|e| match e {
        act_runtime::act::tools::types::ToolEvent::Content(p) => Some(p),
        act_runtime::act::tools::types::ToolEvent::Error(_) => None,
    });

    let part = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    let mime = part.mime_type.as_deref().unwrap_or("");
    let value = if mime == "application/cbor" {
        cbor::cbor_to_json(&part.data).ok()?
    } else if is_json_mime(mime) {
        serde_json::from_slice(&part.data).ok()?
    } else {
        return None;
    };

    matches!(value, Value::Object(_)).then_some(value)
}

// ── fold_events_to_result ───────────────────────────────────────────────────

pub fn fold_events_to_result(result: act_runtime::CallToolResult) -> rmcp::model::CallToolResult {
    let mut content = Vec::new();
    let mut error_detail: Option<Value> = None;

    for event in &result.events {
        match event {
            act_runtime::act::tools::types::ToolEvent::Content(part) => {
                content.push(map_content_part(part));
            }
            act_runtime::act::tools::types::ToolEvent::Error(err) => {
                let message = act_types::types::LocalizedString::from(&err.message)
                    .any_text()
                    .to_string();
                content.push(rmcp::model::ContentBlock::text(message));
                error_detail = Some(error_detail_json(&err.kind, &err.metadata));
            }
        }
    }

    match error_detail {
        Some(detail) => {
            let mut out = rmcp::model::CallToolResult::error(content);
            out.meta = Some(rmcp::model::MetaObject(
                detail.as_object().cloned().unwrap_or_default(),
            ));
            out
        }
        None => {
            let mut out = rmcp::model::CallToolResult::success(content);
            out.structured_content = structured_content_for(&result.events);
            out
        }
    }
}

// ── Public entry point ──────────────────────────────────────────────────────

/// Build the synthetic `open_session` MCP tool. The args schema comes from
/// `get-open-session-args-schema`. `_meta.dev.actcore/session-op = "open"`
/// per ACT-CONSTANTS so agents can recognize this is a session-lifecycle
/// tool, not an ordinary capability.
pub fn virtual_open_session_tool(args_schema: Value) -> Tool {
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
/// `{ session_id: string }`. `_meta.dev.actcore/session-op = "close"`.
pub fn virtual_close_session_tool() -> Tool {
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

pub fn session_op_meta(op: &'static str) -> rmcp::model::MetaObject {
    let mut map = serde_json::Map::new();
    map.insert(
        act_key_to_mcp(META_SESSION_OP).into_owned(),
        Value::String(op.to_string()),
    );
    rmcp::model::MetaObject(map)
}

/// Force `std:session-id` to `default` when set, overriding any existing
/// value. Used in session-of-1 mode so the hidden default session wins over
/// client-supplied ids (ACT-SESSIONS §3 "session-of-1").
pub fn force_session_id(meta: &mut act_types::types::Metadata, default: &Option<String>) {
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
pub fn is_protocol_reserved(key: &str) -> bool {
    key == "progressToken" || key.starts_with("io.modelcontextprotocol/")
}

/// Respell an inbound MCP `_meta` key as an ACT metadata key.
/// Only the `dev.actcore/` prefix is mapped; everything else crosses
/// verbatim. The outbound counterpart, `act_key_to_mcp`, arrives in Task 2
/// with its first production caller.
pub fn mcp_key_to_act(key: &str) -> Cow<'_, str> {
    match key.strip_prefix(MCP_META_PREFIX) {
        Some(name) => Cow::Owned(format!("{ACT_STD_PREFIX}{name}")),
        None => Cow::Borrowed(key),
    }
}

/// Respell an ACT metadata key for the MCP `_meta` channel — the inverse of
/// [`mcp_key_to_act`]. Only the `std:` namespace is mapped; everything else
/// crosses verbatim.
pub fn act_key_to_mcp(key: &str) -> Cow<'_, str> {
    match key.strip_prefix(ACT_STD_PREFIX) {
        Some(name) => Cow::Owned(format!("{MCP_META_PREFIX}{name}")),
        None => Cow::Borrowed(key),
    }
}

/// Merge the transport `_meta` channel (ACT-MCP §3.1) into the call metadata,
/// minus the protocol's own reserved keys.
pub fn apply_transport_meta(
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

/// Strip the trace-context / correlation keys (`TRACE_META_KEYS`) out of an
/// argument-`_meta` object before it is folded into `call_metadata`.
///
/// The argument channel (ACT-MCP §3.2) is tool-call JSON, written by the
/// model turn — under prompt injection, attacker-controlled — and nothing
/// server-side validates it (this host has no JSON Schema validator;
/// `get_tool` is left at rmcp's unvalidated default). `trace_metadata_from_meta`
/// below already never *reads* these keys from the argument channel, but
/// that alone doesn't stop a value the argument channel already inserted
/// into `call_metadata` from surviving untouched when transport is silent
/// on the same key. Without this strip, a prompt-injected model could forge
/// `std:traceparent`/`std:tracestate` to splice a call into someone else's
/// trace, or `std:agent-id` to misattribute it to another agent.
pub fn strip_trace_keys(map: &mut serde_json::Map<String, Value>) {
    for key in TRACE_META_KEYS {
        map.remove(key);
    }
}

/// Lift trace-context keys out of MCP `_meta`, falling back to the JSON-RPC
/// request id for correlation when the client supplied none.
///
/// Per `ACT-CONSTANTS.md` §5, transport adapters SHOULD propagate
/// `std:traceparent` / `std:tracestate` to/from MCP request extensions; this
/// is that propagation for the MCP adapter (ACT-MCP §3.2.1). Reads only the
/// transport `_meta` channel (`context.meta`), never the injected `_meta`
/// **argument** (ACT-MCP §3.2): the argument channel is written by the
/// model and is therefore attacker-influenceable under prompt injection, so
/// it must never be trusted as a source of correlation data. A missing
/// `std:traceparent` / `std:tracestate` / `std:agent-id` is left absent —
/// never fabricated, since a synthetic value would silently misattribute
/// the call. `std:request-id` is the one exception: correlation must never
/// depend on the caller opting in, so it always ends up populated, falling
/// back to the JSON-RPC request id.
pub fn trace_metadata_from_meta(
    meta: &rmcp::model::MetaObject,
    request_id: &str,
) -> Vec<(String, String)> {
    // One merge, honouring the same `std:*`-vs-`dev.actcore/*` precedence as
    // `apply_transport_meta`, then four lookups against it — rather than
    // re-merging transport `_meta` from scratch per key.
    let mut merged = act_types::types::Metadata::default();
    apply_transport_meta(&mut merged, meta);

    let mut out = Vec::new();
    for key in TRACE_META_KEYS {
        if let Some(v) = merged
            .get(key)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
        {
            out.push((key.to_string(), v.to_string()));
        }
    }
    if !out
        .iter()
        .any(|(k, _)| k == act_types::constants::META_REQUEST_ID)
    {
        out.push((
            act_types::constants::META_REQUEST_ID.to_string(),
            request_id.to_string(),
        ));
    }
    out
}
