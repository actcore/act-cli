//! Canary component for `act:sessions/session-provider` host integration.
//!
//! Each session holds a `u64` counter. The component exposes two tools:
//! - `read` — return the current counter value (no-op increment).
//! - `increment` — bump the counter by `by` (default 1) and return the new value.
//!
//! Both tools require `std:session-id` in the call metadata to identify which
//! session's counter to operate on. `open-session` accepts an optional
//! `start: u64` arg to seed the counter.

#![allow(clippy::all)]

wit_bindgen::generate!({
    path: "wit",
    world: "component-world",
    generate_all,
});

use std::cell::RefCell;
use std::collections::HashMap;

use exports::act::sessions::session_provider as session_exports;
use exports::act::tools::tool_provider as tool_exports;

// Data types moved to dedicated `types` interfaces in act:tools@0.2.0 /
// act:sessions@0.2.0; `localized-string` lives in act:core. The
// `Guest` traits and the `stream<>`-bearing `tool-result` stay in their
// provider interfaces (`tool_exports` / `session_exports`).
use act::core::types as core_types;
use act::sessions::types as session_types;
use act::tools::types as tool_types;

// ── State ──────────────────────────────────────────────────────────────────

thread_local! {
    static SESSIONS: RefCell<HashMap<String, u64>> = RefCell::new(HashMap::new());
    static NEXT_ID: RefCell<u64> = const { RefCell::new(0) };
}

fn alloc_session_id() -> String {
    NEXT_ID.with(|n| {
        let mut n = n.borrow_mut();
        let id = *n;
        *n += 1;
        format!("sid_canary_{id}")
    })
}

// ── CBOR helpers ───────────────────────────────────────────────────────────

fn from_cbor(bytes: &[u8]) -> serde_json::Value {
    ciborium::from_reader(bytes).unwrap_or(serde_json::Value::Null)
}

fn to_cbor(value: &serde_json::Value) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).unwrap_or_default();
    buf
}

fn extract_session_id(metadata: &[(String, Vec<u8>)]) -> Option<String> {
    for (key, value) in metadata {
        if key == "std:session-id"
            && let serde_json::Value::String(s) = from_cbor(value)
        {
            return Some(s);
        }
    }
    None
}

fn make_error(kind: &str, message: &str) -> tool_types::Error {
    tool_types::Error {
        kind: kind.to_string(),
        message: core_types::LocalizedString::Plain(message.to_string()),
        metadata: vec![],
    }
}

// ── Component export ───────────────────────────────────────────────────────

struct SessionsCanary;

export!(SessionsCanary);

// ── tool-provider ──────────────────────────────────────────────────────────

impl tool_exports::Guest for SessionsCanary {
    async fn list_tools(
        _metadata: Vec<(String, Vec<u8>)>,
    ) -> Result<tool_types::ListToolsResponse, tool_types::Error> {
        let read_tool = tool_types::ToolDefinition {
            name: "read".to_string(),
            description: core_types::LocalizedString::Plain(
                "Read the current counter value for this session.".to_string(),
            ),
            parameters_schema: r#"{"type":"object","properties":{},"additionalProperties":false}"#
                .to_string(),
            metadata: vec![
                ("std:read-only".to_string(), to_cbor(&serde_json::json!(true))),
                ("std:idempotent".to_string(), to_cbor(&serde_json::json!(true))),
            ],
        };
        let increment_tool = tool_types::ToolDefinition {
            name: "increment".to_string(),
            description: core_types::LocalizedString::Plain(
                "Increment the counter by `by` (default 1) and return the new value.".to_string(),
            ),
            parameters_schema: r#"{"type":"object","properties":{"by":{"type":"integer","default":1}},"additionalProperties":false}"#
                .to_string(),
            metadata: vec![],
        };
        Ok(tool_types::ListToolsResponse {
            metadata: vec![],
            tools: vec![read_tool, increment_tool],
        })
    }

    async fn call_tool(
        name: String,
        arguments: Vec<u8>,
        metadata: Vec<(String, Vec<u8>)>,
    ) -> tool_exports::ToolResult {
        let session_id = match extract_session_id(&metadata) {
            Some(id) => id,
            None => {
                return tool_exports::ToolResult::Immediate(vec![tool_types::ToolEvent::Error(
                    make_error(
                        "std:invalid-args",
                        "Missing required metadata key std:session-id",
                    ),
                )]);
            }
        };

        let event = match name.as_str() {
            "read" => SESSIONS.with(|s| match s.borrow().get(&session_id) {
                Some(&value) => content_event(&serde_json::json!({ "value": value })),
                None => tool_types::ToolEvent::Error(make_error(
                    "std:session-not-found",
                    &format!("Unknown session-id: {session_id}"),
                )),
            }),
            "increment" => {
                let args = from_cbor(&arguments);
                let by = args.get("by").and_then(|v| v.as_u64()).unwrap_or(1);
                SESSIONS.with(|s| {
                    let mut s = s.borrow_mut();
                    match s.get_mut(&session_id) {
                        Some(counter) => {
                            *counter += by;
                            content_event(&serde_json::json!({ "value": *counter }))
                        }
                        None => tool_types::ToolEvent::Error(make_error(
                            "std:session-not-found",
                            &format!("Unknown session-id: {session_id}"),
                        )),
                    }
                })
            }
            other => tool_types::ToolEvent::Error(make_error(
                "std:not-found",
                &format!("Unknown tool: {other}"),
            )),
        };

        tool_exports::ToolResult::Immediate(vec![event])
    }
}

fn content_event(value: &serde_json::Value) -> tool_types::ToolEvent {
    tool_types::ToolEvent::Content(tool_types::ContentPart {
        data: to_cbor(value),
        mime_type: Some("application/cbor".to_string()),
        metadata: vec![],
    })
}

// ── session-provider ───────────────────────────────────────────────────────

impl session_exports::Guest for SessionsCanary {
    async fn get_open_session_args_schema(
        _metadata: Vec<(String, Vec<u8>)>,
    ) -> Result<String, session_exports::Error> {
        let schema = r#"{
            "type": "object",
            "properties": {
                "start": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 0,
                    "description": "Initial counter value"
                }
            },
            "additionalProperties": false
        }"#;
        Ok(schema.to_string())
    }

    async fn open_session(
        args: Vec<(String, Vec<u8>)>,
        _metadata: Vec<(String, Vec<u8>)>,
    ) -> Result<session_types::Session, session_exports::Error> {
        let mut start: u64 = 0;
        for (key, value) in &args {
            if key == "start"
                && let serde_json::Value::Number(n) = from_cbor(value)
                && let Some(v) = n.as_u64()
            {
                start = v;
            }
        }

        let id = alloc_session_id();
        SESSIONS.with(|s| s.borrow_mut().insert(id.clone(), start));

        Ok(session_types::Session {
            id,
            metadata: vec![],
        })
    }

    fn close_session(session_id: String) {
        SESSIONS.with(|s| {
            s.borrow_mut().remove(&session_id);
        });
    }
}
