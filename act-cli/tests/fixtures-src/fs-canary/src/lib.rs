//! Canary component for `wasi:filesystem` host integration.
//!
//! It declares `wasi:filesystem` (ceiling `**`, rw) and its single tool,
//! `read`, reads the path given in its arguments via plain `std::fs`. The
//! declared ceiling is deliberately as wide as possible so a test's `--grant`
//! is what actually narrows access — this fixture exists to exercise the
//! host's per-op capability decisions (`fs_policy.rs`), not to test the
//! component's own declaration.

#![allow(clippy::all)]

wit_bindgen::generate!({
    path: "wit",
    world: "component-world",
    generate_all,
});

use exports::act::tools::tool_provider as tool_exports;

use act::core::types as core_types;
use act::tools::types as tool_types;

fn to_cbor<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).expect("CBOR encode");
    buf
}

fn make_error(kind: &str, message: &str) -> tool_types::Error {
    tool_types::Error {
        kind: kind.to_string(),
        message: core_types::LocalizedString::Plain(message.to_string()),
        metadata: vec![],
    }
}

fn text_event(text: String) -> tool_types::ToolEvent {
    tool_types::ToolEvent::Content(tool_types::ContentPart {
        data: text.into_bytes(),
        mime_type: Some("text/plain".to_string()),
        metadata: vec![],
    })
}

struct FsCanary;

export!(FsCanary);

impl tool_exports::Guest for FsCanary {
    async fn list_tools(
        _metadata: Vec<(String, Vec<u8>)>,
    ) -> Result<tool_types::ListToolsResponse, tool_types::Error> {
        Ok(tool_types::ListToolsResponse {
            metadata: vec![],
            tools: vec![tool_types::ToolDefinition {
                name: "read".to_string(),
                description: core_types::LocalizedString::Plain(
                    "Read `path` and return its contents. Always trips the wasi:filesystem gate."
                        .to_string(),
                ),
                parameters_schema:
                    r#"{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}"#
                        .to_string(),
                metadata: vec![(
                    "std:read-only".to_string(),
                    to_cbor(&serde_json::json!(true)),
                )],
            }],
        })
    }

    async fn call_tool(
        name: String,
        arguments: Vec<u8>,
        _metadata: Vec<(String, Vec<u8>)>,
    ) -> tool_exports::ToolResult {
        if name != "read" {
            return tool_exports::ToolResult::Immediate(vec![tool_types::ToolEvent::Error(
                make_error("std:not-found", &format!("Unknown tool: {name}")),
            )]);
        }

        let args: serde_json::Value = if arguments.is_empty() {
            serde_json::json!({})
        } else {
            match ciborium::from_reader(arguments.as_slice()) {
                Ok(v) => v,
                Err(e) => {
                    return tool_exports::ToolResult::Immediate(vec![
                        tool_types::ToolEvent::Error(make_error(
                            "std:invalid-args",
                            &format!("Failed to decode arguments: {e}"),
                        )),
                    ]);
                }
            }
        };

        let Some(path) = args.get("path").and_then(|p| p.as_str()) else {
            return tool_exports::ToolResult::Immediate(vec![tool_types::ToolEvent::Error(
                make_error("std:invalid-args", "Missing required argument `path`"),
            )]);
        };

        match std::fs::read_to_string(path) {
            Ok(content) => tool_exports::ToolResult::Immediate(vec![text_event(content)]),
            Err(e) => {
                let kind = match e.kind() {
                    std::io::ErrorKind::NotFound => "std:not-found",
                    std::io::ErrorKind::PermissionDenied => "std:capability-denied",
                    _ => "std:internal",
                };
                tool_exports::ToolResult::Immediate(vec![tool_types::ToolEvent::Error(
                    make_error(kind, &format!("Read error on {path}: {e}")),
                )])
            }
        }
    }
}
