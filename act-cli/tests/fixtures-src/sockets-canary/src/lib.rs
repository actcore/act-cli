//! Canary component for `wasi:sockets` host integration.
//!
//! It declares `wasi:sockets` (ceiling `*`, tcp) and its single tool,
//! `connect`, opens a raw TCP connection to the `host`/`port` given in its
//! arguments via plain `std::net::TcpStream`. The declared ceiling is
//! deliberately as wide as possible so a test's `--grant` is what actually
//! narrows access — this fixture exists to exercise the host's per-op
//! socket capability decision (`runtime/mod.rs`'s `socket_addr_check`
//! hook), not to test the component's own declaration.
//!
//! Unlike `ask-canary` (which goes through `wasi:http`, entirely handled
//! host-side), this dials `wasi:sockets` directly — the guest's own TCP
//! stack, gated by a different check than HTTP.

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

struct SocketsCanary;

export!(SocketsCanary);

impl tool_exports::Guest for SocketsCanary {
    async fn list_tools(
        _metadata: Vec<(String, Vec<u8>)>,
    ) -> Result<tool_types::ListToolsResponse, tool_types::Error> {
        Ok(tool_types::ListToolsResponse {
            metadata: vec![],
            tools: vec![tool_types::ToolDefinition {
                name: "connect".to_string(),
                description: core_types::LocalizedString::Plain(
                    "Open a raw TCP connection to `host`:`port` and report what happened. \
                     Always trips the wasi:sockets gate."
                        .to_string(),
                ),
                parameters_schema:
                    r#"{"type":"object","properties":{"host":{"type":"string"},"port":{"type":"integer"}},"required":["host","port"],"additionalProperties":false}"#
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
        if name != "connect" {
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

        let Some(host) = args.get("host").and_then(|h| h.as_str()) else {
            return tool_exports::ToolResult::Immediate(vec![tool_types::ToolEvent::Error(
                make_error("std:invalid-args", "Missing required argument `host`"),
            )]);
        };
        let Some(port) = args.get("port").and_then(|p| p.as_u64()) else {
            return tool_exports::ToolResult::Immediate(vec![tool_types::ToolEvent::Error(
                make_error("std:invalid-args", "Missing required argument `port`"),
            )]);
        };
        let port = port as u16;

        let addr = format!("{host}:{port}");
        // The host's denial arrives here as a plain io::Error. Surface its
        // kind verbatim so a test can tell a policy denial
        // (`PermissionDenied`) from a connect failure at the transport
        // (`ConnectionRefused`) without standing up a server.
        match std::net::TcpStream::connect(&addr) {
            Ok(_) => tool_exports::ToolResult::Immediate(vec![text_event(format!(
                "connected to {addr}"
            ))]),
            Err(e) => tool_exports::ToolResult::Immediate(vec![tool_types::ToolEvent::Error(
                make_error(
                    "std:internal",
                    &format!("connect to {addr} failed: {:?}: {e}", e.kind()),
                ),
            )]),
        }
    }
}
