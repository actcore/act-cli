//! Canary component for `ask`-mode consent host integration.
//!
//! It declares `wasi:http` and its single tool, `fetch`, makes one outbound
//! request. That is the whole point: with no grant the host resolves
//! `wasi:http` to `ask`, so every call drives the consent gate — which is what
//! the host-side tests need to observe.
//!
//! The request is expected to fail (nothing is listening on the target). What
//! matters is *how* it fails: a refused consent is reported by the host as a
//! policy denial before the request leaves, an approved one fails later at the
//! transport. The two are distinguishable, so a test can tell "denied" from
//! "allowed but unreachable" without standing up a server.

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

struct AskCanary;

export!(AskCanary);

impl tool_exports::Guest for AskCanary {
    async fn list_tools(
        _metadata: Vec<(String, Vec<u8>)>,
    ) -> Result<tool_types::ListToolsResponse, tool_types::Error> {
        Ok(tool_types::ListToolsResponse {
            metadata: vec![],
            tools: vec![tool_types::ToolDefinition {
                name: "fetch".to_string(),
                description: core_types::LocalizedString::Plain(
                    "GET `url` and report what happened. Always trips the wasi:http gate."
                        .to_string(),
                ),
                parameters_schema:
                    r#"{"type":"object","properties":{"url":{"type":"string"}},"required":["url"],"additionalProperties":false}"#
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
        if name != "fetch" {
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

        let Some(url) = args.get("url").and_then(|u| u.as_str()) else {
            return tool_exports::ToolResult::Immediate(vec![tool_types::ToolEvent::Error(
                make_error("std:invalid-args", "Missing required argument `url`"),
            )]);
        };

        match wasi_fetch::Client::new()
            .get(url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(response) => tool_exports::ToolResult::Immediate(vec![text_event(format!(
                "fetched {url}: HTTP {}",
                response.status().as_u16()
            ))]),
            // The host's denial arrives here as a transport error. Surface it
            // verbatim so the test can tell a policy denial from a connect
            // failure.
            Err(e) => tool_exports::ToolResult::Immediate(vec![tool_types::ToolEvent::Error(
                make_error("std:internal", &format!("fetch failed: {e}")),
            )]),
        }
    }
}
