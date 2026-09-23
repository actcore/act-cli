//! Canary component for `wasi:filesystem` host integration.
//!
//! It declares `wasi:filesystem` (ceiling `**`, rw). Its `read` tool reads
//! the path given in its arguments via plain `std::fs` (wasip2); `p3-read`
//! and `p3-write` do the same through `wasi:filesystem@0.3`. The
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
            },
            tool_types::ToolDefinition {
                name: "p3-read".to_string(),
                description: core_types::LocalizedString::Plain(
                    "Read `path` through wasi:filesystem@0.3 (open-at + read-via-stream)."
                        .to_string(),
                ),
                parameters_schema:
                    r#"{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}"#
                        .to_string(),
                metadata: vec![(
                    "std:read-only".to_string(),
                    to_cbor(&serde_json::json!(true)),
                )],
            },
            tool_types::ToolDefinition {
                name: "p3-write".to_string(),
                description: core_types::LocalizedString::Plain(
                    "Create or truncate `path` and write `content` through wasi:filesystem@0.3 (open-at + write-via-stream)."
                        .to_string(),
                ),
                parameters_schema:
                    r#"{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},"required":["path","content"],"additionalProperties":false}"#
                        .to_string(),
                metadata: vec![],
            }],
        })
    }

    async fn call_tool(
        name: String,
        arguments: Vec<u8>,
        _metadata: Vec<(String, Vec<u8>)>,
    ) -> tool_exports::ToolResult {
        if name != "read" && name != "p3-read" && name != "p3-write" {
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

        if name == "p3-read" || name == "p3-write" {
            let content = args.get("content").and_then(|c| c.as_str()).map(str::to_string);
            let result = if name == "p3-read" {
                p3_read(path).await
            } else {
                p3_write(path, content.unwrap_or_default()).await
            };
            return tool_exports::ToolResult::Immediate(vec![match result {
                Ok(text) => text_event(text),
                Err(e) => tool_types::ToolEvent::Error(make_error(p3_error_kind(&e), &format!("{name} {path}: {e:?}"))),
            }]);
        }

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

// ── wasi:filesystem@0.3 helpers ─────────────────────────────────────────────

use wasip3::filesystem::types::{
    Descriptor, DescriptorFlags, ErrorCode as P3ErrorCode, OpenFlags, PathFlags,
};

/// Find the preopen containing absolute `path`, and the path relative to it.
fn p3_resolve(path: &str) -> Result<(Descriptor, String), P3ErrorCode> {
    let mut best: Option<(Descriptor, String)> = None;
    for (dir, guest) in wasip3::filesystem::preopens::get_directories() {
        let prefix = guest.trim_end_matches('/');
        let Some(rest) = path.strip_prefix(prefix) else {
            continue;
        };
        if !(rest.is_empty() || rest.starts_with('/')) {
            continue;
        }
        let longer = best.as_ref().is_none_or(|(_, g)| prefix.len() > g.len());
        if longer {
            best = Some((dir, prefix.to_string()));
        }
    }
    let (dir, prefix) = best.ok_or(P3ErrorCode::NoEntry)?;
    let rel = path[prefix.len()..].trim_start_matches('/').to_string();
    Ok((dir, if rel.is_empty() { ".".to_string() } else { rel }))
}

async fn p3_read(path: &str) -> Result<String, P3ErrorCode> {
    let (dir, rel) = p3_resolve(path)?;
    let file = dir
        .open_at(PathFlags::SYMLINK_FOLLOW, rel, OpenFlags::empty(), DescriptorFlags::READ)
        .await?;
    let (rx, done) = file.read_via_stream(0);
    let bytes = rx.collect().await;
    done.await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

async fn p3_write(path: &str, content: String) -> Result<String, P3ErrorCode> {
    let (dir, rel) = p3_resolve(path)?;
    let file = dir
        .open_at(
            PathFlags::SYMLINK_FOLLOW,
            rel,
            OpenFlags::CREATE | OpenFlags::TRUNCATE,
            DescriptorFlags::WRITE,
        )
        .await?;
    let (mut tx, rx) = wasip3::wit_stream::new::<u8>();
    let done = file.write_via_stream(rx, 0);
    let len = content.len();
    let rest = tx.write_all(content.into_bytes()).await;
    drop(tx);
    done.await?;
    Ok(format!("{}", len - rest.len()))
}

fn p3_error_kind(e: &P3ErrorCode) -> &'static str {
    match e {
        P3ErrorCode::NoEntry => "std:not-found",
        P3ErrorCode::NotPermitted | P3ErrorCode::Access => "std:capability-denied",
        _ => "std:internal",
    }
}
