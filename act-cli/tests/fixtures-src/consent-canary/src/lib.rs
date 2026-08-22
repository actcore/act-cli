//! Canary component for `act:consent/consent-authority` host integration.
//!
//! Consent has no physical boundary to intercept (ACT-CONSENT.md §1), so the
//! only way to prove the host's side of the exchange is a component that
//! actually calls `request` across a real component boundary. `ConsentGate`
//! itself is already exhaustively unit-tested in `crates/act-runtime` against
//! `decide` directly; nothing in that layer can see whether the WIT bridge —
//! linking, argument lowering, the async round-trip — actually works. This
//! fixture is the second one (after `credentials-canary`) that *imports* a
//! host interface rather than only exporting one, and for the same reason:
//! only that shape can drive the host's side of the call at all.
//!
//! One tool, `drop_database`, taking a `database` argument. It calls
//! `consent-authority.request` with class `db:drop`, `key` = the database
//! name, a `summary` naming the action, and empty `args` — this canary has no
//! dimensions worth declaring beyond the key. On `allow` it returns
//! `{"dropped": <name>}` **without touching anything** — it is a canary, not
//! a database client, and it drops nothing whether or not it is authorized
//! to. On `deny` it returns a tool error carrying `std:capability-denied`
//! (ACT-CONSENT.md §6).
//!
//! The call's own metadata is passed straight through to `request`, per
//! ACT-CONSENT.md §7.1 — it is what lets the host anchor a decision to a
//! session, even though this canary has no session of its own to name.

#![allow(clippy::all)]

wit_bindgen::generate!({
    path: "wit",
    world: "component-world",
    generate_all,
});

use exports::act::tools::tool_provider as tool_exports;

use act::consent::consent_authority;
use act::consent::types as consent_types;
use act::core::types as core_types;
use act::tools::types as tool_types;

/// The one class this canary ever asks for.
const CLASS: &str = "db:drop";

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

fn content_event(value: &serde_json::Value) -> tool_types::ToolEvent {
    tool_types::ToolEvent::Content(tool_types::ContentPart {
        data: to_cbor(value),
        mime_type: Some("application/cbor".to_string()),
        metadata: vec![],
    })
}

struct ConsentCanary;

export!(ConsentCanary);

impl tool_exports::Guest for ConsentCanary {
    async fn list_tools(
        _metadata: Vec<(String, Vec<u8>)>,
    ) -> Result<tool_types::ListToolsResponse, tool_types::Error> {
        let drop_database = tool_types::ToolDefinition {
            name: "drop_database".to_string(),
            description: core_types::LocalizedString::Plain(
                "Ask the host to authorize dropping `database` under class db:drop, and \
                 report the decision. Never actually drops anything — this is a canary."
                    .to_string(),
            ),
            parameters_schema: r#"{"type":"object","properties":{"database":{"type":"string"}},"required":["database"],"additionalProperties":false}"#
                .to_string(),
            metadata: vec![],
        };
        Ok(tool_types::ListToolsResponse {
            metadata: vec![],
            tools: vec![drop_database],
        })
    }

    async fn call_tool(
        name: String,
        arguments: Vec<u8>,
        metadata: Vec<(String, Vec<u8>)>,
    ) -> tool_exports::ToolResult {
        let event = match name.as_str() {
            "drop_database" => drop_database(&arguments, metadata).await,
            other => tool_types::ToolEvent::Error(make_error(
                "std:not-found",
                &format!("Unknown tool: {other}"),
            )),
        };
        tool_exports::ToolResult::Immediate(vec![event])
    }
}

/// Decode `{"database": "<name>"}`, ask the host, and never touch anything.
async fn drop_database(
    arguments: &[u8],
    metadata: Vec<(String, Vec<u8>)>,
) -> tool_types::ToolEvent {
    let args: serde_json::Value =
        ciborium::from_reader(arguments).unwrap_or(serde_json::Value::Null);
    let Some(database) = args.get("database").and_then(|v| v.as_str()).map(str::to_string) else {
        return tool_types::ToolEvent::Error(make_error(
            "std:invalid-args",
            "Missing required argument: database",
        ));
    };

    let req = consent_types::ConsentRequest {
        class: CLASS.to_string(),
        key: database.clone(),
        summary: format!("Drop database \"{database}\""),
        args: Vec::new(),
    };
    let decision = consent_authority::request(req, metadata).await;

    match decision {
        consent_types::Decision::Allow => {
            content_event(&serde_json::json!({ "dropped": database }))
        }
        consent_types::Decision::Deny => tool_types::ToolEvent::Error(make_error(
            "std:capability-denied",
            "dropping databases was not authorized",
        )),
    }
}
