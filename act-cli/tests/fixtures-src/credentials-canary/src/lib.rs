//! Canary component for `act:credentials/store` host integration.
//!
//! This is the only fixture that *imports* a host interface rather than
//! exporting one, so it is the only one that can prove the end-to-end
//! property the credentials work exists for: material crosses into the
//! guest, and nothing an agent can read ever carries it.
//!
//! One tool, `whoami`, fetches the credential stored under the key `probe`
//! and reports facts about it — its `kind`, whether the field map arrived
//! non-empty, the **byte length** of `acme:value` (when present), and the
//! **CBOR major type** the first field decoded to (`shape`, `"text"` /
//! `"map"` / `"other"`). Nothing else — never the value itself, of either
//! field. The length is a deliberate, minimal oracle: without it the test
//! could not distinguish "the host handed over the real material" from "the
//! host handed over an empty shell with the right kind on it", which is
//! exactly the failure a test asserting only `kind` would sail past. `shape`
//! is the same idea for the field's *encoding*: it proves an object field
//! crossed as a CBOR map rather than as text carrying a JSON-looking string.
//! Both are the least the test can observe and still be a test.
//!
//! `session-provider` is exported because `get-secret` requires a live
//! session, and the credential is fetched **on the tool call, never inside
//! `open-session`** — the host marks a session live only once
//! `open-session` returns, and the id is component-chosen, so a fetch from
//! inside that call is refused as an unknown session, always. See the
//! credentials design doc §8.3 and §9.2; this is settled behaviour, not a
//! race to work around.

#![allow(clippy::all)]

wit_bindgen::generate!({
    path: "wit",
    world: "component-world",
    generate_all,
});

use std::cell::RefCell;
use std::collections::HashSet;

use exports::act::sessions::session_provider as session_exports;
use exports::act::tools::tool_provider as tool_exports;

use act::core::types as core_types;
use act::credentials::store as credential_store;
use act::credentials::types as credential_types;
use act::sessions::types as session_types;
use act::tools::types as tool_types;

/// The one key this canary ever asks for. Derived, not configurable —
/// design §9.2 ("derive keys deterministically"; a single-service component
/// uses a constant).
const PROBE_KEY: &str = "probe";

// ── State ──────────────────────────────────────────────────────────────────

thread_local! {
    static SESSIONS: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
    static NEXT_ID: RefCell<u64> = const { RefCell::new(0) };
}

fn alloc_session_id() -> String {
    NEXT_ID.with(|n| {
        let mut n = n.borrow_mut();
        let id = *n;
        *n += 1;
        format!("sid_cred_canary_{id}")
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

/// The CBOR major type a field decoded to — never the value it carried.
/// `std:string` fields cross as text, `std:oauth2` as a map; anything else
/// the host would have refused before it ever reached here.
fn cbor_shape(decoded: &serde_json::Value) -> &'static str {
    match decoded {
        serde_json::Value::String(_) => "text",
        serde_json::Value::Object(_) => "map",
        _ => "other",
    }
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

fn content_event(value: &serde_json::Value) -> tool_types::ToolEvent {
    tool_types::ToolEvent::Content(tool_types::ContentPart {
        data: to_cbor(value),
        mime_type: Some("application/cbor".to_string()),
        metadata: vec![],
    })
}

/// Project a `secret-error` onto an ACT error kind. The strings are the
/// component's own — `act:credentials` has no registered `std:` error kinds
/// — but they keep the WIT variant name so a test can tell a denial from a
/// miss without parsing prose.
fn credential_error(e: &credential_types::SecretError) -> tool_types::ToolEvent {
    let (kind, message) = match e {
        credential_types::SecretError::NotFound => (
            "canary:credential-not-found",
            format!("no credential under key {PROBE_KEY}"),
        ),
        credential_types::SecretError::Denied => (
            "canary:credential-denied",
            format!("denied: the host refused the credential under key {PROBE_KEY}"),
        ),
        credential_types::SecretError::InvalidSession => (
            "canary:credential-invalid-session",
            "the session is not live".to_string(),
        ),
        credential_types::SecretError::Unavailable(detail) => (
            "canary:credential-unavailable",
            format!("store unavailable: {detail}"),
        ),
    };
    tool_types::ToolEvent::Error(make_error(kind, &message))
}

// ── Component export ───────────────────────────────────────────────────────

struct CredentialsCanary;

export!(CredentialsCanary);

// ── tool-provider ──────────────────────────────────────────────────────────

impl tool_exports::Guest for CredentialsCanary {
    async fn list_tools(
        _metadata: Vec<(String, Vec<u8>)>,
    ) -> Result<tool_types::ListToolsResponse, tool_types::Error> {
        let whoami = tool_types::ToolDefinition {
            name: "whoami".to_string(),
            description: core_types::LocalizedString::Plain(
                "Fetch this component's credential and report facts about it — kind, \
                 whether fields arrived, the length of acme:value, and the CBOR shape \
                 of the first field. Never the value."
                    .to_string(),
            ),
            parameters_schema: r#"{"type":"object","properties":{},"additionalProperties":false}"#
                .to_string(),
            metadata: vec![],
        };
        let list = tool_types::ToolDefinition {
            name: "list_keys".to_string(),
            description: core_types::LocalizedString::Plain(
                "List the credential keys visible in this component's profile. Metadata only."
                    .to_string(),
            ),
            parameters_schema: r#"{"type":"object","properties":{},"additionalProperties":false}"#
                .to_string(),
            metadata: vec![
                ("std:read-only".to_string(), to_cbor(&serde_json::json!(true))),
            ],
        };
        Ok(tool_types::ListToolsResponse {
            metadata: vec![],
            tools: vec![whoami, list],
        })
    }

    async fn call_tool(
        name: String,
        _arguments: Vec<u8>,
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
            "whoami" => whoami(&session_id).await,
            "list_keys" => list_keys(&session_id).await,
            other => tool_types::ToolEvent::Error(make_error(
                "std:not-found",
                &format!("Unknown tool: {other}"),
            )),
        };

        tool_exports::ToolResult::Immediate(vec![event])
    }
}

/// Fetch the probe credential and describe it without quoting it.
///
/// Fetched here rather than at session open, per the module docs.
async fn whoami(session_id: &str) -> tool_types::ToolEvent {
    let want = credential_types::SecretRequest {
        key: PROBE_KEY.to_string(),
        // Left `none` on purpose: the kind is a provisioning hint, not a
        // retrieval filter (design §3.4) — the component inspects
        // `secret.kind` and decides for itself, which is exactly what this
        // canary reports.
        kind: None,
        resource: None,
        scopes: vec![],
        hint: Some("canary probe".to_string()),
    };
    match credential_store::get_secret(session_id.to_string(), want).await {
        Ok(secret) => {
            let mut field_names: Vec<&str> =
                secret.fields.iter().map(|(name, _)| name.as_str()).collect();
            field_names.sort_unstable();
            // Values cross as dCBOR — text for a `std:string` field, a map
            // for a `std:oauth2` one — the same encoding tool arguments and
            // metadata use. Decoded only to measure or classify — the
            // decoded value itself is dropped without ever reaching an
            // event.
            let value_len = secret
                .fields
                .iter()
                .find(|(name, _)| name == "acme:value")
                .and_then(|(_, raw)| match from_cbor(raw) {
                    serde_json::Value::String(s) => Some(s.len()),
                    _ => None,
                });
            // Whichever field this kind carries — `acme:value` for a string
            // kind, `std:token` for `std:oauth2` — report the CBOR major
            // type it decoded to. Fields arrive already sorted by name, and
            // every kind this canary is asked about has exactly one
            // revealable field, so "the first one" is unambiguous.
            let shape = secret
                .fields
                .first()
                .map(|(_, raw)| cbor_shape(&from_cbor(raw)))
                .unwrap_or("other");
            content_event(&serde_json::json!({
                "kind": secret.kind,
                "has_fields": !secret.fields.is_empty(),
                "field_names": field_names,
                "value_len": value_len,
                "shape": shape,
            }))
        }
        Err(e) => credential_error(&e),
    }
}

/// Enumerate the profile — non-secret metadata only, which is all
/// `secret-info` can carry.
async fn list_keys(session_id: &str) -> tool_types::ToolEvent {
    match credential_store::list_secrets(Some(session_id.to_string())).await {
        Ok(infos) => {
            let keys: Vec<serde_json::Value> = infos
                .iter()
                .map(|i| serde_json::json!({ "key": i.key, "kind": i.kind }))
                .collect();
            content_event(&serde_json::json!({ "keys": keys }))
        }
        Err(e) => credential_error(&e),
    }
}

// ── session-provider ───────────────────────────────────────────────────────

impl session_exports::Guest for CredentialsCanary {
    async fn get_open_session_args_schema(
        _metadata: Vec<(String, Vec<u8>)>,
    ) -> Result<String, session_exports::Error> {
        Ok(r#"{"type":"object","properties":{},"additionalProperties":false}"#.to_string())
    }

    async fn open_session(
        _args: Vec<(String, Vec<u8>)>,
        _metadata: Vec<(String, Vec<u8>)>,
    ) -> Result<session_types::Session, session_exports::Error> {
        // Deliberately no `get-secret` here. See the module docs: the host
        // has not seen this id yet, so the fetch would be refused as an
        // unknown session no matter what the policy says.
        let id = alloc_session_id();
        SESSIONS.with(|s| s.borrow_mut().insert(id.clone()));
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
