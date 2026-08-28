//! JSON Schema validation of what an agent sends, before it reaches a
//! component (`ACT-SPEC.md` §6.4, `ACT-SESSIONS.md` §2.1).
//!
//! Two call sites: `call-tool` arguments against the tool's
//! `parameters-schema`, and `open-session` args against
//! `get-open-session-args-schema`. Both spell the failure the same way — an
//! `std:invalid-args` error that never reaches the guest — so a component
//! cannot tell a host that rejected the call from one that never received it.
//!
//! ## Who this protects
//!
//! The component. Arguments are composed by an agent, which is a language
//! model reading a schema and guessing; the schema is the component's own
//! statement of what it accepts. Checking it here means a component's tool
//! body starts from arguments that match its declaration, rather than from
//! whatever a model produced.
//!
//! That is why an unusable schema is not fatal (see [`Validator::compile`]):
//! a component that ships one it cannot compile has opted out of a protection
//! that exists for its benefit, and nothing else is harmed.
//!
//! ## No remote `$ref`
//!
//! A schema arrives from the component, so a `$ref` in it is guest-controlled
//! text. `boon` resolves only resources registered with the compiler, and this
//! module registers none — so an external `$ref` fails to compile rather than
//! becoming an outbound request the component did not have to declare
//! `wasi:http` for. That is the whole reason for the choice of validator.

use crate::act::core::types::{Error as ToolError, LocalizedString};

/// The error kind a rejected call carries (`ACT-CONSTANTS.md` §9).
const INVALID_ARGS: &str = "std:invalid-args";

/// A compiled schema, or the reason there is none.
pub struct Validator {
    schema: Option<boon::Schemas>,
    index: boon::SchemaIndex,
}

impl Validator {
    /// Compile a schema, or decide there is nothing to check against.
    ///
    /// `Ok(None)` — deliberately not an error — when the text is not a usable
    /// schema. The alternative is refusing every call to a component whose
    /// packaging is wrong, which converts a build-time mistake into a total
    /// outage for something whose arguments may be perfectly fine. The
    /// component's own SDK validates too; this layer is the second of two, and
    /// the one that can afford to be absent.
    ///
    /// The reason is logged at `warn` with the tool named, once per compile,
    /// because a component silently running unvalidated is exactly the state
    /// an operator would want to know about.
    pub fn compile(what: &str, schema_text: &str) -> Option<Self> {
        let value: serde_json::Value = match serde_json::from_str(schema_text) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(%what, error = %e, "schema is not JSON; arguments will not be validated");
                return None;
            }
        };

        let mut schemas = boon::Schemas::new();
        let mut compiler = boon::Compiler::new();
        // One synthetic URL, and no resources registered beyond it: an external
        // `$ref` has nowhere to resolve to and fails here, which is the point.
        let url = "act:///schema";
        if let Err(e) = compiler.add_resource(url, value) {
            tracing::warn!(%what, error = %e, "schema could not be added; arguments will not be validated");
            return None;
        }
        match compiler.compile(url, &mut schemas) {
            Ok(index) => Some(Self {
                schema: Some(schemas),
                index,
            }),
            Err(e) => {
                tracing::warn!(%what, error = %e, "schema did not compile; arguments will not be validated");
                None
            }
        }
    }

    /// Check one value. `Err` carries the message the agent sees.
    pub fn check(&self, value: &serde_json::Value) -> Result<(), String> {
        let Some(schemas) = &self.schema else {
            return Ok(());
        };
        schemas.validate(value, self.index).map_err(|e| {
            // `boon`'s display walks the whole failure tree, naming each
            // location — which is what an agent needs to fix its own call. A
            // bare "invalid" would make the next attempt a guess.
            e.to_string()
        })
    }
}

/// The error a rejected call answers with.
///
/// Shaped exactly like the one a guest would have produced for the same
/// arguments, so no transport has to know which side refused.
pub fn invalid_args(message: String) -> ToolError {
    ToolError {
        kind: INVALID_ARGS.to_string(),
        message: LocalizedString::Plain(message),
        metadata: Vec::new(),
    }
}

/// Decode CBOR arguments into the shape a schema is written against.
///
/// A decode failure is itself invalid arguments: the guest could not have read
/// them either, and saying so here beats letting it trap on the far side.
pub fn arguments_as_json(arguments: &[u8]) -> Result<serde_json::Value, String> {
    if arguments.is_empty() {
        // No arguments at all is an empty object, not a missing document: a
        // schema requiring nothing must accept it, and one requiring a
        // property must reject it by naming that property.
        return Ok(serde_json::Value::Object(serde_json::Map::new()));
    }
    act_types::cbor::cbor_to_json(arguments)
        .map_err(|e| format!("arguments are not decodable CBOR: {e}"))
}

/// Session args arrive as named CBOR values rather than one document.
pub fn session_args_as_json(args: &[(String, Vec<u8>)]) -> Result<serde_json::Value, String> {
    let mut map = serde_json::Map::with_capacity(args.len());
    for (name, value) in args {
        let decoded = act_types::cbor::cbor_to_json(value)
            .map_err(|e| format!("session argument '{name}' is not decodable CBOR: {e}"))?;
        map.insert(name.clone(), decoded);
    }
    Ok(serde_json::Value::Object(map))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SCHEMA: &str = r#"{
        "type": "object",
        "properties": {
            "path": { "type": "string" },
            "limit": { "type": "integer" }
        },
        "required": ["path"]
    }"#;

    #[test]
    fn arguments_matching_the_schema_pass() {
        let v = Validator::compile("read", SCHEMA).expect("compiles");
        assert!(v.check(&json!({"path": "/tmp/x", "limit": 3})).is_ok());
    }

    #[test]
    fn a_missing_required_property_is_named() {
        let v = Validator::compile("read", SCHEMA).expect("compiles");
        let err = v.check(&json!({"limit": 3})).expect_err("must reject");
        assert!(
            err.contains("path"),
            "an agent has to learn which property to add: {err}"
        );
    }

    #[test]
    fn a_wrong_type_is_named() {
        let v = Validator::compile("read", SCHEMA).expect("compiles");
        let err = v
            .check(&json!({"path": "/tmp/x", "limit": "three"}))
            .expect_err("must reject");
        assert!(err.contains("limit"), "{err}");
    }

    /// The reason this module exists: a model guessing from a schema produces
    /// exactly this, and the component's body should never see it.
    #[test]
    fn no_arguments_at_all_still_fails_a_required_property() {
        let v = Validator::compile("read", SCHEMA).expect("compiles");
        let value = arguments_as_json(&[]).expect("empty is an empty object");
        assert_eq!(value, json!({}));
        assert!(v.check(&value).is_err());
    }

    #[test]
    fn a_schema_that_is_not_json_disables_validation_rather_than_failing() {
        // A packaging defect must not become an outage for arguments that may
        // be perfectly fine. The component's own SDK still validates.
        assert!(Validator::compile("broken", "not json at all").is_none());
    }

    #[test]
    fn a_schema_that_does_not_compile_disables_validation() {
        assert!(Validator::compile("broken", r#"{"type": 7}"#).is_none());
    }

    /// A `$ref` is guest-authored text. Resolving it over the network would be
    /// an outbound request the component never declared `wasi:http` for — so
    /// it must fail to compile, which disables validation for that tool and
    /// reaches the network not at all.
    #[test]
    fn a_remote_ref_does_not_resolve() {
        let hostile = r#"{"$ref": "https://evil.example.com/schema.json"}"#;
        assert!(
            Validator::compile("hostile", hostile).is_none(),
            "an external $ref must not be fetched, so it must not compile"
        );
    }

    #[test]
    fn undecodable_arguments_are_invalid_arguments() {
        let err = arguments_as_json(&[0xff, 0xff, 0xff]).expect_err("not CBOR");
        assert!(err.contains("CBOR"), "{err}");
    }

    #[test]
    fn session_args_become_one_object_keyed_by_name() {
        let args = vec![
            (
                "std:bearer-token".to_string(),
                act_types::cbor::to_cbor(&"t"),
            ),
            ("acme:tenant".to_string(), act_types::cbor::to_cbor(&"42")),
        ];
        let value = session_args_as_json(&args).expect("decodes");
        assert_eq!(value["std:bearer-token"], "t");
        assert_eq!(value["acme:tenant"], "42");
    }

    #[test]
    fn the_error_is_shaped_like_a_guests_own() {
        let e = invalid_args("nope".into());
        assert_eq!(e.kind, INVALID_ARGS);
        assert!(matches!(e.message, LocalizedString::Plain(ref m) if m == "nope"));
        assert!(
            e.metadata.is_empty(),
            "a host-authored error carries no guest metadata"
        );
    }
}
