//! The audit record types. These are field carriers: `emit.rs` is the only
//! module that turns them into `tracing` events.

use std::fmt;
use std::time::Duration;

use sha2::{Digest, Sha256};

/// Frozen attribute names. Every emitted field uses one of these constants.
///
/// These are a public contract — the OTLP exporter maps them straight onto
/// span/event attributes, so renaming one invalidates existing dashboards.
/// OpenTelemetry semantic conventions are used where one exists; everything
/// else lives under the `act.*` namespace.
pub mod attr {
    pub const COMPONENT_REF: &str = "act.component.ref";
    pub const COMPONENT_DIGEST: &str = "act.component.digest";
    pub const TOOL_NAME: &str = "act.tool.name";
    pub const TOOL_ARGS_SHA256: &str = "act.tool.args_sha256";
    pub const SESSION_ID: &str = "act.session.id";
    // Caller and call identity. Key names come from ACT-CONSTANTS.md §5,
    // which already reserves std:agent-id / std:request-id / std:traceparent
    // / std:tracestate — this host is the first reader of any of them.
    pub const AGENT_ID: &str = "act.agent.id";
    pub const REQUEST_ID: &str = "act.request.id";
    pub const TRACE_PARENT: &str = "act.trace.parent";
    pub const TRACE_STATE: &str = "act.trace.state";
    pub const TRANSPORT: &str = "act.transport";
    pub const OUTCOME: &str = "act.outcome";
    pub const DURATION_MS: &str = "act.duration_ms";
    pub const CAPABILITY_ID: &str = "act.capability.id";
    pub const RESOURCE_KEY: &str = "act.resource.key";
    pub const RESOURCE_ACTION: &str = "act.resource.action";
    pub const DECISION: &str = "act.decision";
    pub const POLICY_MODE: &str = "act.policy.mode";
    pub const POLICY_ACTOR: &str = "act.policy.actor";
    pub const POLICY_REASON: &str = "act.policy.reason";
    pub const POLICY_RULE: &str = "act.policy.rule";
    /// Whether the component declared this capability class in `act.toml`.
    pub const CAPABILITY_DECLARED: &str = "act.capability.declared";
}

/// Which transport dispatched the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Cli,
    Mcp,
    Http,
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Transport::Cli => "cli",
            Transport::Mcp => "mcp",
            Transport::Http => "http",
        })
    }
}

/// How the tool call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    /// The component returned a `tool-event::error` or an `err` result.
    ToolError,
    /// The host failed to run the call at all.
    HostError,
    Cancelled,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Outcome::Ok => "ok",
            Outcome::ToolError => "tool-error",
            Outcome::HostError => "host-error",
            Outcome::Cancelled => "cancelled",
        })
    }
}

/// The resolved verdict. Widens `act_policy::Decision`: the classifier is
/// three-valued, but `Ask` settles into an allow or a deny once the operator
/// (or the degrade-to-deny rule) answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision4 {
    Allow,
    Deny,
    AskAllow,
    AskDeny,
}

impl Decision4 {
    /// True when this record must print the moment it resolves rather than
    /// being folded into the per-call rollup.
    pub fn is_exception(&self) -> bool {
        !matches!(self, Decision4::Allow)
    }
}

impl fmt::Display for Decision4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Decision4::Allow => "allow",
            Decision4::Deny => "deny",
            Decision4::AskAllow => "ask-allow",
            Decision4::AskDeny => "ask-deny",
        })
    }
}

/// Who decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor {
    /// Resolved from the static ceiling × grant intersection.
    Static,
    /// A human answered an `ask` prompt.
    User,
    /// An external policy engine decided (toolserver tier; unused in the CLI).
    Policy,
}

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Actor::Static => "static",
            Actor::User => "user",
            Actor::Policy => "policy",
        })
    }
}

/// The fields known when a tool call begins. Outcome and duration are
/// recorded onto the span when it finishes.
#[derive(Debug, Clone)]
pub struct ToolCallStart {
    pub component_ref: String,
    pub digest: String,
    pub tool: String,
    pub args_sha256: String,
    pub session_id: Option<String>,
    pub transport: Transport,
    /// `std:agent-id` — informational caller identity, never a principal.
    pub agent_id: Option<String>,
    /// `std:request-id`, or a host-generated id. Always present, so an
    /// operator can always join one audit line to one client log line.
    pub request_id: String,
    /// `std:traceparent` (W3C Trace Context) as received.
    pub traceparent: Option<String>,
    /// `std:tracestate` as received.
    pub tracestate: Option<String>,
}

/// One capability decision, emitted as an event inside the tool-call span.
#[derive(Debug, Clone)]
pub struct CapDecisionRecord {
    pub cap_id: String,
    pub key: String,
    pub action: String,
    pub decision: Decision4,
    pub mode: String,
    pub actor: Actor,
    pub reason: Option<String>,
    /// The ceiling rule that matched, when the provider can attribute one.
    /// Drives rollup grouping (Task 2).
    pub rule: Option<String>,
}

impl CapDecisionRecord {
    /// A statically-resolved decision (ceiling x grant, no human involved).
    /// Shared by every capability class so the record shape cannot drift
    /// between providers.
    pub fn statik(
        cap_id: &str,
        key: &str,
        action: &str,
        decision: Decision4,
        mode: &str,
        rule: Option<String>,
    ) -> Self {
        Self {
            cap_id: cap_id.to_string(),
            key: key.to_string(),
            action: action.to_string(),
            decision,
            mode: mode.to_string(),
            actor: Actor::Static,
            reason: (decision == Decision4::Deny).then(|| "outside ceiling".to_string()),
            rule,
        }
    }

    /// An `ask` that a human has just answered.
    pub fn answered(cap_id: &str, key: &str, allowed: bool) -> Self {
        Self {
            cap_id: cap_id.to_string(),
            key: key.to_string(),
            action: String::new(),
            decision: if allowed {
                Decision4::AskAllow
            } else {
                Decision4::AskDeny
            },
            mode: "ask".to_string(),
            actor: Actor::User,
            reason: Some(
                if allowed {
                    "allowed by user"
                } else {
                    "denied by user"
                }
                .to_string(),
            ),
            rule: None,
        }
    }
}

/// One capability class as resolved at instantiation.
#[derive(Debug, Clone)]
pub struct CeilingClassRecord {
    pub cap_id: String,
    pub mode: String,
    /// Whether the component declared this class in `act.toml`.
    pub declared: bool,
}

/// Lowercase hex SHA-256, no `sha256:` prefix.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Milliseconds, saturating — used for the `act.duration_ms` field.
pub fn duration_ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_names_are_frozen() {
        // These strings are a public contract: the OTLP exporter and any
        // dashboard built on it key off them. Changing one is a breaking change.
        assert_eq!(attr::COMPONENT_REF, "act.component.ref");
        assert_eq!(attr::COMPONENT_DIGEST, "act.component.digest");
        assert_eq!(attr::TOOL_NAME, "act.tool.name");
        assert_eq!(attr::TOOL_ARGS_SHA256, "act.tool.args_sha256");
        assert_eq!(attr::SESSION_ID, "act.session.id");
        assert_eq!(attr::AGENT_ID, "act.agent.id");
        assert_eq!(attr::REQUEST_ID, "act.request.id");
        assert_eq!(attr::TRACE_PARENT, "act.trace.parent");
        assert_eq!(attr::TRACE_STATE, "act.trace.state");
        assert_eq!(attr::TRANSPORT, "act.transport");
        assert_eq!(attr::OUTCOME, "act.outcome");
        assert_eq!(attr::DURATION_MS, "act.duration_ms");
        assert_eq!(attr::CAPABILITY_ID, "act.capability.id");
        assert_eq!(attr::RESOURCE_KEY, "act.resource.key");
        assert_eq!(attr::RESOURCE_ACTION, "act.resource.action");
        assert_eq!(attr::DECISION, "act.decision");
        assert_eq!(attr::POLICY_MODE, "act.policy.mode");
        assert_eq!(attr::POLICY_ACTOR, "act.policy.actor");
        assert_eq!(attr::POLICY_REASON, "act.policy.reason");
        assert_eq!(attr::POLICY_RULE, "act.policy.rule");
        assert_eq!(attr::CAPABILITY_DECLARED, "act.capability.declared");
    }

    #[test]
    fn static_records_carry_a_reason_only_when_denied() {
        let a = CapDecisionRecord::statik(
            "wasi:filesystem",
            "/data/x",
            "read",
            Decision4::Allow,
            "allowlist",
            Some("/data/**".into()),
        );
        assert!(a.reason.is_none());
        assert_eq!(a.actor, Actor::Static);

        let d =
            CapDecisionRecord::statik("wasi:http", "evil:443", "GET", Decision4::Deny, "ask", None);
        assert_eq!(d.reason.as_deref(), Some("outside ceiling"));
    }

    #[test]
    fn answered_records_are_attributed_to_the_user() {
        let r = CapDecisionRecord::answered("wasi:filesystem", "/k", false);
        assert_eq!(r.decision, Decision4::AskDeny);
        assert_eq!(r.actor, Actor::User);
        assert_eq!(r.reason.as_deref(), Some("denied by user"));
        assert_eq!(
            CapDecisionRecord::answered("wasi:filesystem", "/k", true).decision,
            Decision4::AskAllow
        );
    }

    #[test]
    fn decision4_renders_the_wire_spellings() {
        assert_eq!(Decision4::Allow.to_string(), "allow");
        assert_eq!(Decision4::Deny.to_string(), "deny");
        assert_eq!(Decision4::AskAllow.to_string(), "ask-allow");
        assert_eq!(Decision4::AskDeny.to_string(), "ask-deny");
    }

    #[test]
    fn decision4_marks_which_records_print_immediately() {
        // Allows are batched into the rollup; everything else is an exception
        // that must reach the operator the moment it resolves.
        assert!(!Decision4::Allow.is_exception());
        assert!(Decision4::Deny.is_exception());
        assert!(Decision4::AskAllow.is_exception());
        assert!(Decision4::AskDeny.is_exception());
    }

    #[test]
    fn sha256_hex_matches_the_known_empty_digest() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn transport_and_outcome_render_lowercase_kebab() {
        assert_eq!(Transport::Cli.to_string(), "cli");
        assert_eq!(Transport::Mcp.to_string(), "mcp");
        assert_eq!(Transport::Http.to_string(), "http");
        assert_eq!(Outcome::Ok.to_string(), "ok");
        assert_eq!(Outcome::ToolError.to_string(), "tool-error");
        assert_eq!(Outcome::HostError.to_string(), "host-error");
        assert_eq!(Outcome::Cancelled.to_string(), "cancelled");
    }
}
