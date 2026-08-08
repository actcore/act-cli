//! Structured audit trail for the ACT host.
//!
//! Two record kinds mirror the span/event split that OTLP wants: a tool call
//! is a span, and the capability decisions it triggers are events inside it.

pub mod emit;
pub mod record;
pub mod render;

pub use emit::{emit_cap_decision, finish_tool_call, tool_call_span};
pub use record::{
    Actor, CapDecisionRecord, Decision4, Outcome, ToolCallStart, Transport, attr, duration_ms,
    sha256_hex,
};
pub use render::{Rollup, SpanFields, render_exception, render_header, render_rollup};

/// Target for host-authored audit records. The audit layer's filter is pinned
/// to this and nothing else.
pub const TARGET_AUDIT: &str = "act::audit";

/// Target reserved for guest-emitted telemetry (`wasi:otel`, deferred — see
/// the design doc §4.2). Guest events are untrusted input and must never
/// reach the audit stream, so they are kept on a separate target that the
/// audit layer's filter structurally excludes.
pub const TARGET_GUEST: &str = "act::guest";
