//! Structured audit trail for the ACT host.
//!
//! Two record kinds mirror the span/event split that OTLP wants: a tool call
//! is a span, and the capability decisions it triggers are events inside it.

pub mod emit;
pub mod layer;
pub mod record;
pub mod render;

pub use emit::{
    emit_cap_decision, emit_ceiling_class, finish_tool_call, instantiation_span, tool_call_span,
};
pub use layer::{AuditLayer, AuditWriter, Detail, StderrWriter};
pub use record::{
    Actor, CapDecisionRecord, CeilingClassRecord, Decision4, Outcome, ToolCallStart, Transport,
    attr, duration_ms, sha256_hex,
};
pub use render::{
    Rollup, SpanFields, render_declared_ask_blocked_warning, render_declared_ungranted_warning,
    render_exception, render_header, render_rollup,
};

/// Target for host-authored audit records. The audit layer's filter is pinned
/// to this and nothing else.
pub const TARGET_AUDIT: &str = "act::audit";

/// Target reserved for guest-emitted telemetry (`wasi:otel`, deferred — see
/// the design doc §4.2). Guest events are untrusted input and must never
/// reach the audit stream, so they are kept on a separate target that the
/// audit layer's filter structurally excludes.
pub const TARGET_GUEST: &str = "act::guest";
