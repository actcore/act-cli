//! Structured audit trail for the ACT host.
//!
//! Two record kinds mirror the span/event split that OTLP wants: a tool call
//! is a span, and the capability decisions it triggers are events inside it.

pub mod emit;
pub mod layer;
pub mod record;
pub mod render;

pub use emit::{
    emit_cap_decision, emit_ceiling_class, emit_credential_issue, finish_tool_call,
    instantiation_span, tool_call_span,
};
pub use layer::{AuditLayer, Detail};
pub use record::{
    CapDecisionRecord, CeilingClassRecord, CredentialIssueRecord, Decision4, Outcome,
    ToolCallStart, Transport, sha256_hex,
};

/// Target for host-authored audit records. The audit layer's filter is pinned
/// to this and nothing else.
pub const TARGET_AUDIT: &str = "act::audit";

/// Target reserved for guest-emitted telemetry (`wasi:otel`, deferred — see
/// the design doc §4.2). Guest events are untrusted input and must never
/// reach the audit stream, so they are kept on a separate target that the
/// audit layer's filter structurally excludes.
pub const TARGET_GUEST: &str = "act::guest";

/// A `fmt`-layer filter that lets ordinary logs through and drops both audit
/// streams.
///
/// A host that installs its own `fmt` layer alongside [`AuditLayer`] needs
/// this, or every audit record is printed twice — once as a raw tracing event
/// with all its typed fields, once rendered. `act::guest` is excluded for a
/// second reason: guest telemetry is untrusted input and has no business in
/// the operator's log at all.
pub fn fmt_filter<S>(
    env_filter: tracing_subscriber::EnvFilter,
) -> impl tracing_subscriber::layer::Filter<S> {
    use tracing_subscriber::filter::{FilterExt, filter_fn};
    env_filter.and(filter_fn(|meta: &tracing::Metadata<'_>| {
        meta.target() != crate::audit::TARGET_AUDIT && meta.target() != crate::audit::TARGET_GUEST
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_filter_excludes_audit_and_guest_targets() {
        // Pins the fmt layer's filter behaviour without touching the real
        // subscriber or stderr: a capturing layer records every target that
        // makes it through `fmt_filter`, and only the ordinary one should.
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::layer::{Context, Layer};
        use tracing_subscriber::prelude::*;
        use tracing_subscriber::registry::LookupSpan;

        #[derive(Clone, Default)]
        struct Capture(Arc<Mutex<Vec<String>>>);

        impl<S> Layer<S> for Capture
        where
            S: tracing::Subscriber + for<'a> LookupSpan<'a>,
        {
            fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
                self.0
                    .lock()
                    .unwrap()
                    .push(event.metadata().target().to_string());
            }
        }

        let cap = Capture::default();
        let sink = cap.clone();
        let env_filter: tracing_subscriber::EnvFilter = "act=info".parse().unwrap();
        let sub = tracing_subscriber::registry().with(cap.with_filter(fmt_filter(env_filter)));

        tracing::subscriber::with_default(sub, || {
            tracing::info!(target: TARGET_AUDIT, "audit event");
            tracing::info!(target: TARGET_GUEST, "guest event");
            tracing::info!(target: "act::runtime", "ordinary event");
        });

        let got = sink.0.lock().unwrap().clone();
        assert_eq!(got, vec!["act::runtime".to_string()]);
    }
}
