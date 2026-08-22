//! The only module that calls `tracing` macros.
//!
//! Every value is passed as a typed field. Nothing here formats a human
//! sentence — that is the layer's job (`render.rs`), and doing it at the
//! emission site would collapse the OTLP export into one opaque attribute.

use std::time::Duration;

use tracing::field::Empty;

use crate::audit::TARGET_AUDIT;
use crate::audit::record::{
    CapDecisionRecord, CeilingClassRecord, CredentialIssueRecord, Outcome, ToolCallStart, attr,
    duration_ms,
};

/// Open the envelope span for one tool call. `act.outcome` and
/// `act.duration_ms` are declared empty and filled by `finish_tool_call`.
pub fn tool_call_span(start: &ToolCallStart) -> tracing::Span {
    tracing::info_span!(
        target: TARGET_AUDIT,
        "act.tool_call",
        { attr::COMPONENT_REF } = %start.component_ref,
        { attr::COMPONENT_DIGEST } = %start.digest,
        { attr::TOOL_NAME } = %start.tool,
        { attr::TOOL_ARGS_SHA256 } = %start.args_sha256,
        { attr::TOOL_ARGS } = start.args_json.as_deref().unwrap_or(""),
        { attr::SESSION_ID } = start.session_id.as_deref().unwrap_or(""),
        { attr::AGENT_ID } = start.agent_id.as_deref().unwrap_or(""),
        { attr::REQUEST_ID } = %start.request_id,
        { attr::TRACE_PARENT } = start.traceparent.as_deref().unwrap_or(""),
        { attr::TRACE_STATE } = start.tracestate.as_deref().unwrap_or(""),
        { attr::TRANSPORT } = %start.transport,
        { attr::OUTCOME } = Empty,
        { attr::DURATION_MS } = Empty,
    )
}

/// Record the terminal fields on an open tool-call span. The layer flushes
/// the rollup when the span closes, which happens when the caller drops it.
pub fn finish_tool_call(span: &tracing::Span, outcome: Outcome, elapsed: Duration) {
    span.record(attr::OUTCOME, tracing::field::display(outcome));
    span.record(attr::DURATION_MS, duration_ms(elapsed));
}

/// Emit one capability decision as an event inside the current span.
pub fn emit_cap_decision(r: &CapDecisionRecord) {
    // `tracing::info!`'s `target: .., { fields }, args` arm treats a single
    // leading brace-group as the *whole* field list, so a leading
    // `{ attr::CONST } = val` field gets misread as that marker instead of
    // one field. Wrapping every field below in this outer `{ }` is required
    // — do not remove it (`tool_call_span` has no such arm, hence no wrap).
    tracing::info!(
        target: TARGET_AUDIT,
        {
            { attr::CAPABILITY_ID } = %r.cap_id,
            { attr::RESOURCE_KEY } = %r.key,
            { attr::RESOURCE_ACTION } = %r.action,
            { attr::DECISION } = %r.decision,
            { attr::POLICY_MODE } = %r.mode,
            { attr::POLICY_ACTOR } = %r.actor,
            { attr::POLICY_REASON } = r.reason.as_deref().unwrap_or(""),
            { attr::POLICY_RULE } = r.rule.as_deref().unwrap_or(""),
            { attr::NEVER_ROLLUP } = r.never_rollup,
        },
        "act.cap_decision",
    );
}

/// Open the envelope span for one component instantiation. One span per
/// component load; one `emit_ceiling_class` event per capability class inside
/// it. Modelled exactly like `tool_call_span` / `emit_cap_decision` so the
/// same layer machinery renders it and an OTLP exporter gets queryable
/// per-class attributes instead of a pre-formatted sentence.
pub fn instantiation_span(component_ref: &str, digest: &str) -> tracing::Span {
    tracing::info_span!(
        target: TARGET_AUDIT,
        "act.instantiation",
        { attr::COMPONENT_REF } = %component_ref,
        { attr::COMPONENT_DIGEST } = %digest,
    )
}

/// One resolved capability class, as seen at instantiation. Carries no
/// decision — that is what distinguishes it from a `CapDecisionRecord` event
/// at the layer, which decodes strictly by presence of `act.decision`.
pub fn emit_ceiling_class(r: &CeilingClassRecord) {
    tracing::info!(
        target: TARGET_AUDIT,
        {
            { attr::CAPABILITY_ID } = %r.cap_id,
            { attr::POLICY_MODE } = %r.mode,
            { attr::CAPABILITY_DECLARED } = r.declared,
            { attr::CONSENT_PROMPT_CHANNEL } = r.has_prompt_channel,
        },
        "act.ceiling_class",
    );
}

/// One credential handed to a component. Carries no decision and no
/// capability id, which is how the layer tells it apart from the two event
/// shapes above — `act.credential.kind` is present on this event and on
/// nothing else.
///
/// Emitted on the audit target, not this crate's default log target, and that
/// is the point: `RUST_LOG` / `-v` must not be able to hide the moment a
/// secret crossed into a sandbox. Only `--no-audit` silences it.
pub fn emit_credential_issue(r: &CredentialIssueRecord) {
    tracing::info!(
        target: TARGET_AUDIT,
        {
            { attr::COMPONENT_REF } = %r.component_ref,
            { attr::SESSION_ID } = %r.session_id,
            { attr::RESOURCE_KEY } = %r.key,
            { attr::CREDENTIAL_KIND } = %r.kind,
        },
        "act.credential_issue",
    );
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::layer::{Context, Layer};
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::registry::LookupSpan;

    use super::*;
    use crate::audit::record::*;

    /// Captures `(field_name, value)` pairs off every event on the audit target.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<(String, String)>>>);

    impl tracing::field::Visit for Capture {
        fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
            self.0
                .lock()
                .unwrap()
                .push((f.name().to_string(), format!("{v:?}")));
        }
        fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
            self.0
                .lock()
                .unwrap()
                .push((f.name().to_string(), v.to_string()));
        }
    }

    impl<S> Layer<S> for Capture
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            if event.metadata().target() == crate::audit::TARGET_AUDIT {
                let mut v = self.clone();
                event.record(&mut v);
            }
        }
    }

    // Every field gets its own value, and no two fields share a value, so a
    // copy-paste mapping swap (e.g. `r.actor` written to `attr::POLICY_MODE`
    // and `r.mode` to `attr::POLICY_ACTOR`) fails an exact-match assertion
    // instead of silently passing.
    fn cap_record() -> CapDecisionRecord {
        CapDecisionRecord {
            cap_id: "wasi:filesystem".into(),
            key: "/data/app.db".into(),
            action: "read".into(),
            decision: Decision4::Allow,
            mode: "allowlist".into(),
            actor: Actor::Static,
            reason: Some("no-exception".into()),
            rule: Some("/data/**".into()),
            never_rollup: false,
        }
    }

    #[test]
    fn cap_decision_emits_every_frozen_field_name() {
        let cap = Capture::default();
        let sink = cap.clone();
        let sub = tracing_subscriber::registry().with(cap);

        tracing::subscriber::with_default(sub, || {
            emit_cap_decision(&cap_record());
        });

        let got = sink.0.lock().unwrap().clone();
        let names: Vec<&str> = got.iter().map(|(n, _)| n.as_str()).collect();
        for expected in [
            attr::CAPABILITY_ID,
            attr::RESOURCE_KEY,
            attr::RESOURCE_ACTION,
            attr::DECISION,
            attr::POLICY_MODE,
            attr::POLICY_ACTOR,
            attr::POLICY_REASON,
            attr::POLICY_RULE,
            attr::NEVER_ROLLUP,
        ] {
            assert!(
                names.contains(&expected),
                "missing field {expected} in {names:?}"
            );
        }
    }

    #[test]
    fn cap_decision_emits_values_not_a_rendered_sentence() {
        // Guards the global constraint: no field may carry a pre-formatted
        // human string, because the OTLP exporter would then see one opaque blob.
        let cap = Capture::default();
        let sink = cap.clone();
        let sub = tracing_subscriber::registry().with(cap);

        tracing::subscriber::with_default(sub, || {
            emit_cap_decision(&cap_record());
        });

        let got = sink.0.lock().unwrap().clone();
        let by = |n: &str| {
            got.iter()
                .find(|(k, _)| k == n)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        // Pins the complete eight-field map, one assertion per field, each
        // against a fixture value found nowhere else in the record — a
        // mapping swap between any two fields fails at least one of these.
        assert_eq!(by(attr::CAPABILITY_ID), "wasi:filesystem");
        assert_eq!(by(attr::RESOURCE_KEY), "/data/app.db");
        assert_eq!(by(attr::RESOURCE_ACTION), "read");
        assert_eq!(by(attr::DECISION), "allow");
        assert_eq!(by(attr::POLICY_MODE), "allowlist");
        assert_eq!(by(attr::POLICY_ACTOR), "static");
        assert_eq!(by(attr::POLICY_REASON), "no-exception");
        assert_eq!(by(attr::POLICY_RULE), "/data/**");
        assert_eq!(by(attr::NEVER_ROLLUP), "false");
        // The message field must be a stable event name, never a sentence.
        assert!(!by("message").contains("/data/app.db"));
    }
}
