//! The audit layer.
//!
//! Rollup requires state accumulated across events within a span, which a
//! `FormatEvent` implementation cannot hold — so this is a full `Layer` that
//! keeps per-span state in span extensions:
//!
//! * `on_new_span`  — capture the envelope fields, install an empty `Rollup`
//! * `on_record`    — pick up `outcome` / `duration_ms` recorded at finish
//! * `on_event`     — print exceptions now, fold allows into the parent span
//! * `on_close`     — render and flush the rollup line

use std::io::Write;
use std::sync::Mutex;

use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber, span};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

use crate::TARGET_AUDIT;
use crate::record::{Actor, CapDecisionRecord, Decision4, attr};
use crate::render::{Rollup, SpanFields, render_exception, render_rollup};

/// Default cap on distinct rollup groups per tool call. Chosen to comfortably
/// cover a well-behaved component; past it, new groups collapse into a count.
pub const DEFAULT_ROLLUP_CAP: usize = 64;

/// How much the operator wants to see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detail {
    /// Exceptions immediately; allows summarised per tool call.
    Rollup,
    /// Every operation, plus the summary.
    Full,
}

/// Where rendered lines go. Abstracted so tests can capture them.
pub trait AuditWriter: Send + Sync + 'static {
    fn write_line(&self, line: &str);
}

/// The production sink: stderr, line-buffered, failures ignored.
pub struct StderrWriter {
    inner: Mutex<std::io::Stderr>,
}

impl Default for StderrWriter {
    fn default() -> Self {
        Self {
            inner: Mutex::new(std::io::stderr()),
        }
    }
}

impl AuditWriter for StderrWriter {
    fn write_line(&self, line: &str) {
        // A closed or full stderr degrades to silence. Audit must never
        // affect a decision, so nothing here can fail upward.
        if let Ok(mut w) = self.inner.lock() {
            let _ = writeln!(w, "{line}");
            let _ = w.flush();
        }
    }
}

pub struct AuditLayer<W> {
    writer: W,
    detail: Detail,
    rollup_cap: usize,
}

impl AuditLayer<StderrWriter> {
    pub fn stderr(detail: Detail) -> Self {
        Self::new(StderrWriter::default(), detail)
    }
}

impl<W: AuditWriter> AuditLayer<W> {
    pub fn new(writer: W, detail: Detail) -> Self {
        Self {
            writer,
            detail,
            rollup_cap: DEFAULT_ROLLUP_CAP,
        }
    }

    pub fn with_rollup_cap(mut self, cap: usize) -> Self {
        self.rollup_cap = cap;
        self
    }

    /// Never let a rendering or writing fault escape into enforcement.
    ///
    /// Takes a **closure**, not a `String`, deliberately: an argument would be
    /// evaluated before `catch_unwind` is entered, so a panic while rendering
    /// would unwind through the layer — and rendering handles guest-chosen
    /// values. The audit path must not be able to take the host down.
    fn emit(&self, render: impl FnOnce() -> String) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.writer.write_line(&render());
        }));
    }
}

/// Collects the envelope fields declared by `emit::tool_call_span`.
#[derive(Default)]
struct SpanVisitor(SpanFields);

impl Visit for SpanVisitor {
    fn record_str(&mut self, f: &Field, v: &str) {
        match f.name() {
            n if n == attr::COMPONENT_REF => self.0.component_ref = v.to_string(),
            n if n == attr::COMPONENT_DIGEST => self.0.digest = v.to_string(),
            n if n == attr::TOOL_NAME => self.0.tool = v.to_string(),
            n if n == attr::TOOL_ARGS_SHA256 => self.0.args_sha256 = v.to_string(),
            n if n == attr::TRANSPORT => self.0.transport = v.to_string(),
            n if n == attr::OUTCOME => self.0.outcome = v.to_string(),
            n if n == attr::SESSION_ID && !v.is_empty() => {
                self.0.session_id = Some(v.to_string());
            }
            _ => {}
        }
    }

    fn record_u64(&mut self, f: &Field, v: u64) {
        if f.name() == attr::DURATION_MS {
            self.0.duration_ms = v;
        }
    }

    fn record_debug(&mut self, f: &Field, v: &dyn std::fmt::Debug) {
        // `%value` fields arrive as Display-formatted debug output in some
        // tracing versions; normalise by stripping surrounding quotes.
        let s = format!("{v:?}");
        let s = s.trim_matches('"').to_string();
        self.record_str(f, &s);
    }
}

/// Collects one capability-decision event back into a record.
#[derive(Default)]
struct EventVisitor {
    cap_id: String,
    key: String,
    action: String,
    decision: String,
    mode: String,
    actor: String,
    reason: String,
    rule: String,
}

impl Visit for EventVisitor {
    fn record_str(&mut self, f: &Field, v: &str) {
        match f.name() {
            n if n == attr::CAPABILITY_ID => self.cap_id = v.to_string(),
            n if n == attr::RESOURCE_KEY => self.key = v.to_string(),
            n if n == attr::RESOURCE_ACTION => self.action = v.to_string(),
            n if n == attr::DECISION => self.decision = v.to_string(),
            n if n == attr::POLICY_MODE => self.mode = v.to_string(),
            n if n == attr::POLICY_ACTOR => self.actor = v.to_string(),
            n if n == attr::POLICY_REASON => self.reason = v.to_string(),
            n if n == attr::POLICY_RULE => self.rule = v.to_string(),
            _ => {}
        }
    }

    fn record_debug(&mut self, f: &Field, v: &dyn std::fmt::Debug) {
        let s = format!("{v:?}");
        let s = s.trim_matches('"').to_string();
        self.record_str(f, &s);
    }
}

impl EventVisitor {
    fn into_record(self) -> Option<CapDecisionRecord> {
        if self.cap_id.is_empty() || self.decision.is_empty() {
            return None;
        }
        let decision = match self.decision.as_str() {
            "allow" => Decision4::Allow,
            "deny" => Decision4::Deny,
            "ask-allow" => Decision4::AskAllow,
            "ask-deny" => Decision4::AskDeny,
            _ => return None,
        };
        let actor = match self.actor.as_str() {
            "user" => Actor::User,
            "policy" => Actor::Policy,
            _ => Actor::Static,
        };
        Some(CapDecisionRecord {
            cap_id: self.cap_id,
            key: self.key,
            action: self.action,
            decision,
            mode: self.mode,
            actor,
            reason: (!self.reason.is_empty()).then_some(self.reason),
            rule: (!self.rule.is_empty()).then_some(self.rule),
        })
    }
}

struct SpanState {
    fields: SpanFields,
    rollup: Rollup,
}

impl<S, W> Layer<S> for AuditLayer<W>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: AuditWriter,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        if attrs.metadata().target() != TARGET_AUDIT {
            return;
        }
        let Some(span) = ctx.span(id) else { return };
        let mut v = SpanVisitor::default();
        attrs.record(&mut v);
        span.extensions_mut().insert(SpanState {
            fields: v.0,
            rollup: Rollup::new(self.rollup_cap),
        });
    }

    fn on_record(&self, id: &span::Id, values: &span::Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut ext = span.extensions_mut();
        let Some(state) = ext.get_mut::<SpanState>() else {
            return;
        };
        let mut v = SpanVisitor(std::mem::take(&mut state.fields));
        values.record(&mut v);
        state.fields = v.0;
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        if event.metadata().target() != TARGET_AUDIT {
            return;
        }
        let mut v = EventVisitor::default();
        event.record(&mut v);
        let Some(record) = v.into_record() else {
            return;
        };

        if record.decision.is_exception() || self.detail == Detail::Full {
            self.emit(|| render_exception(&record));
        }
        if !record.decision.is_exception() {
            // Fold into the enclosing tool-call span, if there is one. A
            // decision fired outside any call (instantiation) has nowhere to
            // roll up, so it is printed instead of dropped.
            let folded = ctx.event_span(event).is_some_and(|span| {
                let mut ext = span.extensions_mut();
                match ext.get_mut::<SpanState>() {
                    Some(state) => {
                        state
                            .rollup
                            .add(&record.cap_id, &record.action, record.rule.as_deref());
                        true
                    }
                    None => false,
                }
            });
            if !folded && self.detail != Detail::Full {
                self.emit(|| render_exception(&record));
            }
        }
    }

    fn on_close(&self, id: span::Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };
        let state = span.extensions_mut().remove::<SpanState>();
        let Some(state) = state else { return };
        self.emit(|| render_rollup(&state.fields, &state.rollup));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tracing_subscriber::prelude::*;

    use super::*;
    use crate::emit::{emit_cap_decision, finish_tool_call, tool_call_span};
    use crate::record::*;

    #[derive(Clone, Default)]
    struct TestWriter(Arc<Mutex<Vec<String>>>);

    impl AuditWriter for TestWriter {
        fn write_line(&self, line: &str) {
            self.0.lock().unwrap().push(line.to_string());
        }
    }

    fn start() -> ToolCallStart {
        ToolCallStart {
            component_ref: "python-eval@0.16.0".into(),
            digest: "1f3a9c4e5d6b7a8c".into(),
            tool: "run_python".into(),
            args_sha256: "9e21c4aa".into(),
            session_id: None,
            transport: Transport::Cli,
            agent_id: None,
            request_id: "req-1".into(),
            traceparent: None,
            tracestate: None,
        }
    }

    fn allow(action: &str, rule: &str) -> CapDecisionRecord {
        CapDecisionRecord {
            cap_id: "wasi:filesystem".into(),
            key: "/data/app.db".into(),
            action: action.into(),
            decision: Decision4::Allow,
            mode: "allowlist".into(),
            actor: Actor::Static,
            reason: None,
            rule: Some(rule.into()),
        }
    }

    fn deny() -> CapDecisionRecord {
        CapDecisionRecord {
            cap_id: "wasi:http".into(),
            key: "evil.example.com:443".into(),
            action: "GET".into(),
            decision: Decision4::Deny,
            mode: "ask".into(),
            actor: Actor::Static,
            reason: Some("outside ceiling".into()),
            rule: None,
        }
    }

    fn run(f: impl FnOnce()) -> Vec<String> {
        let w = TestWriter::default();
        let sink = w.clone();
        let sub = tracing_subscriber::registry().with(AuditLayer::new(w, Detail::Rollup));
        tracing::subscriber::with_default(sub, f);
        sink.0.lock().unwrap().clone()
    }

    #[test]
    fn allows_produce_exactly_one_line_at_span_close() {
        let out = run(|| {
            let span = tool_call_span(&start());
            let _g = span.enter();
            for _ in 0..12 {
                emit_cap_decision(&allow("read", "/data/**"));
            }
            finish_tool_call(&span, Outcome::Ok, Duration::from_millis(1400));
        });
        assert_eq!(out.len(), 1, "expected a single rollup line, got {out:?}");
        assert!(out[0].contains("12 read"), "got {}", out[0]);
        assert!(out[0].contains("run_python"));
    }

    #[test]
    fn a_denial_prints_immediately_and_before_the_rollup() {
        let out = run(|| {
            let span = tool_call_span(&start());
            let _g = span.enter();
            emit_cap_decision(&deny());
            emit_cap_decision(&allow("read", "/data/**"));
            finish_tool_call(&span, Outcome::Ok, Duration::from_millis(10));
        });
        assert_eq!(out.len(), 2, "got {out:?}");
        assert!(out[0].contains("deny"), "denial must come first: {out:?}");
        assert!(
            out[1].contains("run_python"),
            "rollup must come last: {out:?}"
        );
    }

    #[test]
    fn full_detail_prints_every_operation() {
        let w = TestWriter::default();
        let sink = w.clone();
        let sub = tracing_subscriber::registry().with(AuditLayer::new(w, Detail::Full));
        tracing::subscriber::with_default(sub, || {
            let span = tool_call_span(&start());
            let _g = span.enter();
            for _ in 0..3 {
                emit_cap_decision(&allow("read", "/data/**"));
            }
            finish_tool_call(&span, Outcome::Ok, Duration::from_millis(5));
        });
        let out = sink.0.lock().unwrap().clone();
        assert_eq!(out.len(), 4, "3 ops + 1 rollup, got {out:?}");
    }

    #[test]
    fn a_decision_outside_any_tool_call_still_reaches_the_operator() {
        // Capability gates can fire during instantiation, before any tool
        // call exists. Those records must not be swallowed.
        let out = run(|| emit_cap_decision(&deny()));
        assert_eq!(out.len(), 1, "got {out:?}");
        assert!(out[0].contains("deny"));
    }

    #[test]
    fn a_panic_while_rendering_does_not_poison_enforcement() {
        // Rendering touches guest-chosen values, so it must run inside the
        // same catch_unwind as the write — not be evaluated before it.
        struct Silent;
        impl AuditWriter for Silent {
            fn write_line(&self, _l: &str) {}
        }
        let layer = AuditLayer::new(Silent, Detail::Rollup);
        layer.emit(|| panic!("render exploded"));
        // Reaching here without unwinding is the assertion.
    }

    #[test]
    fn a_writer_that_panics_does_not_poison_enforcement() {
        struct Exploding;
        impl AuditWriter for Exploding {
            fn write_line(&self, _l: &str) {
                panic!("sink exploded");
            }
        }
        let sub = tracing_subscriber::registry().with(AuditLayer::new(Exploding, Detail::Rollup));
        tracing::subscriber::with_default(sub, || {
            emit_cap_decision(&deny());
        });
        // Reaching here without unwinding is the assertion.
    }
}
