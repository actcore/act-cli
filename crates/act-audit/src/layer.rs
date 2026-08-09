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
use crate::record::{Actor, CapDecisionRecord, CeilingClassRecord, Decision4, attr};
use crate::render::{
    Rollup, SpanFields, render_declared_ungranted_warning, render_exception, render_header,
    render_rollup,
};

/// Name of the tool-call envelope span, set by `emit::tool_call_span`.
const SPAN_TOOL_CALL: &str = "act.tool_call";
/// Name of the instantiation envelope span, set by `emit::instantiation_span`.
const SPAN_INSTANTIATION: &str = "act.instantiation";

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
            // AGENT_ID, TRACE_PARENT and TRACE_STATE are captured onto the
            // span but stay unrendered by design; only REQUEST_ID reaches a
            // line, so an operator can join it back to a client log line.
            n if n == attr::REQUEST_ID => self.0.request_id = v.to_string(),
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
        // Every field here is recorded with `%value` (Display), which
        // tracing routes through `record_debug` with a wrapper whose `Debug`
        // impl just forwards to `Display` — so `{v:?}` is already the plain,
        // unquoted value. Do not strip quotes here: a guest-chosen value may
        // legitimately start or end with one, and trimming it corrupts data.
        let s = format!("{v:?}");
        self.record_str(f, &s);
    }
}

/// Collects one capability-decision event — or one ceiling-class event, from
/// an instantiation span — back into a record. The two share a visitor
/// because both carry `act.capability.id`; `into_record` / the `declared`
/// field is how the layer tells them apart (see `on_event`).
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
    declared: bool,
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

    fn record_bool(&mut self, f: &Field, v: bool) {
        // `act.capability.declared` is the only bool field this crate emits.
        // Without this override, tracing's default `Visit::record_bool`
        // routes a bool to `record_debug`, whose output ("true"/"false")
        // doesn't match any `record_str` arm above — the field would be
        // silently dropped and the declared-but-ungranted warning could
        // never fire.
        if f.name() == attr::CAPABILITY_DECLARED {
            self.declared = v;
        }
    }

    fn record_debug(&mut self, f: &Field, v: &dyn std::fmt::Debug) {
        // See the identical comment on `SpanVisitor::record_debug`: these
        // fields all arrive as `%value` and are already unquoted.
        let s = format!("{v:?}");
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

/// Per-instantiation-span state: the envelope identity plus every capability
/// class resolved for this component load, collected as `emit_ceiling_class`
/// events arrive.
struct InstantiationState {
    component_ref: String,
    digest: String,
    classes: Vec<CeilingClassRecord>,
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
        // Two envelope kinds share this target: a tool call gets the rollup
        // state it always had; an instantiation gets a plain vec of ceiling
        // classes. Branching on the span *name* (not just target) matters —
        // every audit-target span used to get a tool-call `SpanState`
        // unconditionally, which would make an instantiation span render as
        // a bogus tool call once it started reaching this layer at all.
        match attrs.metadata().name() {
            SPAN_TOOL_CALL => {
                span.extensions_mut().insert(SpanState {
                    fields: v.0,
                    rollup: Rollup::new(self.rollup_cap),
                });
            }
            SPAN_INSTANTIATION => {
                span.extensions_mut().insert(InstantiationState {
                    component_ref: v.0.component_ref,
                    digest: v.0.digest,
                    classes: Vec::new(),
                });
            }
            _ => {}
        }
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

        // A ceiling-class record (from `emit_ceiling_class`, inside an
        // instantiation span) carries a capability id but no `act.decision`
        // — a capability decision always carries both. That's the only
        // signal available at this point to tell the two event shapes
        // apart, so check it before falling through to `into_record`, which
        // requires a decision and would otherwise just drop this event.
        if !v.cap_id.is_empty() && v.decision.is_empty() {
            let record = CeilingClassRecord {
                cap_id: v.cap_id,
                mode: v.mode,
                declared: v.declared,
            };
            let _ = ctx.event_scope(event).is_some_and(|mut scope| {
                scope.any(
                    |span| match span.extensions_mut().get_mut::<InstantiationState>() {
                        Some(state) => {
                            state.classes.push(record.clone());
                            true
                        }
                        None => false,
                    },
                )
            });
            return;
        }

        let Some(record) = v.into_record() else {
            return;
        };

        if record.decision.is_exception() || self.detail == Detail::Full {
            self.emit(|| render_exception(&record));
        }
        if !record.decision.is_exception() {
            // Fold into the nearest enclosing tool-call span, if there is
            // one. `SpanState` is installed only on TARGET_AUDIT spans, so a
            // plain (non-audit) span nested between the event and the tool
            // call would make a direct parent lookup miss it — walk the
            // whole scope instead of just the immediate parent. A decision
            // fired outside any call (instantiation) has nowhere to roll up,
            // so it is printed instead of dropped.
            let folded = ctx.event_scope(event).is_some_and(|mut scope| {
                scope.any(|span| match span.extensions_mut().get_mut::<SpanState>() {
                    Some(state) => {
                        state
                            .rollup
                            .add(&record.cap_id, &record.action, record.rule.as_deref());
                        true
                    }
                    None => false,
                })
            });
            // Carries the instantiation-time guarantee: an allow with
            // nowhere to fold (no enclosing tool-call span) would otherwise
            // be silently dropped under Detail::Rollup. Detail::Full already
            // printed it above, so this only fires under Detail::Rollup.
            if !folded && self.detail != Detail::Full {
                self.emit(|| render_exception(&record));
            }
        }
    }

    fn on_close(&self, id: span::Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };
        let mut ext = span.extensions_mut();
        if let Some(state) = ext.remove::<SpanState>() {
            drop(ext);
            self.emit(|| render_rollup(&state.fields, &state.rollup));
            return;
        }
        let Some(state) = ext.remove::<InstantiationState>() else {
            return;
        };
        drop(ext);
        let modes: Vec<(String, String)> = state
            .classes
            .iter()
            .map(|c| (c.cap_id.clone(), c.mode.clone()))
            .collect();
        self.emit(|| render_header(&state.component_ref, &state.digest, &modes));
        // Only a class the component actually declared, that still resolved
        // to deny, is worth a warning — every undeclared class also resolves
        // to deny, and flagging all of those would bury the one signal an
        // operator needs: a capability the component asked for that nothing
        // granted.
        let ungranted: Vec<String> = state
            .classes
            .iter()
            .filter(|c| c.declared && c.mode == "deny")
            .map(|c| c.cap_id.clone())
            .collect();
        if !ungranted.is_empty() {
            self.emit(|| render_declared_ungranted_warning(&ungranted));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tracing_subscriber::prelude::*;

    use super::*;
    use crate::emit::{
        emit_cap_decision, emit_ceiling_class, finish_tool_call, instantiation_span, tool_call_span,
    };
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
        // Pins that on_record actually landed the values finish_tool_call
        // recorded, not just that some line got printed.
        assert!(out[0].contains("ok"), "outcome missing, got {}", out[0]);
        assert!(
            out[0].contains("1.4s"),
            "humanised duration missing, got {}",
            out[0]
        );
        // Pins that SpanVisitor actually captured these off the real span
        // (not just that render_rollup can format them when handed a
        // hand-built SpanFields directly, which is all render.rs's own
        // tests exercise).
        assert!(
            out[0].contains("args:9e21c4"),
            "args_sha256 missing, got {}",
            out[0]
        );
        assert!(
            out[0].contains("req:req-1"),
            "request_id missing, got {}",
            out[0]
        );
    }

    #[test]
    fn a_real_session_id_is_captured_from_the_span_and_rendered() {
        // Every other layer.rs fixture uses session_id: None, so the
        // SESSION_ID capture arm in SpanVisitor::record_str is otherwise
        // never exercised end-to-end: a broken capture and "no session on
        // this call" render identically (no "session:" clause) unless a
        // real, non-empty id is driven through the real span.
        let mut s = start();
        s.session_id = Some("sess-abc123def456".into());
        let out = run(|| {
            let span = tool_call_span(&s);
            let _g = span.enter();
            finish_tool_call(&span, Outcome::Ok, Duration::from_millis(5));
        });
        assert_eq!(out.len(), 1, "got {out:?}");
        assert!(
            out[0].contains("session:sess-abc"),
            "session id missing, got {}",
            out[0]
        );
    }

    #[test]
    fn an_allow_inside_a_non_audit_span_still_folds_into_the_enclosing_tool_call() {
        // SpanState lives only on TARGET_AUDIT spans. A plain span nested
        // between the event and the tool call must not break the fold — the
        // host will instrument exactly this region in a later task.
        let out = run(|| {
            let span = tool_call_span(&start());
            let _g = span.enter();
            {
                let inner = tracing::info_span!("some.other.span");
                let _inner_g = inner.enter();
                emit_cap_decision(&allow("read", "/data/**"));
            }
            finish_tool_call(&span, Outcome::Ok, Duration::from_millis(10));
        });
        assert_eq!(out.len(), 1, "expected a single rollup line, got {out:?}");
        assert!(out[0].contains("1 read"), "got {}", out[0]);
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
        // Three individual operations, each naming the capability, then the
        // rollup — not e.g. three rollups plus one exception.
        for line in &out[..3] {
            assert!(line.contains("wasi:filesystem"), "got {out:?}");
        }
        assert!(out[3].contains("run_python"), "got {out:?}");
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
    fn an_allow_outside_any_tool_call_still_reaches_the_operator() {
        // Same scenario as the deny case above, but for an allow: with no
        // enclosing tool-call span there is nowhere to fold it, so it must
        // print immediately rather than being silently dropped.
        let out = run(|| emit_cap_decision(&allow("read", "/data/**")));
        assert_eq!(out.len(), 1, "got {out:?}");
        assert!(out[0].contains("wasi:filesystem"), "got {out:?}");
    }

    #[test]
    fn ask_allow_and_ask_deny_decode_correctly() {
        // `EventVisitor::into_record` matches "ask-allow" / "ask-deny" by
        // string; a typo in either arm would delete every ask outcome from
        // the trail with no test failing. `answered` also attributes both to
        // Actor::User, exercising that decode arm too.
        let out = run(|| {
            emit_cap_decision(&CapDecisionRecord::answered(
                "wasi:filesystem",
                "/data/x",
                true,
            ));
            emit_cap_decision(&CapDecisionRecord::answered(
                "wasi:http",
                "evil.example.com",
                false,
            ));
        });
        assert_eq!(out.len(), 2, "got {out:?}");
        assert!(out[0].contains("ask-allow"), "got {out:?}");
        assert!(out[1].contains("ask-deny"), "got {out:?}");
    }

    #[test]
    fn a_quote_bearing_resource_key_survives_rendering_intact() {
        // `%value` fields route through `record_debug`, whose `Debug` output
        // is already the unquoted Display form. A prior `trim_matches('"')`
        // there stripped real leading/trailing quote characters out of
        // guest-controlled data instead of normalising anything.
        let out = run(|| {
            emit_cap_decision(&CapDecisionRecord {
                cap_id: "wasi:filesystem".into(),
                key: "\"payload\".json".into(),
                action: "read".into(),
                decision: Decision4::Deny,
                mode: "ask".into(),
                actor: Actor::Static,
                reason: Some("outside ceiling".into()),
                rule: None,
            });
        });
        assert_eq!(out.len(), 1, "got {out:?}");
        assert!(
            out[0].contains("\"payload\".json"),
            "quotes must survive intact, got {}",
            out[0]
        );
    }

    #[test]
    fn a_call_that_never_finishes_renders_as_incomplete() {
        // A span created and entered but closed without finish_tool_call
        // ever being called (early return, or dropped) is exactly the case
        // an auditor cares about — it must not render as if outcome "" and
        // duration_ms 0 were a real completed call.
        let out = run(|| {
            let span = tool_call_span(&start());
            let _g = span.enter();
            emit_cap_decision(&allow("read", "/data/**"));
            // Deliberately never call finish_tool_call.
        });
        assert_eq!(out.len(), 1, "got {out:?}");
        assert!(out[0].contains("incomplete"), "got {}", out[0]);
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
    fn an_instantiation_span_renders_one_header_line() {
        let out = run(|| {
            let span = instantiation_span("python-eval@0.16.0", "1f3a9c4e");
            let _g = span.enter();
            emit_ceiling_class(&CeilingClassRecord {
                cap_id: "wasi:filesystem".into(),
                mode: "allowlist".into(),
                declared: true,
            });
            emit_ceiling_class(&CeilingClassRecord {
                cap_id: "wasi:http".into(),
                mode: "ask".into(),
                declared: true,
            });
        });
        assert_eq!(out.len(), 1, "got {out:?}");
        assert!(
            out[0].contains("wasi:filesystem=allowlist"),
            "got {}",
            out[0]
        );
        assert!(out[0].contains("wasi:http=ask"));
        assert!(out[0].contains("sha256:1f3a9c"));
    }

    #[test]
    fn a_declared_but_denied_class_produces_a_warning_line() {
        let out = run(|| {
            let span = instantiation_span("c@1", "abcdef01");
            let _g = span.enter();
            emit_ceiling_class(&CeilingClassRecord {
                cap_id: "wasi:http".into(),
                mode: "deny".into(),
                declared: true,
            });
        });
        assert_eq!(out.len(), 2, "header + warning, got {out:?}");
        assert!(out[1].contains("wasi:http"));
        assert!(out[1].contains("not granted"), "got {}", out[1]);
    }

    #[test]
    fn an_undeclared_denied_class_produces_no_warning() {
        // Every class the component never asked for resolves to deny. Warning
        // on those would bury the one signal that matters.
        let out = run(|| {
            let span = instantiation_span("c@1", "abcdef01");
            let _g = span.enter();
            emit_ceiling_class(&CeilingClassRecord {
                cap_id: "wasi:sockets".into(),
                mode: "deny".into(),
                declared: false,
            });
        });
        assert_eq!(out.len(), 1, "header only, got {out:?}");
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
