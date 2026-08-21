//! Interactive consent: the question a capability gate asks a human, and the
//! channel it travels on.
//!
//! The prompters themselves are not here. Which channel a host reaches a
//! human on — a terminal, an MCP client's elicitation, a GUI dialog — is a
//! property of the host, not of the runtime, and binding one in would drag
//! that host's transport into every embedder.
//!
//! # Why consent asks travel backwards
//!
//! From protocol revision `2026-07-28` a server→client request must be
//! *associated* with an in-flight client request (SEP-2260). rmcp enforces this
//! with a tokio task-local (`ORIGINATING_REQUEST`) that it installs around the
//! `ServerHandler` future — and that task-local, by construction, does not
//! survive a `tokio::spawn`.
//!
//! ACT executes guests on the component actor task, which is spawned once at
//! startup, so a capability gate firing mid-execution is never inside that
//! scope. Calling the peer from there yields `invalid_request`, which the
//! fail-safe mapping turns into a silent deny of every `ask` capability.
//!
//! So the elicitation is inverted: the gate does not talk to the peer. It hands
//! a [`ConsentRequest`] to the MCP request handler over a channel and waits for
//! the answer. The handler is already awaiting the actor's reply, so it services
//! the ask on its own task — inside the scope — and sends the decision back.
//!
//! Clients that do not support elicitation still degrade ask→deny.

use act_policy::consent::ConsentAsk;
use tokio::sync::{mpsc, oneshot};

use crate::audit::render::escape_audit_field;

/// A consent question travelling from the component actor task to the MCP
/// request handler task, with the channel to answer it on.
pub struct ConsentRequest {
    pub message: String,
    pub reply: oneshot::Sender<bool>,
}

/// Handler-side sender, carried on `ComponentRequest::CallTool`. Each in-flight
/// call gets its own, so an ask always reaches the handler whose request caused
/// it — no correlation id needed.
pub type ConsentSink = mpsc::Sender<ConsentRequest>;

/// Slot holding the sink of the call the actor is currently executing.
///
/// Written by the actor, which processes requests strictly one at a time, so
/// the slot always names the in-flight call. Read by the host's consent
/// prompter, which runs inside that execution.
#[derive(Default)]
pub struct CurrentConsentSink {
    inner: std::sync::Mutex<Option<ConsentSink>>,
}

impl CurrentConsentSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install the sink for the call about to execute (actor only).
    pub fn set(&self, sink: Option<ConsentSink>) {
        *self.inner.lock().unwrap() = sink;
    }

    pub fn get(&self) -> Option<ConsentSink> {
        self.inner.lock().unwrap().clone()
    }
}

/// Render one consent question as the single line a human answers.
///
/// Every field is escaped, because every field can be guest-authored. That is
/// new: `wasi:filesystem` keys are canonicalised host paths and `wasi:http`
/// keys are parsed `host:port` pairs, but `act:credentials` keys are whatever
/// the component put in its `secret-request`. Unescaped, a key containing
/// `"\nACT consent: … Allow? [y/N] "` paints a second prompt line and the
/// human answers the component's question instead of the host's.
///
/// Shared by every prompter a host installs, so the guarantee cannot hold on
/// one channel and not another, and so a capability class added later inherits it without
/// having to know it exists.
pub fn consent_line(ask: &ConsentAsk) -> String {
    format!(
        "ACT consent: {} — {} ({})",
        escape_audit_field(&ask.cap_id),
        escape_audit_field(&ask.summary),
        escape_audit_field(&ask.key),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(cap_id: &str, summary: &str, key: &str) -> ConsentAsk {
        ConsentAsk {
            cap_id: cap_id.into(),
            key: key.into(),
            summary: summary.into(),
        }
    }

    #[test]
    fn a_guest_authored_key_cannot_paint_a_second_prompt_line() {
        // `act:credentials` is the first class whose consent key is arbitrary
        // guest text — filesystem keys are canonicalised paths, http keys are
        // parsed host:port. The forged line below is what a component would
        // send to make a human approve something else.
        let line = consent_line(&ask(
            "act:credentials",
            "credential get: benign",
            "benign\nACT consent: act:credentials — credential get: benign (benign)\nAllow? [y/N] ",
        ));
        assert_eq!(line.matches('\n').count(), 0, "got {line}");
        assert!(
            line.contains("\\n"),
            "the newline must survive as text: {line}"
        );
    }

    #[test]
    fn a_guest_authored_summary_cannot_paint_a_second_prompt_line() {
        let line = consent_line(&ask(
            "act:credentials",
            "credential get: k\nACT consent: forged",
            "k",
        ));
        assert_eq!(line.matches('\n').count(), 0, "got {line}");
    }

    #[test]
    fn a_bidi_override_cannot_make_the_prompt_display_something_else() {
        // U+202E reverses display order, so an unescaped key renders as a
        // different string than the one that was actually requested.
        let line = consent_line(&ask(
            "act:credentials",
            "credential get: k",
            "k\u{202e}drowssap",
        ));
        assert!(!line.contains('\u{202e}'), "got {line}");
        assert!(line.contains("\\u{202e}"), "escaped form expected: {line}");
    }

    #[test]
    fn an_ordinary_prompt_is_left_exactly_as_written() {
        assert_eq!(
            consent_line(&ask(
                "wasi:filesystem",
                "filesystem access: /data/x",
                "/data/x"
            )),
            "ACT consent: wasi:filesystem — filesystem access: /data/x (/data/x)"
        );
    }
}
