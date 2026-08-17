//! Interactive consent: prompt-on-access for `ask`-mode capabilities,
//! with a per-session decision cache and fail-safe (no channel = deny).

use act_policy::consent::{ConsentAsk, ConsentPrompter};

use crate::audit::render::escape_audit_field;

/// Render one consent question as the single line a human answers.
///
/// Every field is escaped, because every field can be guest-authored. That is
/// new: `wasi:filesystem` keys are canonicalised host paths and `wasi:http`
/// keys are parsed `host:port` pairs, but `act:credentials` keys are whatever
/// the component put in its `secret-request`. Unescaped, a key containing
/// `"\nACT consent: … Allow? [y/N] "` paints a second prompt line and the
/// human answers the component's question instead of the host's.
///
/// Shared by both prompters — the TTY one below and the MCP elicitation one
/// in `runtime::elicit` — so the guarantee cannot hold on one channel and not
/// the other, and so a capability class added later inherits it without
/// having to know it exists.
pub fn consent_line(ask: &ConsentAsk) -> String {
    format!(
        "ACT consent: {} — {} ({})",
        escape_audit_field(&ask.cap_id),
        escape_audit_field(&ask.summary),
        escape_audit_field(&ask.key),
    )
}

/// Prompts on the controlling terminal. Reads a line from stdin; `y`/`yes`
/// (case-insensitive) allows, anything else (incl. EOF) denies.
pub struct TtyPrompter;

#[async_trait::async_trait]
impl ConsentPrompter for TtyPrompter {
    async fn decide(&self, ask: &ConsentAsk) -> bool {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let mut stderr = tokio::io::stderr();
        let prompt = format!("\n{}\nAllow? [y/N] ", consent_line(ask));
        if stderr.write_all(prompt.as_bytes()).await.is_err() {
            return false;
        }
        let _ = stderr.flush().await;
        let mut line = String::new();
        let mut reader = BufReader::new(tokio::io::stdin());
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => false,
            Ok(_) => matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"),
        }
    }
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
