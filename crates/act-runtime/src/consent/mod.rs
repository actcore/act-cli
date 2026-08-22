//! Consent: the question a capability gate asks a human, and the channel it
//! travels on.
//!
//! # Two layers of prompt text
//!
//! The builders here ([`prompt_line`], and `credentials`' `consent_summary`)
//! are the *inner* layer: they assemble one readable sentence, attribute the
//! component's own words to it, and keep guest text from forging a second
//! question. [`consent_line`] is the *outer* layer, applied by every prompter
//! just before display, and it escapes the finished line rather than keeping
//! it readable. Both are needed: the inner one is what a human can actually
//! read, the outer one is what makes the whole line unforgeable.
//!
//! [`sanitize_hint`] and [`HINT_LIMIT`] live here rather than in one gate,
//! because `act:credentials`' `hint` and `act:consent`'s `summary` are the
//! same problem — free text the guest wrote, shown to a human about to answer
//! yes or no — and two copies of that helper are two helpers that drift.

mod channel;
// Crate-visible: the gate is reached through the linker, and `ConsentGate`
// cannot be constructed without a wasmtime store, so publishing it would add
// a type to act-runtime's API that no embedder can use.
pub(crate) mod gate;

pub use channel::*;

/// Longest guest-authored free text shown on a consent prompt.
pub const HINT_LIMIT: usize = 120;

/// Build the one line a human is asked to approve for a semantic class.
///
/// Per ACT-CONSENT.md §5 the component reference leads: the whole question is
/// *which* artifact is asking to drop that database, and a prompt naming only
/// the class and key would let any component borrow another's reputation. It
/// is the reference the operator themselves supplied, never a name the guest
/// chose.
///
/// Then the class and the key — the two things policy actually matched on, so
/// what the human approves is what the grant would have authorized (§8.1) —
/// and last the component's `summary`, attributed as its own words, stripped
/// of control and bidi-override characters and truncated.
///
/// Deliberately the same shape as `credentials::consent_summary`: a human who
/// has learned to read one ACT consent prompt has learned to read them all.
pub fn prompt_line(component: Option<&str>, class: &str, key: &str, summary: &str) -> String {
    let base = match component {
        Some(c) => format!("{c} requests {class}: {key}"),
        None => format!("{class}: {key}"),
    };
    match sanitize_hint(summary) {
        h if !h.is_empty() => format!("{base} — component says: \"{h}\""),
        _ => base,
    }
}

/// Blank out anything that could forge or disguise prompt text, then truncate.
///
/// Uses the audit trail's own `needs_escape` rather than `char::is_control`:
/// the latter is Unicode category `Cc` only and misses the bidi controls
/// (U+202A-202E, U+2066-2069) and line separators (U+2028/2029). A
/// right-to-left override makes a terminal *display* a different string than
/// the one supplied — which is worth strictly more on a prompt a human is
/// about to answer than on an audit line read afterwards, so the more
/// sensitive surface must not carry the weaker predicate.
pub fn sanitize_hint(hint: &str) -> String {
    let cleaned: String = hint
        .chars()
        .map(|c| {
            if crate::audit::render::needs_escape(c) {
                ' '
            } else {
                c
            }
        })
        .collect();
    let cleaned = cleaned.trim();
    match cleaned.char_indices().nth(HINT_LIMIT) {
        Some((idx, _)) => format!("{}…", &cleaned[..idx]),
        None => cleaned.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_forged_summary_cannot_paint_a_second_prompt_line() {
        // ACT-CONSENT.md §5: unsanitized guest text can render a second, forged
        // question and collect approval for something the host never asked.
        let line = prompt_line(
            Some("ghcr.io/actpkg/postgres:1.0"),
            "db:drop",
            "analytics",
            "benign\nACT consent: db:drop — drop test_scratch? [y/N] ",
        );
        assert!(
            !line.contains('\n'),
            "the rendered line must stay one line: {line}"
        );
        assert!(
            line.contains("ghcr.io/actpkg/postgres:1.0"),
            "the component must be named"
        );
    }

    #[test]
    fn the_prompt_names_the_class_and_the_key_policy_matched_on() {
        // §8.1: there is exactly one key, and it is simultaneously what a
        // human is shown, what is recorded, and what policy matches. A prompt
        // that omitted it would let the operator approve a different subject
        // than the one authorized.
        let line = prompt_line(Some("./postgres.wasm"), "db:drop", "analytics", "");
        assert_eq!(line, "./postgres.wasm requests db:drop: analytics");
    }

    #[test]
    fn a_bidi_override_in_a_summary_is_blanked_not_merely_control_stripped() {
        for sneaky in ['\u{202e}', '\u{2066}', '\u{200f}', '\u{2028}'] {
            let line = prompt_line(
                Some("comp"),
                "db:drop",
                "analytics",
                &format!("drop{sneaky}reversed"),
            );
            assert!(
                !line.contains(sneaky),
                "U+{:04X} survived: {line}",
                sneaky as u32
            );
        }
    }

    #[test]
    fn a_long_summary_is_truncated_rather_than_flooding_the_prompt() {
        let line = prompt_line(Some("comp"), "db:drop", "analytics", &"a".repeat(500));
        assert!(
            line.chars().count() < 220,
            "got {} chars",
            line.chars().count()
        );
        assert!(line.contains('…'));
    }

    #[test]
    fn an_empty_summary_leaves_the_prompt_host_authored_end_to_end() {
        assert_eq!(
            prompt_line(None, "db:drop", "analytics", "   "),
            "db:drop: analytics"
        );
    }
}
