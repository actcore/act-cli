//! Human rendering of audit records. Pure: takes data, returns a `String`.
//!
//! Kept free of `tracing` and of I/O so every output shape is unit-testable.

use std::collections::BTreeMap;

use crate::record::CapDecisionRecord;

const PREFIX: &str = "audit: ";

/// The envelope-span fields the layer captures at span open and completes at
/// span close.
#[derive(Debug, Clone, Default)]
pub struct SpanFields {
    pub component_ref: String,
    pub digest: String,
    pub tool: String,
    pub args_sha256: String,
    pub session_id: Option<String>,
    pub transport: String,
    pub outcome: String,
    pub duration_ms: u64,
}

/// Accumulated allows for one tool call, grouped by `(cap_id, action, rule)`.
#[derive(Debug, Clone)]
pub struct Rollup {
    counts: BTreeMap<(String, String, String), u64>,
    cap: usize,
    overflow: u64,
}

impl Rollup {
    pub fn new(cap: usize) -> Self {
        Self {
            counts: BTreeMap::new(),
            cap,
            overflow: 0,
        }
    }

    /// Fold one permitted operation in. Past `cap` distinct groups, further
    /// *new* groups collapse into an overflow counter — existing groups keep
    /// counting, so the common case stays exact.
    pub fn add(&mut self, cap_id: &str, action: &str, rule: Option<&str>) {
        let key = (
            cap_id.to_string(),
            action.to_string(),
            rule.unwrap_or("").to_string(),
        );
        if let Some(n) = self.counts.get_mut(&key) {
            *n += 1;
            return;
        }
        if self.counts.len() >= self.cap {
            self.overflow += 1;
            return;
        }
        self.counts.insert(key, 1);
    }

    pub fn is_empty(&self) -> bool {
        self.counts.is_empty() && self.overflow == 0
    }

    pub fn groups(&self) -> usize {
        self.counts.len()
    }

    pub fn overflow(&self) -> u64 {
        self.overflow
    }
}

/// Truncate to at most `n` bytes without splitting a UTF-8 character.
fn take_bytes(s: &str, n: usize) -> &str {
    let mut e = s.len().min(n);
    while e > 0 && !s.is_char_boundary(e) {
        e -= 1;
    }
    &s[..e]
}

fn short_digest(digest: &str) -> String {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    format!("sha256:{}", take_bytes(hex, 6))
}

fn humanise_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else {
        format!("{:.1}s", ms as f64 / 1000.0)
    }
}

/// The instantiation header: what is running and under what modes.
pub fn render_header(component_ref: &str, digest: &str, modes: &[(String, String)]) -> String {
    let modes: Vec<String> = modes
        .iter()
        .map(|(id, mode)| format!("{id}={mode}"))
        .collect();
    format!(
        "{PREFIX}{component_ref} {} \u{2502} {}",
        short_digest(digest),
        modes.join(" ")
    )
}

/// A denial or an ask — printed the moment it resolves, never batched.
pub fn render_exception(r: &CapDecisionRecord) -> String {
    let marker = if r.decision == crate::Decision4::Deny {
        "\u{2717}"
    } else {
        "?"
    };
    let subject = if r.action.is_empty() {
        r.key.clone()
    } else {
        format!("{} {}", r.action, r.key)
    };
    let reason = r
        .reason
        .as_deref()
        .map(|s| format!("   {s}"))
        .unwrap_or_default();
    format!(
        "{PREFIX}{marker} {}  {}  {}{}",
        r.decision, r.cap_id, subject, reason
    )
}

/// The per-call summary, flushed when the envelope span closes.
pub fn render_rollup(span: &SpanFields, roll: &Rollup) -> String {
    let mut line = format!(
        "{PREFIX}\u{25cf} {}  {} {}  args:{}",
        span.tool,
        span.outcome,
        humanise_ms(span.duration_ms),
        take_bytes(&span.args_sha256, 6)
    );
    if let Some(sid) = &span.session_id {
        line.push_str(&format!("  session:{}", take_bytes(sid, 8)));
    }

    // Group by capability so one clause covers all actions on that class.
    let mut by_cap: BTreeMap<&str, Vec<(&str, &str, u64)>> = BTreeMap::new();
    for ((cap_id, action, rule), n) in &roll.counts {
        by_cap
            .entry(cap_id.as_str())
            .or_default()
            .push((action.as_str(), rule.as_str(), *n));
    }
    for (cap_id, entries) in by_cap {
        let short = cap_id.strip_prefix("wasi:").unwrap_or(cap_id);
        let ops: Vec<String> = entries
            .iter()
            .map(|(action, _, n)| {
                if action.is_empty() {
                    format!("{n}")
                } else {
                    format!("{n} {action}")
                }
            })
            .collect();
        let mut rules: Vec<&str> = entries
            .iter()
            .map(|(_, rule, _)| *rule)
            .filter(|r| !r.is_empty())
            .collect();
        rules.sort_unstable();
        rules.dedup();
        let scope = if rules.is_empty() {
            String::new()
        } else {
            format!(" under {}", rules.join(", "))
        };
        line.push_str(&format!("  {short}: {}{scope}", ops.join(" ")));
    }
    if roll.overflow > 0 {
        line.push_str(&format!("  and {} more", roll.overflow));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::*;

    fn span_fields() -> SpanFields {
        SpanFields {
            component_ref: "python-eval@0.16.0".into(),
            digest: "1f3a9c4e5d6b7a8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c".into(),
            tool: "run_python".into(),
            args_sha256: "9e21c4aa00000000".into(),
            session_id: None,
            transport: "cli".into(),
            outcome: "ok".into(),
            duration_ms: 1400,
        }
    }

    #[test]
    fn exception_line_names_decision_capability_and_reason() {
        let r = CapDecisionRecord {
            cap_id: "wasi:http".into(),
            key: "api.telemetry.example.com:443".into(),
            action: "GET".into(),
            decision: Decision4::Deny,
            mode: "ask".into(),
            actor: Actor::Static,
            reason: Some("outside ceiling".into()),
            rule: None,
        };
        let line = render_exception(&r);
        assert!(line.starts_with("audit: "), "got {line}");
        assert!(line.contains("deny"));
        assert!(line.contains("wasi:http"));
        assert!(line.contains("GET api.telemetry.example.com:443"));
        assert!(line.contains("outside ceiling"));
    }

    #[test]
    fn ask_denied_by_user_is_attributed_to_the_user() {
        let r = CapDecisionRecord {
            cap_id: "wasi:filesystem".into(),
            key: "/home/alex/.ssh/id_ed25519".into(),
            action: "read".into(),
            decision: Decision4::AskDeny,
            mode: "ask".into(),
            actor: Actor::User,
            reason: Some("denied by user".into()),
            rule: None,
        };
        let line = render_exception(&r);
        assert!(line.contains("ask-deny"));
        assert!(line.contains("denied by user"));
    }

    #[test]
    fn rollup_groups_allows_by_capability_action_and_rule() {
        let mut roll = Rollup::new(64);
        for _ in 0..12 {
            roll.add("wasi:filesystem", "read", Some("/data/**"));
        }
        for _ in 0..2 {
            roll.add("wasi:filesystem", "write", Some("/data/**"));
        }
        roll.add("wasi:http", "GET", Some("pypi.org"));

        let line = render_rollup(&span_fields(), &roll);
        assert!(line.contains("run_python"));
        assert!(line.contains("ok"));
        assert!(
            line.contains("1.4s"),
            "expected humanised duration, got {line}"
        );
        assert!(
            line.contains("args:9e21c4"),
            "expected short args digest, got {line}"
        );
        assert!(line.contains("12 read"));
        assert!(line.contains("2 write"));
        assert!(line.contains("/data/**"));
        assert!(line.contains("pypi.org"));
    }

    #[test]
    fn rollup_with_no_allows_still_reports_the_call() {
        let roll = Rollup::new(64);
        let line = render_rollup(&span_fields(), &roll);
        assert!(line.contains("run_python"));
        assert!(!line.contains("under"), "no grants touched, got {line}");
    }

    #[test]
    fn rollup_collapses_past_the_cap() {
        // A pathological component must not grow rollup state without bound.
        let mut roll = Rollup::new(2);
        roll.add("wasi:filesystem", "read", Some("/a/**"));
        roll.add("wasi:filesystem", "read", Some("/b/**"));
        roll.add("wasi:filesystem", "read", Some("/c/**"));
        roll.add("wasi:filesystem", "read", Some("/d/**"));
        assert_eq!(roll.groups(), 2);
        assert_eq!(roll.overflow(), 2);
        let line = render_rollup(&span_fields(), &roll);
        assert!(line.contains("and 2 more"), "got {line}");
    }

    #[test]
    fn header_shows_short_digest_and_per_class_modes() {
        let line = render_header(
            "python-eval@0.16.0",
            "1f3a9c4e5d6b7a8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c",
            &[
                ("wasi:filesystem".to_string(), "allowlist".to_string()),
                ("wasi:http".to_string(), "ask".to_string()),
            ],
        );
        assert!(line.contains("python-eval@0.16.0"));
        assert!(
            line.contains("sha256:1f3a9c"),
            "expected truncated digest, got {line}"
        );
        assert!(
            !line.contains("9f0a1b2c"),
            "full digest must not be printed"
        );
        assert!(line.contains("wasi:filesystem=allowlist"));
        assert!(line.contains("wasi:http=ask"));
    }

    #[test]
    fn rollup_truncates_multibyte_session_id_safely() {
        // Japanese hiragana: "アアアアア" = 5 chars × 3 bytes = 15 bytes total.
        // Byte 8 lands mid-character (inside the 3rd "ア"). This must not panic.
        let mut sf = span_fields();
        sf.session_id = Some("アアアアア".to_string());
        let roll = Rollup::new(64);

        let line = render_rollup(&sf, &roll);
        // Should render safely and contain the session clause
        assert!(
            line.contains("session:"),
            "session clause missing from {line}"
        );
        // Should truncate to a safe point (2 chars = 6 bytes for "アア")
        assert!(
            line.contains("session:アア"),
            "expected 2 chars, got {line}"
        );
    }

    #[test]
    fn rollup_with_short_session_id_unchanged() {
        // Session ID shorter than 8 bytes should not be truncated
        let mut sf = span_fields();
        sf.session_id = Some("short".to_string()); // 5 bytes
        let roll = Rollup::new(64);

        let line = render_rollup(&sf, &roll);
        assert!(
            line.contains("session:short"),
            "full short ID should appear, got {line}"
        );
    }

    #[test]
    fn rollup_truncates_multibyte_at_boundary() {
        // A session ID where the 8-byte mark happens to be on a char boundary.
        // UTF-8 boundary at 8: use a string that has a character boundary there.
        // "café" (4 chars, 5 bytes: c=1, a=1, f=1, é=2), repeated to fit.
        // We want exactly 8 bytes: "café" + "test" = 9 bytes (too long)
        // "abcd" (4 chars, 4 bytes) × 2 = 8 bytes exactly
        let mut sf = span_fields();
        sf.session_id = Some("abcdefghijklmnop".to_string()); // 16 ASCII chars = 16 bytes
        let roll = Rollup::new(64);

        let line = render_rollup(&sf, &roll);
        assert!(
            line.contains("session:abcdefgh"),
            "expected 8 chars, got {line}"
        );
    }

    #[test]
    fn take_bytes_helper_respects_utf8_boundaries() {
        // Directly test the truncation helper via a rollup that exercises it.
        // Emoji 🎉 is 4 bytes each. At max 8 bytes, we get exactly 2 emojis.
        // This test ensures we render them without panic.
        let mut sf = span_fields();
        sf.session_id = Some("🎉🎉🎉".to_string()); // 3 emoji × 4 bytes = 12 bytes
        let roll = Rollup::new(64);

        let line = render_rollup(&sf, &roll);
        // At 8 bytes exactly (char boundary), we get 2 emojis
        assert!(
            line.contains("session:🎉🎉"),
            "expected 2 emoji at boundary, got {line}"
        );
        // Third emoji should not appear (would need 12 bytes)
        assert!(
            !line.contains("🎉🎉🎉"),
            "should not contain 3 emoji, got {line}"
        );
    }
}
