//! Human rendering of audit records. Pure: takes data, returns a `String`.
//!
//! Kept free of `tracing` and of I/O so every output shape is unit-testable.

use std::borrow::Cow;
use std::collections::BTreeMap;

use crate::record::{CapDecisionRecord, Decision4};

const PREFIX: &str = "audit: ";

/// The envelope-span fields the layer captures at span open and completes at
/// span close.
#[derive(Debug, Clone)]
pub struct SpanFields {
    pub component_ref: String,
    pub digest: String,
    pub tool: String,
    pub args_sha256: String,
    pub session_id: Option<String>,
    pub transport: String,
    /// Defaults to `"incomplete"`, never empty: a span that closes without
    /// `finish_tool_call` ever recording an outcome (dropped early, never
    /// entered) must not render as if the call had actually completed.
    pub outcome: String,
    pub duration_ms: u64,
    /// `std:request-id`, or a host-generated id. Rendered truncated and
    /// escaped — it is the only way an operator can join one audit line
    /// back to a client log line.
    pub request_id: String,
}

impl Default for SpanFields {
    fn default() -> Self {
        Self {
            component_ref: String::new(),
            digest: String::new(),
            tool: String::new(),
            args_sha256: String::new(),
            session_id: None,
            transport: String::new(),
            outcome: "incomplete".to_string(),
            duration_ms: 0,
            request_id: String::new(),
        }
    }
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

/// Escape control characters to prevent audit-line forgery. Components can inject
/// newlines and ANSI sequences into guest-controlled fields. This sanitizes them
/// uniformly at the rendering point: \n, \r, \t as their literal forms; other
/// control chars as \u{...}. Returns the original string if no escaping needed.
fn escape_audit_field(s: &str) -> Cow<'_, str> {
    if !s.chars().any(|c| c.is_control()) {
        return Cow::Borrowed(s);
    }
    let mut out = String::new();
    for c in s.chars() {
        if c.is_control() {
            match c {
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                _ => out.push_str(&format!("\\u{{{:04x}}}", c as u32)),
            }
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
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
    let component_ref_escaped = escape_audit_field(component_ref);
    let modes: Vec<String> = modes
        .iter()
        .map(|(id, mode)| {
            let id_escaped = escape_audit_field(id);
            let mode_escaped = escape_audit_field(mode);
            format!("{id_escaped}={mode_escaped}")
        })
        .collect();
    format!(
        "{PREFIX}{} {} \u{2502} {}",
        component_ref_escaped,
        short_digest(digest),
        modes.join(" ")
    )
}

/// A second line, printed right after the header, naming capability classes
/// the component declared in `act.toml` that resolved to `deny` anyway (no
/// grant covered them, or an operator explicitly denied them). Restricted to
/// `declared == true` classes by the caller — every class a component never
/// asked for also resolves to deny, and warning on those would bury the one
/// signal an operator actually needs to see.
pub fn render_declared_ungranted_warning(ids: &[String]) -> String {
    let escaped: Vec<String> = ids
        .iter()
        .map(|id| escape_audit_field(id).to_string())
        .collect();
    format!(
        "{PREFIX}\u{26a0} declared but not granted: {}",
        escaped.join(", ")
    )
}

/// A sibling warning for a declared class configured as `ask` when this run
/// has no interactive prompt channel at all (headless / ACT-HTTP). The
/// header still shows the configured mode (`ask`) unchanged — that really is
/// the policy — but every access to a class like this resolves through
/// `DenyPrompter` before a human is ever asked, so the operator needs the
/// outcome spelled out, not just the mode.
pub fn render_declared_ask_blocked_warning(ids: &[String]) -> String {
    let escaped: Vec<String> = ids
        .iter()
        .map(|id| escape_audit_field(id).to_string())
        .collect();
    format!(
        "{PREFIX}\u{26a0} declared ask, no prompt channel — every access will be denied: {}",
        escaped.join(", ")
    )
}

/// A denial or an ask — printed the moment it resolves, never batched. Also
/// reused (from the layer) for an allow that has nowhere to fold, e.g. one
/// fired at instantiation time, before any tool-call span exists.
pub fn render_exception(r: &CapDecisionRecord) -> String {
    let marker = match r.decision {
        Decision4::Deny => "\u{2717}",
        Decision4::Allow => "\u{2713}",
        Decision4::AskAllow | Decision4::AskDeny => "?",
    };
    let action_escaped = escape_audit_field(&r.action);
    let key_escaped = escape_audit_field(&r.key);
    let subject = if r.action.is_empty() {
        key_escaped.to_string()
    } else {
        format!("{} {}", action_escaped, key_escaped)
    };
    let cap_id_escaped = escape_audit_field(&r.cap_id);
    let reason = r
        .reason
        .as_deref()
        .map(|s| {
            let escaped = escape_audit_field(s);
            format!("   {escaped}")
        })
        .unwrap_or_default();
    format!(
        "{PREFIX}{marker} {}  {}  {}{}",
        r.decision, cap_id_escaped, subject, reason
    )
}

/// The per-call summary, flushed when the envelope span closes.
pub fn render_rollup(span: &SpanFields, roll: &Rollup) -> String {
    let tool_escaped = escape_audit_field(&span.tool);
    // Truncate the caller-supplied request id before escaping, same order as
    // the session id below: `take_bytes` yields whole characters, whereas
    // escaping first could cut an escape sequence in half.
    let req_escaped = escape_audit_field(take_bytes(&span.request_id, 6));
    let mut line = format!(
        "{PREFIX}\u{25cf} {}  {} {}  args:{}  req:{}",
        tool_escaped,
        span.outcome,
        humanise_ms(span.duration_ms),
        take_bytes(&span.args_sha256, 6),
        req_escaped,
    );
    if let Some(sid) = &span.session_id {
        let sid_trunc = take_bytes(sid, 8);
        let sid_escaped = escape_audit_field(sid_trunc);
        line.push_str(&format!("  session:{}", sid_escaped));
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
        let short_escaped = escape_audit_field(short);
        let ops: Vec<String> = entries
            .iter()
            .map(|(action, _, n)| {
                let action_escaped = escape_audit_field(action);
                if action.is_empty() {
                    format!("{n}")
                } else {
                    format!("{n} {action_escaped}")
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
            let rules_escaped: Vec<String> = rules
                .iter()
                .map(|r| escape_audit_field(r).to_string())
                .collect();
            format!(" under {}", rules_escaped.join(", "))
        };
        line.push_str(&format!("  {short_escaped}: {}{scope}", ops.join(" ")));
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
            request_id: "req-9f8e7d6c5b4a".into(),
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
        assert!(
            line.contains("req:req-9f"),
            "expected truncated request id, got {line}"
        );
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
        // A session ID where the 8-byte mark happens to be exactly on a char
        // boundary. Emoji 🎉 is 4 bytes, so "🎉🎉" = 8 bytes at a boundary.
        let mut sf = span_fields();
        sf.session_id = Some("🎉🎉🎉".to_string()); // 3 emoji × 4 bytes = 12 bytes
        let roll = Rollup::new(64);

        let line = render_rollup(&sf, &roll);
        // At 8 bytes exactly (boundary), we get 2 complete emoji
        assert!(
            line.contains("session:🎉🎉"),
            "expected 2 emoji at boundary, got {line}"
        );
        // 3rd emoji (would need 12 bytes) should not appear
        assert!(
            !line.contains("🎉🎉🎉"),
            "should not contain 3 emoji, got {line}"
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

    #[test]
    fn render_escapes_newline_in_rule_to_prevent_forgery() {
        // A component declares a filesystem path containing a newline followed
        // by forged audit text. The escaping must prevent the forgery.
        let mut roll = Rollup::new(64);
        roll.add("wasi:filesystem", "read", Some("/data\naudit: forged line"));

        let line = render_rollup(&span_fields(), &roll);
        // Must be exactly one line (no actual newline character)
        assert_eq!(line.matches('\n').count(), 0, "got {line}");
        // Newline must appear escaped as literal \n
        assert!(line.contains("\\n"), "expected escaped newline, got {line}");
        // The rule should render with the escape, preventing a forged second line
        assert!(
            line.contains("\\naudit: forged line"),
            "escaped injection should appear, got {line}"
        );
    }

    #[test]
    fn render_escapes_newline_in_tool_name() {
        let mut sf = span_fields();
        sf.tool = "run\naudit: forged".to_string();
        let roll = Rollup::new(64);

        let line = render_rollup(&sf, &roll);
        assert_eq!(line.matches('\n').count(), 0, "got {line}");
        assert!(line.contains("\\n"), "expected escaped newline, got {line}");
    }

    #[test]
    fn render_escapes_newline_in_resource_key() {
        let r = CapDecisionRecord {
            cap_id: "wasi:http".into(),
            key: "api.example.com:443\naudit: forged".into(),
            action: "GET".into(),
            decision: Decision4::Deny,
            mode: "ask".into(),
            actor: Actor::Static,
            reason: Some("outside ceiling".into()),
            rule: None,
        };
        let line = render_exception(&r);
        assert_eq!(line.matches('\n').count(), 0, "got {line}");
        assert!(line.contains("\\n"), "expected escaped newline, got {line}");
    }

    #[test]
    fn render_escapes_ansi_sequences() {
        // ANSI red color sequence: ESC[31m
        let mut roll = Rollup::new(64);
        roll.add("wasi:http", "GET", Some("api.example.com\u{1b}[31m"));

        let line = render_rollup(&span_fields(), &roll);
        // ESC is a control char, should be escaped as \u{001b}
        assert!(
            line.contains("\\u{001b}"),
            "expected escaped ESC, got {line}"
        );
        // Must not contain the raw ESC (which could affect terminal)
        assert!(
            !line.contains("\u{1b}[31m"),
            "ANSI sequence should not appear raw"
        );
    }

    #[test]
    fn render_escaping_preserves_clean_strings() {
        // A record with no control characters should render byte-identically.
        let r = CapDecisionRecord {
            cap_id: "wasi:filesystem".into(),
            key: "/data/file.txt".into(),
            action: "read".into(),
            decision: Decision4::Allow,
            mode: "allowlist".into(),
            actor: Actor::Static,
            reason: None,
            rule: None,
        };
        // Clean ASCII strings should not allocate or escape
        let line = render_exception(&r);
        assert!(line.contains("wasi:filesystem"), "cap_id should appear");
        assert!(line.contains("/data/file.txt"), "key should appear");
        assert!(line.contains("read"), "action should appear");
        // No backslashes or escape sequences
        assert!(
            !line.contains('\\'),
            "clean strings should not be escaped, got {line}"
        );
    }

    #[test]
    fn render_escapes_newline_in_capability_id() {
        // Gap 1 fix: capability ID in render_rollup was unescaped.
        // A component declares a custom capability class "db\naudit: forged".
        let mut roll = Rollup::new(64);
        roll.add("db\naudit: forged", "drop-database", Some("/data"));

        let line = render_rollup(&span_fields(), &roll);
        // Must be exactly one line (no actual newline character)
        assert_eq!(line.matches('\n').count(), 0, "got {line}");
        // Newline must appear escaped
        assert!(
            line.contains("\\n"),
            "expected escaped newline in cap_id, got {line}"
        );
    }

    #[test]
    fn render_header_escapes_capability_class_id() {
        // Gap 1 fix: capability class id in render_header was unescaped.
        let line = render_header(
            "python-eval@0.16.0",
            "1f3a9c4e5d6b7a8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c",
            &[("db\naudit: forged".to_string(), "allowlist".to_string())],
        );
        // Must be exactly one line
        assert_eq!(line.matches('\n').count(), 0, "got {line}");
        // Newline must appear escaped
        assert!(
            line.contains("\\n"),
            "expected escaped newline in capability class id, got {line}"
        );
    }

    #[test]
    fn render_header_escapes_component_ref() {
        // Gap 2 fix: component_ref in render_header was unescaped.
        let line = render_header(
            "python-eval\naudit: forged@0.16.0",
            "1f3a9c4e5d6b7a8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c",
            &[("wasi:filesystem".to_string(), "allowlist".to_string())],
        );
        // Must be exactly one line
        assert_eq!(line.matches('\n').count(), 0, "got {line}");
        // Newline must appear escaped
        assert!(
            line.contains("\\n"),
            "expected escaped newline in component_ref, got {line}"
        );
    }

    #[test]
    fn render_exception_marks_allow_distinctly_from_ask() {
        // An allow rendered by render_exception (e.g. one with nowhere to
        // fold) must not be marked with "?", which means "a human was
        // asked" — a statically-allowed operation is not that.
        let r = CapDecisionRecord {
            cap_id: "wasi:filesystem".into(),
            key: "/data/x".into(),
            action: "read".into(),
            decision: Decision4::Allow,
            mode: "allowlist".into(),
            actor: Actor::Static,
            reason: None,
            rule: Some("/data/**".into()),
        };
        let line = render_exception(&r);
        assert!(
            !line.starts_with("audit: ? "),
            "allow must not render the ask marker, got {line}"
        );
        assert!(line.contains("allow"), "got {line}");
    }

    #[test]
    fn render_escapes_control_character_in_request_id() {
        // The request id is caller-supplied and outside our control, same as
        // the session id.
        let mut sf = span_fields();
        sf.request_id = "req\naudit: forged".to_string();
        let roll = Rollup::new(64);

        let line = render_rollup(&sf, &roll);
        assert_eq!(line.matches('\n').count(), 0, "got {line}");
        assert!(
            line.contains("\\n"),
            "expected escaped newline in request id, got {line}"
        );
    }
}
