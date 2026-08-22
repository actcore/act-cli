//! Interactive consent: prompt-on-access for `ask`-mode capabilities,
//! with a per-session decision cache and fail-safe (no channel = deny).
//!
//! Portable types: `ConsentAsk`, `ConsentPrompter`, `DenyPrompter`,
//! `DecisionCache`. The TTY-backed prompter lives in act-cli's
//! `runtime::consent` module (host-only, uses tokio I/O).

use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct ConsentAsk {
    pub cap_id: String,
    /// Cache key within the class (e.g. a path, host:port, or socket addr).
    pub key: String,
    pub summary: String,
}

#[async_trait::async_trait]
pub trait ConsentPrompter: Send + Sync {
    async fn decide(&self, ask: &ConsentAsk) -> bool;

    /// Whether this prompter can actually reach a human at all. `true` for
    /// every interactive prompter (a real TTY, an MCP client offering
    /// elicitation); `false` only for [`DenyPrompter`], which resolves every
    /// `ask` to deny with nobody consulted.
    ///
    /// Read at the point an `ask` resolves, so the audit trail can tell "a
    /// human answered no" apart from "there was no one to ask" — §5's
    /// degrade-to-deny is not the same event as a real refusal, and callers
    /// must not attribute the latter's `actor`/`reason` to the former. See
    /// `CapDecisionRecord::answered`.
    fn has_channel(&self) -> bool {
        true
    }
}

/// No prompt channel (headless / --mcp / non-TTY): every ask denies (fail-safe).
pub struct DenyPrompter;

#[async_trait::async_trait]
impl ConsentPrompter for DenyPrompter {
    async fn decide(&self, _ask: &ConsentAsk) -> bool {
        false
    }

    fn has_channel(&self) -> bool {
        false
    }
}

/// Per-session memory of granted/denied (cap_id, key) decisions.
#[derive(Default)]
pub struct DecisionCache {
    seen: Mutex<HashMap<(String, String), bool>>,
}

impl DecisionCache {
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Return the remembered decision for `(cap_id, key)`, or prompt once via
    /// `prompter`, store, and return it.
    pub async fn decide_cached(&self, prompter: &dyn ConsentPrompter, ask: ConsentAsk) -> bool {
        let k = (ask.cap_id.clone(), ask.key.clone());
        if let Some(v) = self.seen.lock().unwrap().get(&k).copied() {
            return v;
        }
        let v = prompter.decide(&ask).await;
        self.seen.lock().unwrap().insert(k, v);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingPrompter {
        allow: bool,
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ConsentPrompter for CountingPrompter {
        async fn decide(&self, _ask: &ConsentAsk) -> bool {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.allow
        }
    }

    fn ask(key: &str) -> ConsentAsk {
        ConsentAsk {
            cap_id: "wasi:filesystem".into(),
            key: key.into(),
            summary: "read".into(),
        }
    }

    #[tokio::test]
    async fn cache_remembers_and_prompts_once() {
        let cache = DecisionCache::new();
        let p = CountingPrompter {
            allow: true,
            calls: AtomicUsize::new(0),
        };
        assert!(cache.decide_cached(&p, ask("/a")).await);
        assert!(cache.decide_cached(&p, ask("/a")).await); // cached, no second prompt
        assert_eq!(p.calls.load(Ordering::SeqCst), 1);
        assert!(cache.decide_cached(&p, ask("/b")).await); // different key → prompts
        assert_eq!(p.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn deny_prompter_denies() {
        let cache = DecisionCache::new();
        assert!(!cache.decide_cached(&DenyPrompter, ask("/x")).await);
    }

    /// Prompter scripted per cache-key: returns the configured verdict for the
    /// key and records every prompt (post-cache misses only).
    struct ScriptedPrompter {
        decisions: HashMap<String, bool>,
        prompts: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl ConsentPrompter for ScriptedPrompter {
        async fn decide(&self, ask: &ConsentAsk) -> bool {
            self.prompts.lock().unwrap().push(ask.key.clone());
            self.decisions.get(&ask.key).copied().unwrap_or(false)
        }
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn ask_allow_remembered_deny_blocked_and_degrade() {
        // Scripted: "/allow" → allow, "/deny" → deny.
        let p = ScriptedPrompter {
            decisions: HashMap::from([("/allow".to_string(), true), ("/deny".to_string(), false)]),
            prompts: Mutex::new(Vec::new()),
        };
        let cache = DecisionCache::new();

        // First access to an allowed key prompts and is allowed.
        assert!(cache.decide_cached(&p, ask("/allow")).await);
        // Repeat is served from cache — no second prompt.
        assert!(cache.decide_cached(&p, ask("/allow")).await);
        // A denied key is blocked.
        assert!(!cache.decide_cached(&p, ask("/deny")).await);
        // Repeat denied key is also cached (no re-prompt).
        assert!(!cache.decide_cached(&p, ask("/deny")).await);

        // Exactly one prompt per distinct key: ["/allow", "/deny"].
        let prompts = p.prompts.lock().unwrap();
        assert_eq!(
            prompts.as_slice(),
            &["/allow".to_string(), "/deny".to_string()]
        );

        // DenyPrompter degrades any ask → deny (fail-safe, no channel).
        let deny_cache = DecisionCache::new();
        assert!(!deny_cache.decide_cached(&DenyPrompter, ask("/allow")).await);
    }
}
