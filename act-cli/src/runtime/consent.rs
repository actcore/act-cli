//! Interactive consent: prompt-on-access for `ask`-mode capabilities,
//! with a per-session decision cache and fail-safe (no channel = deny).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentRisk {
    // `Low` / `Destructive` are the risk taxonomy consumed by the prompter's
    // rendering (`TtyPrompter` already flags `Destructive` in the prompt
    // string). The three current decision points all classify as `Normal`;
    // destructive-op classification (unlink / rmdir / rename → `Destructive`)
    // is a later phase, so these two are constructed by no caller yet.
    #[allow(dead_code)]
    Low,
    Normal,
    #[allow(dead_code)]
    Destructive,
}

#[derive(Debug, Clone)]
pub struct ConsentAsk {
    pub cap_id: String,
    /// Cache key within the class (e.g. a path, host:port, or socket addr).
    pub key: String,
    pub summary: String,
    pub risk: ConsentRisk,
}

pub trait ConsentPrompter: Send + Sync {
    fn decide<'a>(&'a self, ask: &'a ConsentAsk)
    -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
}

/// No prompt channel (headless / --mcp / non-TTY): every ask denies (fail-safe).
pub struct DenyPrompter;

impl ConsentPrompter for DenyPrompter {
    fn decide<'a>(
        &'a self,
        _ask: &'a ConsentAsk,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async { false })
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

/// Prompts on the controlling terminal. Reads a line from stdin; `y`/`yes`
/// (case-insensitive) allows, anything else (incl. EOF) denies.
pub struct TtyPrompter;

impl ConsentPrompter for TtyPrompter {
    fn decide<'a>(
        &'a self,
        ask: &'a ConsentAsk,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let mut stderr = tokio::io::stderr();
            let risk = match ask.risk {
                ConsentRisk::Destructive => " [DESTRUCTIVE]",
                _ => "",
            };
            let prompt = format!(
                "\nACT consent{risk}: {} — {} ({})\nAllow? [y/N] ",
                ask.cap_id, ask.summary, ask.key
            );
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
        })
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

    impl ConsentPrompter for CountingPrompter {
        fn decide<'a>(
            &'a self,
            _ask: &'a ConsentAsk,
        ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let allow = self.allow;
            Box::pin(async move { allow })
        }
    }

    fn ask(key: &str) -> ConsentAsk {
        ConsentAsk {
            cap_id: "wasi:filesystem".into(),
            key: key.into(),
            summary: "read".into(),
            risk: ConsentRisk::Normal,
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

    impl ConsentPrompter for ScriptedPrompter {
        fn decide<'a>(
            &'a self,
            ask: &'a ConsentAsk,
        ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
            self.prompts.lock().unwrap().push(ask.key.clone());
            let verdict = self.decisions.get(&ask.key).copied().unwrap_or(false);
            Box::pin(async move { verdict })
        }
    }

    #[tokio::test]
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
