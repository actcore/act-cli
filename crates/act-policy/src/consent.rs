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

/// Per-session memory of granted/denied (`cap_id`, key) decisions.
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

// ── A queue a human drains out of band ──────────────────────────────────────

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A consent question waiting for an answer.
///
/// The caller — a tool call that touched an `ask`-mode capability — is blocked
/// until someone resolves this or it expires.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingConsent {
    pub id: u64,
    /// What is asking, named the way the host names its subjects: a component
    /// label in the toolserver, a reference on the command line.
    pub subject: String,
    /// The host's own identifier for that subject, carried through untouched.
    /// The queue never interprets it; it exists so an answer can be attributed
    /// to something more durable than a display name — a toolset membership,
    /// say — when the host wants to remember it.
    pub subject_id: i64,
    pub cap_id: String,
    /// The specific thing within the capability — a path, a host, an address.
    pub key: String,
    pub summary: String,
    /// Unix epoch seconds.
    pub asked_at: i64,
}

struct Waiting {
    entry: PendingConsent,
    answer: tokio::sync::oneshot::Sender<bool>,
}

/// Consent questions that are waiting for a person.
///
/// This is the portable half of an out-of-band consent surface: it holds the
/// questions and wakes their callers. How a person *reaches* it belongs to the
/// host — an HTTP endpoint and a window in the toolserver, a second terminal
/// for a CLI. Nothing here knows about either.
pub struct ConsentQueue {
    next_id: AtomicU64,
    waiting: Mutex<HashMap<u64, Waiting>>,
    timeout: Duration,
    /// A revision counter, bumped whenever the set of waiting questions
    /// changes. See [`Self::changes`].
    revision: tokio::sync::watch::Sender<u64>,
}

impl ConsentQueue {
    pub fn new(timeout: Duration) -> Self {
        Self {
            next_id: AtomicU64::new(0),
            waiting: Mutex::new(HashMap::new()),
            timeout,
            revision: tokio::sync::watch::Sender::new(0),
        }
    }

    /// Hear about every change to [`Self::pending`]: a question asked, one
    /// answered, one expired.
    ///
    /// A revision counter rather than the questions themselves, on purpose.
    /// A `watch` keeps only the latest value, so a listener that falls behind
    /// catches up in one wake instead of replaying a backlog, and it re-reads
    /// `pending` for the truth — which is also what a listener that subscribed
    /// late has to do anyway. Answers given elsewhere count: a window must
    /// stop offering a question the command line already answered.
    pub fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.revision.subscribe()
    }

    fn changed(&self) {
        self.revision.send_modify(|r| *r += 1);
    }

    /// Questions waiting right now, oldest first.
    pub fn pending(&self) -> Vec<PendingConsent> {
        let mut all: Vec<PendingConsent> = self.lock().values().map(|w| w.entry.clone()).collect();
        all.sort_by_key(|e| e.id);
        all
    }

    /// Answer a question, waking whoever asked it.
    ///
    /// Returns the question that was answered, so a host that wants to
    /// remember the decision has what it needs without a second lookup — and
    /// without a window in which the entry could expire between the two.
    /// `None` when nothing was waiting: it was answered already, or it expired.
    pub fn resolve(&self, id: u64, allow: bool) -> Option<PendingConsent> {
        let waiting = self.lock().remove(&id)?;
        self.changed();
        // The receiver is gone if the caller stopped waiting; the decision is
        // then moot rather than an error.
        let _ = waiting.answer.send(allow);
        Some(waiting.entry)
    }

    /// Ask, and wait for an answer or for the deadline.
    ///
    /// Expiry denies. A tool call cannot hang forever waiting for someone who
    /// may have walked away, and the safe direction when nobody answered is
    /// the same as when they said no — with the difference visible to the
    /// caller, which is why this is separate from `DenyPrompter`.
    pub async fn ask(&self, subject: &str, subject_id: i64, ask: &ConsentAsk) -> bool {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = tokio::sync::oneshot::channel();

        self.lock().insert(
            id,
            Waiting {
                entry: PendingConsent {
                    id,
                    subject: subject.to_string(),
                    subject_id,
                    cap_id: ask.cap_id.clone(),
                    key: ask.key.clone(),
                    summary: ask.summary.clone(),
                    asked_at: now_epoch(),
                },
                answer: tx,
            },
        );
        self.changed();

        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(decision)) => decision,
            // Timed out, or the sender was dropped with the queue.
            _ => {
                // Only a change if it was still there: an answer that landed
                // at the deadline already took it out, and announced that.
                if self.lock().remove(&id).is_some() {
                    self.changed();
                }
                false
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Waiting>> {
        self.waiting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// A prompter that parks its question in a [`ConsentQueue`].
///
/// `subject` is what the host calls whatever is asking; it is the first thing
/// a person reads when deciding, so "allow `wasi:filesystem` on `/data`" does
/// not arrive without saying who wants it.
pub struct QueuePrompter {
    queue: Arc<ConsentQueue>,
    subject: String,
    subject_id: i64,
}

impl QueuePrompter {
    pub fn new(queue: Arc<ConsentQueue>, subject: impl Into<String>, subject_id: i64) -> Self {
        Self {
            queue,
            subject: subject.into(),
            subject_id,
        }
    }
}

#[async_trait::async_trait]
impl ConsentPrompter for QueuePrompter {
    async fn decide(&self, ask: &ConsentAsk) -> bool {
        self.queue.ask(&self.subject, self.subject_id, ask).await
    }

    /// There is a channel: someone may be looking at the queue. Whether they
    /// answer in time is a different question, and expiry is reported as a
    /// refusal rather than as "nobody was there".
    fn has_channel(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod queue_tests {
    use super::*;

    fn ask(key: &str) -> ConsentAsk {
        ConsentAsk {
            cap_id: "wasi:filesystem".into(),
            key: key.into(),
            summary: format!("read {key}"),
        }
    }

    fn queue() -> Arc<ConsentQueue> {
        Arc::new(ConsentQueue::new(Duration::from_secs(5)))
    }

    #[tokio::test]
    async fn a_question_waits_and_names_who_is_asking() {
        let queue = queue();
        let asking = tokio::spawn({
            let queue = queue.clone();
            async move { queue.ask("clock", 1, &ask("/data")).await }
        });

        let pending = wait_for_one(&queue).await;
        assert_eq!(pending.subject, "clock");
        assert_eq!(pending.cap_id, "wasi:filesystem");
        assert_eq!(pending.key, "/data");
        assert!(pending.asked_at > 1_577_836_800);

        assert!(queue.resolve(pending.id, true).is_some());
        assert!(asking.await.unwrap(), "allowing must wake the caller");
        assert!(queue.pending().is_empty());
    }

    #[tokio::test]
    async fn denying_wakes_the_caller_with_a_refusal() {
        let queue = queue();
        let asking = tokio::spawn({
            let queue = queue.clone();
            async move { queue.ask("clock", 1, &ask("/etc")).await }
        });

        let pending = wait_for_one(&queue).await;
        queue.resolve(pending.id, false);

        assert!(!asking.await.unwrap());
    }

    #[tokio::test]
    async fn answering_a_question_nobody_asked_reports_it() {
        let queue = queue();
        assert!(queue.resolve(999, true).is_none());
    }

    #[tokio::test]
    async fn a_question_cannot_be_answered_twice() {
        let queue = queue();
        let asking = tokio::spawn({
            let queue = queue.clone();
            async move { queue.ask("clock", 1, &ask("/data")).await }
        });
        let pending = wait_for_one(&queue).await;

        assert!(queue.resolve(pending.id, true).is_some());
        assert!(
            queue.resolve(pending.id, false).is_none(),
            "it is no longer waiting"
        );
        assert!(asking.await.unwrap());
    }

    /// Nobody is coming: the call must not hang for the life of the process.
    #[tokio::test]
    async fn an_unanswered_question_expires_into_a_refusal() {
        let queue = Arc::new(ConsentQueue::new(Duration::from_millis(50)));

        let decision = queue.ask("clock", 1, &ask("/data")).await;

        assert!(!decision, "expiry denies");
        assert!(queue.pending().is_empty(), "and stops waiting");
    }

    #[tokio::test]
    async fn two_questions_are_answered_independently() {
        let queue = queue();
        let first = tokio::spawn({
            let queue = queue.clone();
            async move { queue.ask("clock", 1, &ask("/a")).await }
        });
        let second = tokio::spawn({
            let queue = queue.clone();
            async move { queue.ask("db", 2, &ask("/b")).await }
        });

        let mut pending = Vec::new();
        while pending.len() < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            pending = queue.pending();
        }
        assert_ne!(pending[0].id, pending[1].id);

        let by_key = |k: &str| pending.iter().find(|p| p.key == k).unwrap().id;
        queue.resolve(by_key("/a"), true);
        queue.resolve(by_key("/b"), false);

        assert!(first.await.unwrap());
        assert!(!second.await.unwrap());
    }

    #[tokio::test]
    async fn the_prompter_reports_that_a_human_can_be_reached() {
        let prompter = QueuePrompter::new(queue(), "clock", 1);
        assert!(prompter.has_channel());
    }

    /// A window showing the queue must hear about every way it changes, not
    /// only about new questions: an answer given elsewhere (the command line)
    /// and an expiry both take a question away, and a window that missed
    /// either would keep offering an answer nobody is waiting for.
    #[tokio::test]
    async fn asking_answering_and_expiring_each_announce_a_change() {
        let queue = Arc::new(ConsentQueue::new(Duration::from_millis(80)));
        let mut changes = queue.changes();
        let seen = *changes.borrow_and_update();

        let asking = tokio::spawn({
            let queue = queue.clone();
            async move { queue.ask("clock", 1, &ask("/data")).await }
        });
        tokio::time::timeout(Duration::from_secs(1), changes.changed())
            .await
            .expect("a new question is announced")
            .unwrap();
        let after_ask = *changes.borrow_and_update();
        assert!(after_ask > seen);

        let pending = wait_for_one(&queue).await;
        queue.resolve(pending.id, true);
        tokio::time::timeout(Duration::from_secs(1), changes.changed())
            .await
            .expect("an answer is announced")
            .unwrap();
        assert!(asking.await.unwrap());

        // Nobody answers this one; its expiry must be announced too.
        let expired = queue.ask("clock", 1, &ask("/etc")).await;
        assert!(!expired);
        changes.borrow_and_update();
        assert!(queue.pending().is_empty());
        assert!(
            *queue.changes().borrow() >= after_ask + 3,
            "ask, answer, ask and expiry are four changes"
        );
    }

    /// Answering something that was not waiting changes nothing, so it must
    /// not wake a window into re-reading a queue that is exactly as it was.
    #[tokio::test]
    async fn a_miss_is_not_a_change() {
        let queue = queue();
        let before = *queue.changes().borrow();
        assert!(queue.resolve(42, true).is_none());
        assert_eq!(*queue.changes().borrow(), before);
    }

    async fn wait_for_one(queue: &ConsentQueue) -> PendingConsent {
        for _ in 0..200 {
            if let Some(entry) = queue.pending().into_iter().next() {
                return entry;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("the question never reached the queue");
    }
}
