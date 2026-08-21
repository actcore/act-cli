//! `state` — the unguessable value that binds a callback to the authorization
//! request this host made.
//!
//! An earlier draft also gave each flow an unguessable callback **path**. It is
//! gone, and not for simplicity: RFC 8252 §7.3 has authorization servers match
//! a registered loopback redirect while ignoring only the **port**, so a path
//! that changed per run would fail against a conformant server, or force a new
//! client registration every login. The binding `state` provides is the one the
//! protocol is built on, and the listener still refuses anything whose `Host`
//! is not the address it bound.

use anyhow::Result;
use std::time::{Duration, Instant};

use super::{b64url, random_bytes};

/// How long a pending authorization may sit unanswered.
///
/// A flow that is never completed holds a loopback socket and a verifier. Ten
/// minutes is long enough for a user to find their password manager, log in and
/// approve, and short enough that an abandoned `act login` does not leave a
/// listener up for the rest of the session.
pub const PENDING_TTL: Duration = Duration::from_secs(600);

/// The unguessable half of one pending authorization.
#[derive(Debug)]
pub struct Pending {
    state: String,
    started: Instant,
}

impl Pending {
    pub fn generate() -> Result<Self> {
        Ok(Self {
            state: b64url(&random_bytes::<32>()?),
            started: Instant::now(),
        })
    }

    pub fn state(&self) -> &str {
        &self.state
    }

    pub fn expired(&self) -> bool {
        self.started.elapsed() > PENDING_TTL
    }

    /// Constant-time comparison of the returned `state`.
    ///
    /// A byte-by-byte early return leaks how much of a guess was right, which
    /// over enough attempts is how a `state` gets recovered. The listener
    /// answers every callback the same way regardless, but that only holds if
    /// the comparison itself does not time-differentiate.
    pub fn state_matches(&self, returned: &str) -> bool {
        constant_time_eq(self.state.as_bytes(), returned.as_bytes())
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_pendings_share_nothing() {
        let a = Pending::generate().unwrap();
        let b = Pending::generate().unwrap();
        assert_ne!(a.state(), b.state());
    }

    #[test]
    fn the_state_is_url_safe() {
        // It travels in a query string the authorization server echoes back;
        // anything needing escaping would not survive the round trip intact.
        let p = Pending::generate().unwrap();
        assert!(
            p.state()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "{}",
            p.state()
        );
    }

    #[test]
    fn state_matching_rejects_a_wrong_or_truncated_value() {
        let p = Pending::generate().unwrap();
        assert!(p.state_matches(p.state()));
        assert!(!p.state_matches(""));
        assert!(
            !p.state_matches(&p.state()[..10]),
            "a prefix is not a match"
        );
        let mut wrong = p.state().to_string();
        wrong.pop();
        wrong.push('!');
        assert!(!p.state_matches(&wrong), "one byte differing is a mismatch");
    }

    #[test]
    fn constant_time_eq_agrees_with_equality() {
        // The property that matters is that it is *correct*; its timing is not
        // observable from a test. Pinning correctness is what stops a rewrite
        // of the fold from silently accepting everything.
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }
}
