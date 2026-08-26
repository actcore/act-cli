//! When a stored credential value is too close to expiry to be served.
//!
//! Here rather than beside the OAuth flow because it is a property of the
//! **stored shape** — a `std:oauth2` value and its `std:expires-at` member
//! (`ACT-CONSTANTS.md` §8.3) — not of the protocol that produced it. The host
//! runtime has to make this decision on every `get-secret` and holds no opinion
//! about OAuth; the crate that renews it lives further out.

use serde_json::Value;

/// How close to expiry is close enough to renew.
///
/// Sixty seconds covers the round trip to the upstream plus the clock skew
/// between this host and the authorization server, which is the pair that
/// decides whether a token still valid when we checked is still valid when it
/// arrives. Shorter risks handing over a credential that expires in flight;
/// much longer spends refreshes on tokens that had plenty of life.
pub const SKEW_SECS: u64 = 60;

/// Whether a `std:oauth2` field's value should be renewed before it is served.
///
/// A value with no `std:expires-at` is **not** renewed. ACT-CONSTANTS §8.3 has
/// a consumer read a missing expiry as "no known expiry", and a host that
/// treated absence as "expired" would refresh on every single call — burning a
/// rotation each time against servers that rotate.
pub fn needs_refresh(value: &Value, now: u64) -> bool {
    match value.get("std:expires-at").and_then(Value::as_u64) {
        Some(expires_at) => expires_at.saturating_sub(SKEW_SECS) <= now,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_value_without_an_expiry_is_never_refreshed() {
        // §8.3 reads a missing expiry as "no known expiry". Treating it as
        // expired would refresh on every call, burning a rotation each time.
        assert!(!needs_refresh(&json!({"std:access-token": "at"}), 1_000));
    }

    #[test]
    fn expiry_is_compared_with_the_skew_that_covers_the_round_trip() {
        let v = json!({"std:access-token": "at", "std:expires-at": 1_000u64});
        assert!(!needs_refresh(&v, 1_000 - SKEW_SECS - 1), "plenty of life");
        assert!(
            needs_refresh(&v, 1_000 - SKEW_SECS),
            "inside the skew is close enough: a token still valid when checked \
             must still be valid when it arrives"
        );
        assert!(needs_refresh(&v, 1_000), "at the boundary");
        assert!(needs_refresh(&v, 2_000), "long past");
    }

    #[test]
    fn an_expiry_below_the_skew_does_not_wrap_into_the_future() {
        // `expires_at - SKEW` on a small timestamp underflows to a huge number
        // in release mode, which would read as "not due for centuries" — the
        // one arithmetic mistake here that fails open.
        let v = json!({"std:access-token": "at", "std:expires-at": 5u64});
        assert!(needs_refresh(&v, 10), "an expiry in 1970 is long past");
    }

    #[test]
    fn a_mistyped_expiry_is_not_an_expiry() {
        // §8.3 requires a whole number of seconds and has a consumer treat
        // anything else as absent. A float here must not be coerced into a
        // refresh decision.
        for bad in [json!(1.5), json!("1000"), json!(null)] {
            let v = json!({"std:access-token": "at", "std:expires-at": bad});
            assert!(!needs_refresh(&v, 10_000), "{bad} is not an expiry");
        }
    }
}
