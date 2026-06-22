//! Re-export of the network matcher, now in `act-policy`.
pub use act_policy::net::*;

// Keep a type alias for the old `Decision` name (now `NetVerdict` in act-policy)
// so existing call sites in this crate don't break. New code should import
// `act_policy::net::NetVerdict` directly.
pub use act_policy::net::NetVerdict as Decision;
