//! Capability policy decision core (PDP) for ACT hosts.
//!
//! Pure, synchronous, wasm-portable: `resolve` computes the effective
//! ceiling once per instantiation; the matchers classify each operation.
//! Host-only async consent helpers live behind the `host` feature.

pub mod effective;
pub mod fs_matcher;
pub mod grant;
pub mod net;

#[cfg(feature = "host")]
pub mod consent;

/// Canonical filesystem-access decision type (re-exported from `fs_matcher`).
pub use fs_matcher::Decision;
