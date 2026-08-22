//! Capability policy decision core (PDP) for ACT hosts.
//!
//! Pure, synchronous, wasm-portable: `resolve` computes the effective
//! ceiling once per instantiation; the matchers classify each operation.
//! Host-only async consent helpers live behind the `host` feature.

pub mod ceilings;
pub mod decision;
pub mod effective;
pub mod fs_matcher;
pub mod grant;
pub mod net;
pub mod provider;
pub mod providers;

#[cfg(feature = "host")]
pub mod consent;

/// The common policy decision type, returned by every provider's `classify`.
pub use decision::Decision;
