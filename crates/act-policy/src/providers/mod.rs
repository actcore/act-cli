//! Built-in capability providers (factories) for the ACT policy framework.
//!
//! Each provider wraps Stage 1 matchers and implements `CapabilityProvider`.
//! `ProviderRegistry::with_builtins()` (in `provider.rs`) registers these.

pub mod credentials;
pub mod fs;
pub mod generic;
pub mod http;
pub mod sockets;
