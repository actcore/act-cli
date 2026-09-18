//! A registry client over `hclient`, replacing `oci-client`'s network half.
//!
//! **Why this exists.** `oci-client` brought `reqwest`, and with it a second
//! TLS stack: `hyper-rustls` on `aws-lc-rs` beside the `ring` that
//! `hclient-tls-rustls` uses. Two rustls providers in one binary is why an
//! `install_crypto_provider` had to be called before any TLS happened —
//! rustls refuses to guess between them, correctly. Both are gone: `reqwest`,
//! `hyper-rustls` and `aws-lc-rs` are no longer in the dependency graph, and
//! neither is that function.
//!
//! The types stay `oci-spec`'s — this crate already reads and writes them for
//! the local store. What is replaced is the transport and the token dance,
//! which is the part that was pulling a whole second stack in.

pub mod auth;
pub mod client;
pub mod push;
pub mod reference;
