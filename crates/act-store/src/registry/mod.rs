//! A registry client over `hclient`, replacing `oci-client`'s network half.
//!
//! **Why this exists.** `oci-client` brings `reqwest`, which brings a second
//! TLS stack: `hyper-rustls` with `aws-lc-rs` beside the `ring` that
//! `hclient-tls-rustls` uses. Two rustls providers in one binary is why
//! `install_crypto_provider` has to exist at all, and it is most of the
//! duplicated HTTP machinery in the shipped `act`.
//!
//! The types stay `oci-spec`'s — this crate already reads and writes them for
//! the local store. What is replaced is the transport and the token dance,
//! which is the part that was pulling a whole second stack in.

pub mod auth;
pub mod client;
