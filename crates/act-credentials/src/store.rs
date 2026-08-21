use crate::record::{SecretInfo, SecretRecord};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("credential store io: {0}")]
    Io(#[from] std::io::Error),
    #[error("credential store encoding: {0}")]
    Encoding(String),
    #[error("credential store is read-only; {0}")]
    ReadOnly(String),
    #[error("credential store unavailable: {0}")]
    Unavailable(String),
}

/// Keys are `(component, key)`. `component` is the resolved reference the
/// operator used, which is what makes the profile a per-component namespace.
pub trait CredentialStore: Send + Sync {
    fn get(&self, component: &str, key: &str) -> Result<Option<SecretRecord>, StoreError>;
    fn put(&self, component: &str, key: &str, rec: &SecretRecord) -> Result<(), StoreError>;
    fn erase(&self, component: &str, key: &str) -> Result<(), StoreError>;
    /// Metadata only, never values. `None` lists every component.
    fn list(&self, component: Option<&str>) -> Result<Vec<SecretInfo>, StoreError>;
    /// The components holding at least one credential.
    ///
    /// `list(None)` flattens the profile away, which is the one thing a
    /// listing across components must not lose: profile keys are normalised
    /// (`act-cli`'s `resolve::profile_key`), so this is also how an operator
    /// sees which key a `set` actually landed under. Component names, like
    /// `SecretInfo`, cannot carry a value.
    fn components(&self) -> Result<Vec<String>, StoreError>;
}

// There is deliberately no `writable()`. It existed for the read-only reference
// backends of design §7.1, which are an open question rather than a feature, and
// nothing consulted it: `put` and `erase` never asked, so a backend answering
// `false` would have been written to anyway. A trait method that every
// implementor must write, that no caller reads, and that reads as a promise the
// crate does not keep is worse than its absence. It comes back with the first
// backend that can answer `false` — and with the check that honours it.
