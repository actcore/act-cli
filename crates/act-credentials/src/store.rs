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
    /// False for a mounted read-only secret; OAuth refresh needs this (spec §7.1).
    fn writable(&self) -> bool;
}
