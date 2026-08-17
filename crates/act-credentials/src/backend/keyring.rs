use std::path::PathBuf;

use crate::index::Index;
use crate::record::{SecretInfo, SecretRecord};
use crate::store::{CredentialStore, StoreError};

const SERVICE: &str = "dev.actcore.act";

/// Secrets in the OS keyring; metadata in the index file beside it, because a
/// keyring cannot be enumerated.
pub struct KeyringStore {
    root: PathBuf,
}

impl KeyringStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn entry(component: &str, key: &str) -> Result<keyring::Entry, StoreError> {
        keyring::Entry::new(SERVICE, &format!("{component}#{key}"))
            .map_err(|e| StoreError::Unavailable(e.to_string()))
    }

    /// Probe used by backend selection.
    pub fn available() -> bool {
        if std::env::var_os("ACT_CREDENTIALS_FORCE_NO_KEYRING").is_some() {
            return false;
        }
        match keyring::Entry::new(SERVICE, "__probe__") {
            Ok(e) => !matches!(e.get_password(), Err(keyring::Error::PlatformFailure(_))),
            Err(_) => false,
        }
    }
}

impl CredentialStore for KeyringStore {
    fn get(&self, component: &str, key: &str) -> Result<Option<SecretRecord>, StoreError> {
        match Self::entry(component, key)?.get_password() {
            Ok(json) => serde_json::from_str(&json)
                .map(Some)
                .map_err(|e| StoreError::Encoding(e.to_string())),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(StoreError::Unavailable(e.to_string())),
        }
    }

    fn put(&self, component: &str, key: &str, rec: &SecretRecord) -> Result<(), StoreError> {
        let json = serde_json::to_string(rec).map_err(|e| StoreError::Encoding(e.to_string()))?;
        Self::entry(component, key)?
            .set_password(&json)
            .map_err(|e| StoreError::Unavailable(e.to_string()))?;
        let mut idx = Index::load(&self.root)?;
        idx.upsert(component, rec.info(key));
        idx.save(&self.root)
    }

    fn erase(&self, component: &str, key: &str) -> Result<(), StoreError> {
        match Self::entry(component, key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(e) => return Err(StoreError::Unavailable(e.to_string())),
        }
        let mut idx = Index::load(&self.root)?;
        idx.remove(component, key);
        idx.save(&self.root)
    }

    fn list(&self, component: Option<&str>) -> Result<Vec<SecretInfo>, StoreError> {
        Ok(Index::load(&self.root)?.list(component))
    }

    fn writable(&self) -> bool {
        true
    }
}
