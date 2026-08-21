use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::index::{Index, write_private};
use crate::record::{SecretInfo, SecretRecord};
use crate::store::{CredentialStore, StoreError};

/// Secrets in one JSON file next to the index. This is the only backend: the
/// records are plaintext on disk, protected by filesystem permissions alone,
/// and it is always selected explicitly (design §7.4).
pub struct FileStore {
    root: PathBuf,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Secrets {
    /// component -> key -> record
    entries: BTreeMap<String, BTreeMap<String, SecretRecord>>,
}

/// The file holding the plaintext records, given the store root.
///
/// Public because `act secret`'s first-write disclosure names it: an operator
/// told that permissions are the only protection needs to know which file to
/// chmod, back up, or keep out of a sync client. One definition, so the notice
/// cannot name a file the store does not use.
pub fn secrets_path(root: &Path) -> PathBuf {
    root.join("secrets.json")
}

impl FileStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn secrets_path(&self) -> PathBuf {
        secrets_path(&self.root)
    }

    fn load(&self) -> Result<Secrets, StoreError> {
        let p = self.secrets_path();
        if !p.exists() {
            return Ok(Secrets::default());
        }
        let text = std::fs::read_to_string(p)?;
        serde_json::from_str(&text).map_err(|e| StoreError::Encoding(e.to_string()))
    }

    fn save(&self, s: &Secrets) -> Result<(), StoreError> {
        let text =
            serde_json::to_string_pretty(s).map_err(|e| StoreError::Encoding(e.to_string()))?;
        write_private(&self.secrets_path(), text.as_bytes())
    }
}

impl CredentialStore for FileStore {
    fn get(&self, component: &str, key: &str) -> Result<Option<SecretRecord>, StoreError> {
        Ok(self
            .load()?
            .entries
            .get(component)
            .and_then(|m| m.get(key))
            .cloned())
    }

    fn put(&self, component: &str, key: &str, rec: &SecretRecord) -> Result<(), StoreError> {
        let mut s = self.load()?;
        s.entries
            .entry(component.to_string())
            .or_default()
            .insert(key.to_string(), rec.clone());
        self.save(&s)?;

        let mut idx = Index::load(&self.root)?;
        idx.upsert(component, rec.info(key));
        idx.save(&self.root)
    }

    fn erase(&self, component: &str, key: &str) -> Result<(), StoreError> {
        let mut s = self.load()?;
        if let Some(m) = s.entries.get_mut(component) {
            m.remove(key);
            if m.is_empty() {
                s.entries.remove(component);
            }
        }
        self.save(&s)?;

        let mut idx = Index::load(&self.root)?;
        idx.remove(component, key);
        idx.save(&self.root)
    }

    fn list(&self, component: Option<&str>) -> Result<Vec<SecretInfo>, StoreError> {
        Ok(Index::load(&self.root)?.list(component))
    }

    fn components(&self) -> Result<Vec<String>, StoreError> {
        Ok(Index::load(&self.root)?.entries.into_keys().collect())
    }
}
