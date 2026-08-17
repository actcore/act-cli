use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::record::SecretInfo;
use crate::store::StoreError;

/// Non-secret companion to a store that cannot enumerate itself.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Index {
    pub version: u32,
    /// component -> key -> info
    pub entries: BTreeMap<String, BTreeMap<String, SecretInfo>>,
}

impl Index {
    pub fn path(root: &Path) -> PathBuf {
        root.join("index.json")
    }

    pub fn load(root: &Path) -> Result<Self, StoreError> {
        let p = Self::path(root);
        if !p.exists() {
            return Ok(Self {
                version: 1,
                entries: BTreeMap::new(),
            });
        }
        let text = std::fs::read_to_string(p)?;
        serde_json::from_str(&text).map_err(|e| StoreError::Encoding(e.to_string()))
    }

    pub fn save(&self, root: &Path) -> Result<(), StoreError> {
        std::fs::create_dir_all(root)?;
        let text =
            serde_json::to_string_pretty(self).map_err(|e| StoreError::Encoding(e.to_string()))?;
        write_private(&Self::path(root), text.as_bytes())
    }

    pub fn upsert(&mut self, component: &str, info: SecretInfo) {
        self.entries
            .entry(component.to_string())
            .or_default()
            .insert(info.key.clone(), info);
    }

    pub fn remove(&mut self, component: &str, key: &str) {
        if let Some(m) = self.entries.get_mut(component) {
            m.remove(key);
            if m.is_empty() {
                self.entries.remove(component);
            }
        }
    }

    pub fn list(&self, component: Option<&str>) -> Vec<SecretInfo> {
        match component {
            Some(c) => self
                .entries
                .get(c)
                .map(|m| m.values().cloned().collect())
                .unwrap_or_default(),
            None => self
                .entries
                .values()
                .flat_map(|m| m.values().cloned())
                .collect(),
        }
    }
}

/// Atomic write with restrictive permissions: temp file then rename.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}
