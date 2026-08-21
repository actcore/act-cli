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
        create_dir_private(root)?;
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

/// `create_dir_all`, then narrow the leaf directory to `0700` on unix.
///
/// The records are 0600, so the *contents* are safe at any directory mode —
/// but write permission on the directory is enough for a co-group user to
/// `rename` their own `secrets.json` over the real one and feed a chosen
/// credential to every component that reads this store. That is credential
/// substitution against exactly the threat [`write_private`]'s `create_new`
/// guard was written to close. The default root under `dirs::data_dir()`
/// inherits the home directory's own protection; an explicit
/// `--credentials-backend file:/srv/shared/store` inherits nothing.
///
/// Applied on every write rather than only on creation, so a store laid down
/// by an earlier build heals instead of staying loose forever. A directory
/// widened on purpose for sharing is the attack above, not a use case this
/// backend supports.
pub fn create_dir_private(dir: &Path) -> Result<(), StoreError> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Atomic write with restrictive permissions: temp file then rename.
///
/// The mode is set **as the file is created**, not chmodded afterwards.
/// Writing at the ambient umask and tightening after leaves a window in which
/// the plaintext temp file is world-readable — and `act secret` prints
/// filesystem permissions as the store's only protection, so that window is a
/// broken promise rather than a small imprecision. `rename` carries the mode
/// with the inode, so the destination is never briefly loose either.
///
/// `create_new` for the same reason: the temp file must be one we created. A
/// leftover from a crash is removed first, but anything that reappears in
/// between (a hostile pre-created file, a symlink pointed elsewhere) makes the
/// open fail loudly instead of writing plaintext through someone else's inode.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    use std::io::Write;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    create_dir_private(dir)?;
    let tmp = path.with_extension("tmp");

    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    drop(f);

    std::fs::rename(&tmp, path)?;
    Ok(())
}
