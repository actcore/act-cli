//! Advisory file lock over `<store>/.lock`, guarding `index.json` mutations.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

use fs2::FileExt;

/// RAII advisory lock. The lock is released when dropped.
#[derive(Debug)]
pub struct StoreLock {
    file: File,
}

fn open_lockfile(root: &Path) -> io::Result<File> {
    std::fs::create_dir_all(root)?;
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(root.join(".lock"))
}

impl StoreLock {
    /// Block until an exclusive (writer) lock is held.
    pub fn exclusive(root: &Path) -> io::Result<Self> {
        let file = open_lockfile(root)?;
        FileExt::lock_exclusive(&file)?;
        Ok(Self { file })
    }

    /// Block until a shared (reader) lock is held.
    pub fn shared(root: &Path) -> io::Result<Self> {
        let file = open_lockfile(root)?;
        FileExt::lock_shared(&file)?;
        Ok(Self { file })
    }

    /// Non-blocking exclusive lock; errors if it cannot be acquired now.
    pub fn try_exclusive(root: &Path) -> io::Result<Self> {
        let file = open_lockfile(root)?;
        FileExt::try_lock_exclusive(&file)?;
        Ok(Self { file })
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn exclusive_then_shared_release_roundtrip() {
        let dir = TempDir::new().unwrap();
        {
            let _g = StoreLock::exclusive(dir.path()).unwrap();
            assert!(dir.path().join(".lock").is_file());
        } // released on drop
        let _g = StoreLock::shared(dir.path()).unwrap();
    }

    #[test]
    fn try_exclusive_fails_while_held() {
        let dir = TempDir::new().unwrap();
        let _held = StoreLock::exclusive(dir.path()).unwrap();
        assert!(StoreLock::try_exclusive(dir.path()).is_err());
    }
}
