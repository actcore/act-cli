use std::path::{Path, PathBuf};

pub mod file;

use crate::store::{CredentialStore, StoreError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendChoice {
    File(PathBuf),
}

/// The file store is the only backend. Its contents are plaintext on disk,
/// protected by filesystem permissions alone — nothing here encrypts them.
///
/// Selection still goes through this seam, and the choice is still explicit,
/// so a second backend can arrive as another `BackendChoice` variant rather
/// than being wired in somewhere else. `state_dir` is the host's own state
/// directory, unused while `File` carries its own root.
pub fn select(
    choice: BackendChoice,
    _state_dir: &Path,
) -> Result<Box<dyn CredentialStore>, StoreError> {
    match choice {
        BackendChoice::File(root) => Ok(Box::new(file::FileStore::new(root))),
    }
}
