use std::path::{Path, PathBuf};

pub mod file;
pub mod keyring;

use crate::store::{CredentialStore, StoreError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendChoice {
    Keyring,
    File(PathBuf),
    /// Keyring when present. Never falls back — see `select`.
    Auto,
}

/// `Auto` resolves to the keyring or fails. It does **not** fall back to a file:
/// an operator who believes the keyring is protecting them, and is silently
/// getting plaintext instead, is exactly the outcome D13 forbids.
pub fn select(
    choice: BackendChoice,
    state_dir: &Path,
) -> Result<Box<dyn CredentialStore>, StoreError> {
    match choice {
        BackendChoice::File(root) => Ok(Box::new(file::FileStore::new(root))),
        BackendChoice::Keyring => Ok(Box::new(keyring::KeyringStore::new(
            state_dir.to_path_buf(),
        ))),
        BackendChoice::Auto => {
            if keyring::KeyringStore::available() {
                Ok(Box::new(keyring::KeyringStore::new(
                    state_dir.to_path_buf(),
                )))
            } else {
                Err(StoreError::Unavailable(
                    "no OS keyring on this system. Credentials will not be stored in plaintext \
                     implicitly: choose a backend explicitly with --credentials-backend \
                     file:<path> (for containers and CI, point it at a mounted secret)"
                        .into(),
                ))
            }
        }
    }
}
