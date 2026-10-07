//! Local OCI-layout component store shared by act-cli and act-toolserver.
//!
//! See `docs/specs/2026-05-26-shared-component-store-design.md`.

pub mod fetch;
pub mod index;
pub mod layout;
pub mod lock;
pub mod provenance;
pub mod reference;
pub mod referrer;
pub mod registry;
pub mod store;

use std::path::PathBuf;

pub use fetch::{UpdateOutcome, ensure, install_local, pull, store_referrer, update};
pub use provenance::{Provenance, ProvenanceError, Source, implied_name_version};
pub use reference::{ParseRefError, Ref};
pub use referrer::{ReferrerInfo, referrer_kind};
pub use store::{Store, StoreError, Stored};

/// Error type for store-location resolution.
#[derive(Debug, thiserror::Error)]
pub enum LocationError {
    #[error("cannot determine a local directory for act's on-disk state")]
    NoDataDir,
}

/// Resolve the shared store directory.
///
/// Priority: `ACT_STORE_DIR` env var, else the platform machine-local data
/// dir under `act/store`:
/// - Linux:   `$XDG_DATA_HOME/act/store` (`~/.local/share/act/store`)
/// - macOS:   `~/Library/Application Support/act/store`
/// - Windows: `%LOCALAPPDATA%\act\store`
pub fn store_dir() -> Result<PathBuf, LocationError> {
    if let Some(dir) = std::env::var_os("ACT_STORE_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let base = dirs::data_local_dir().ok_or(LocationError::NoDataDir)?;
    Ok(base.join("act").join("store"))
}

/// Resolve the wasmtime compilation-cache directory.
///
/// Cranelift's compiled artifacts land here, so a component is compiled once
/// per machine rather than once per process: every `act run`/`act call`
/// otherwise repeats the same compilation. Regenerable bytes, so they live in
/// the platform cache dir, not next to the store's data: priority
/// `ACT_WASMTIME_CACHE_DIR` env var, else the platform cache dir under
/// `act/wasmtime` (`~/.cache/act/wasmtime` on Linux, `~/Library/Caches` on
/// macOS, `%LOCALAPPDATA%` on Windows).
pub fn wasmtime_cache_dir() -> Result<PathBuf, LocationError> {
    if let Some(dir) = std::env::var_os("ACT_WASMTIME_CACHE_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let base = dirs::cache_dir().ok_or(LocationError::NoDataDir)?;
    Ok(base.join("act").join("wasmtime"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_override_wins() {
        let prev = std::env::var_os("ACT_STORE_DIR");
        unsafe { std::env::set_var("ACT_STORE_DIR", "/tmp/act-store-test-xyz") };
        assert_eq!(
            store_dir().unwrap(),
            std::path::PathBuf::from("/tmp/act-store-test-xyz")
        );
        match prev {
            Some(v) => unsafe { std::env::set_var("ACT_STORE_DIR", v) },
            None => unsafe { std::env::remove_var("ACT_STORE_DIR") },
        }
    }

    #[test]
    fn wasmtime_cache_dir_follows_the_store_shape() {
        let prev = std::env::var_os("ACT_WASMTIME_CACHE_DIR");
        unsafe { std::env::set_var("ACT_WASMTIME_CACHE_DIR", "/tmp/act-wasmtime-test-xyz") };
        assert_eq!(
            wasmtime_cache_dir().unwrap(),
            std::path::PathBuf::from("/tmp/act-wasmtime-test-xyz")
        );
        match prev {
            Some(v) => unsafe { std::env::set_var("ACT_WASMTIME_CACHE_DIR", v) },
            None => unsafe { std::env::remove_var("ACT_WASMTIME_CACHE_DIR") },
        }
        // Without the override it sits in the platform cache dir, not the
        // data dir where the store lives.
        let mut dir = dirs::cache_dir().unwrap();
        dir.extend(["act", "wasmtime"]);
        assert_eq!(wasmtime_cache_dir().unwrap(), dir);
    }
}
