//! Component reference resolution, backed by the shared `act-store`.
//!
//! `ComponentRef` is re-exported from `act-store` (the parsing source of truth).
//! Local refs run in place; remote refs (OCI/HTTP) resolve read-through the
//! store (pulled on first use, then served from disk).

use std::path::PathBuf;

use anyhow::{Context, Result};

pub use act_store::Ref as ComponentRef;

/// Open the shared component store at its platform default location.
pub fn open_store() -> Result<act_store::Store> {
    let dir = act_store::store_dir().context("locating component store")?;
    act_store::Store::open(&dir).context("opening component store")
}

/// Resolve a component reference to a local `.wasm` path.
///
/// Local files are used in place (never copied into the store). Remote refs
/// (OCI/HTTP) are served read-through from the store; `fresh` forces a re-pull.
pub async fn resolve(component_ref: &ComponentRef, fresh: bool) -> Result<PathBuf> {
    if let ComponentRef::Local(path) = component_ref {
        anyhow::ensure!(
            tokio::fs::try_exists(path).await.unwrap_or(false),
            "component not found: {}",
            path.display()
        );
        return Ok(path.clone());
    }
    let store = open_store()?;
    let reference = component_ref.to_string();
    if fresh {
        act_store::pull(&store, &reference)
            .await
            .with_context(|| format!("pulling {reference}"))?;
    }
    act_store::ensure(&store, &reference)
        .await
        .with_context(|| format!("resolving {reference}"))
}
