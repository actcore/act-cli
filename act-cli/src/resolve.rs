//! Component reference resolution, backed by the shared `act-store`.
//!
//! `ComponentRef` is re-exported from `act-store` (the parsing source of truth).
//! Local refs run in place; remote refs (OCI/HTTP) resolve read-through the
//! store (pulled on first use, then served from disk).

use std::path::PathBuf;

use anyhow::{Context, Result};
use path_clean::PathClean;

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

/// The stable key a component's credential profile is namespaced under.
///
/// This is *not* `component_ref.to_string()`. For `Http`/`Oci`/`Name` refs
/// `to_string()` already is canonical (a parsed URL, a registry ref matched
/// by the OCI regex, a bare name) and is returned unchanged. For `Local` it
/// is not: `to_string()` is `path.display()` verbatim, so `./notion.wasm`,
/// `notion.wasm` and its absolute form would each open a *different*
/// profile for the same file — `act secret set ./notion.wasm` followed by
/// `act run notion.wasm` would silently miss.
///
/// Relative local paths are joined onto the current directory and
/// lexically cleaned (`path_clean`, no filesystem access — the component
/// need not exist yet, e.g. before a first `act pull`), so every spelling
/// of the same path agrees. Both `act secret set/list/rm` and the runtime's
/// `credential_host` (main.rs) key their profile lookups through this
/// function, so they cannot drift apart.
pub fn profile_key(component_ref: &ComponentRef) -> String {
    match component_ref {
        ComponentRef::Local(path) => {
            let abs = if path.is_absolute() {
                path.clone()
            } else {
                std::env::current_dir()
                    .map(|cwd| cwd.join(path))
                    .unwrap_or_else(|_| path.clone())
            };
            abs.clean().display().to_string()
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_refs_are_lexically_cleaned_without_touching_the_filesystem() {
        // Absolute, so this is deterministic regardless of the test
        // process's current directory; `..`/`.` are cleaned away purely
        // lexically, on a path that need not exist on disk.
        let key = profile_key(&ComponentRef::Local(PathBuf::from(
            "/abs/a/./sub/../c.wasm",
        )));
        assert_eq!(key, "/abs/a/c.wasm");
    }

    #[test]
    fn non_local_refs_pass_through_unchanged() {
        let oci: ComponentRef = "ghcr.io/actpkg/notion:0.1.0".parse().unwrap();
        assert_eq!(profile_key(&oci), oci.to_string());

        let name: ComponentRef = "sqlite".parse().unwrap();
        assert_eq!(profile_key(&name), "sqlite");
    }
}
