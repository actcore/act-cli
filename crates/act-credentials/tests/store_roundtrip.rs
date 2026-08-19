use std::collections::BTreeMap;

use act_credentials::backend::file::FileStore;
use act_credentials::record::{SecretRecord, SecretValue};
use act_credentials::store::CredentialStore;

fn rec() -> SecretRecord {
    let mut fields = BTreeMap::new();
    fields.insert("std:value".to_string(), SecretValue::new("tok"));
    let mut host_only = BTreeMap::new();
    host_only.insert("std:refresh-token".to_string(), SecretValue::new("rt"));
    SecretRecord {
        kind: "std:opaque".into(),
        fields,
        host_only,
        description: Some("Notion work".into()),
        expires_at: None,
    }
}

#[test]
fn put_get_list_erase_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::new(dir.path().to_path_buf());
    let c = "ghcr.io/actpkg/mcp-bridge";

    assert!(store.get(c, "notion").unwrap().is_none());
    store.put(c, "notion", &rec()).unwrap();

    let got = store.get(c, "notion").unwrap().expect("stored");
    assert_eq!(got.fields["std:value"].expose_str(), Some("tok"));
    assert_eq!(got.host_only["std:refresh-token"].expose_str(), Some("rt"));

    let listed = store.list(Some(c)).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].key, "notion");
    assert_eq!(listed[0].description.as_deref(), Some("Notion work"));

    store.erase(c, "notion").unwrap();
    assert!(store.get(c, "notion").unwrap().is_none());
    assert!(store.list(Some(c)).unwrap().is_empty());
}

#[test]
fn the_index_holds_no_values() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::new(dir.path().to_path_buf());
    store.put("comp", "k", &rec()).unwrap();

    let index = std::fs::read_to_string(dir.path().join("index.json")).unwrap();
    assert!(index.contains("\"key\""), "index carries metadata");
    assert!(!index.contains("tok"), "index must not carry a value");
    assert!(
        !index.contains("rt"),
        "index must not carry host-only material"
    );
}

#[test]
fn a_component_cannot_see_another_components_keys() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::new(dir.path().to_path_buf());
    store.put("comp-a", "shared-name", &rec()).unwrap();

    assert!(store.get("comp-b", "shared-name").unwrap().is_none());
    assert!(store.list(Some("comp-b")).unwrap().is_empty());
}

#[test]
fn components_enumerates_the_profiles_and_forgets_the_emptied_ones() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::new(dir.path().to_path_buf());
    assert!(store.components().unwrap().is_empty());

    store.put("comp-a", "k", &rec()).unwrap();
    store.put("comp-b", "k", &rec()).unwrap();
    assert_eq!(store.components().unwrap(), vec!["comp-a", "comp-b"]);

    // A profile exists only while it holds something: `act secret list`
    // must not report a component whose last credential was removed.
    store.erase("comp-a", "k").unwrap();
    assert_eq!(store.components().unwrap(), vec!["comp-b"]);
}

/// The phase's entire protection story, and the one `act secret set` prints to
/// the operator: *"the file will be created 0600, readable only by this
/// user."* Deleting the `mode(0o600)` call left every other test green while
/// the plaintext records were written at the ambient umask — 0644 on a default
/// box — and the CLI kept printing the promise.
///
/// The root is a directory this crate creates, not the tempdir itself:
/// `tempfile` already makes its own directories 0700, so asserting on that
/// would hold whether or not the store sets a mode.
#[cfg(unix)]
#[test]
fn the_store_is_created_readable_only_by_its_owner() {
    use std::os::unix::fs::PermissionsExt;

    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("store");
    let store = FileStore::new(root.clone());
    store.put("comp", "notion", &rec()).unwrap();

    let mode = |p: &std::path::Path| {
        std::fs::metadata(p)
            .unwrap_or_else(|e| panic!("{}: {e}", p.display()))
            .permissions()
            .mode()
            & 0o777
    };

    for p in [
        act_credentials::backend::file::secrets_path(&root),
        root.join("index.json"),
    ] {
        assert_eq!(
            mode(&p),
            0o600,
            "{} must be 0600 — `act secret set` promises it",
            p.display()
        );
    }

    // Files at 0600 keep the contents safe on their own; write permission on
    // the directory is enough for a co-group user to `rename` their own
    // `secrets.json` over the real one and feed a chosen credential to every
    // component that reads this store.
    assert_eq!(
        mode(&root),
        0o700,
        "the store directory must not be created at the ambient umask"
    );
}
