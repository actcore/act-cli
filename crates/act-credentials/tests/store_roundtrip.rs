use std::collections::BTreeMap;

use act_credentials::backend::file::FileStore;
use act_credentials::record::{SecretRecord, SecretValue};
use act_credentials::store::CredentialStore;

fn rec() -> SecretRecord {
    let mut fields = BTreeMap::new();
    fields.insert("acme:token".to_string(), SecretValue::new("tok"));
    let mut host_only = BTreeMap::new();
    host_only.insert("std:refresh-token".to_string(), SecretValue::new("rt"));
    SecretRecord {
        kind: "std:fields".into(),
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
    assert_eq!(got.fields["acme:token"].expose_str(), Some("tok"));
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

/// `update` replaces one field and leaves the rest of the record alone.
///
/// This is the shape an OAuth refresh writes through, and the property the
/// design rests on: sibling fields survive because they were never in scope,
/// not because an implementer remembered to merge them back.
#[test]
fn update_rewrites_one_field_and_leaves_its_siblings() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::new(dir.path().to_path_buf());

    let mut fields = BTreeMap::new();
    fields.insert("acme:token".to_string(), SecretValue::new("old-token"));
    fields.insert("acme:tenant".to_string(), SecretValue::new("tenant-42"));
    let mut host_only = BTreeMap::new();
    host_only.insert(
        "acme:token:std:refresh-token".to_string(),
        SecretValue::new("old-refresh"),
    );
    store
        .put(
            "comp",
            "default",
            &SecretRecord {
                kind: "std:fields".into(),
                fields,
                host_only,
                description: Some("kept".into()),
                expires_at: Some(1_000),
            },
        )
        .unwrap();

    let updated = store
        .update("comp", "default", &mut |rec| {
            rec.fields
                .insert("acme:token".into(), SecretValue::new("new-token"));
            rec.host_only.insert(
                "acme:token:std:refresh-token".into(),
                SecretValue::new("new-refresh"),
            );
            rec.expires_at = Some(2_000);
        })
        .unwrap()
        .expect("the key exists");

    assert_eq!(updated.fields["acme:token"].expose_str(), Some("new-token"));
    assert_eq!(
        updated.fields["acme:tenant"].expose_str(),
        Some("tenant-42"),
        "a sibling field was never in scope"
    );
    assert_eq!(
        updated.host_only["acme:token:std:refresh-token"].expose_str(),
        Some("new-refresh"),
        "rotation replaces the refresh token"
    );
    assert_eq!(updated.description.as_deref(), Some("kept"));

    // And it is on disk, not just in the returned copy.
    let read_back = store.get("comp", "default").unwrap().unwrap();
    assert_eq!(
        read_back.fields["acme:token"].expose_str(),
        Some("new-token")
    );
    assert_eq!(read_back.expires_at, Some(2_000));
}

#[test]
fn update_of_an_absent_key_does_not_run_the_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::new(dir.path().to_path_buf());

    let mut ran = false;
    let got = store.update("comp", "nope", &mut |_| ran = true).unwrap();
    assert!(got.is_none());
    assert!(!ran, "there is nothing to mutate, so nothing is invented");
}

/// Two processes refreshing one credential at once.
///
/// Threads stand in for processes — the lock is advisory and per-file, so both
/// exercise the same `flock`. Without it the two read the same record and the
/// loser's write lands last, carrying data from before the winner's: for a
/// rotating refresh token that is not a lost update but a dead credential.
#[test]
fn concurrent_updates_do_not_lose_one_another() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let store = FileStore::new(root.clone());
    store
        .put(
            "comp",
            "default",
            &SecretRecord {
                kind: "std:fields".into(),
                fields: BTreeMap::from([("acme:counter".to_string(), SecretValue::new("0"))]),
                host_only: BTreeMap::new(),
                description: None,
                expires_at: None,
            },
        )
        .unwrap();

    let threads: Vec<_> = (0..8)
        .map(|_| {
            let root = root.clone();
            std::thread::spawn(move || {
                let store = FileStore::new(root.clone());
                store
                    .update("comp", "default", &mut |rec| {
                        // Read-modify-write inside the lock: the increment is
                        // only safe because nothing else may read between this
                        // read and the write that follows.
                        let n: u32 = rec.fields["acme:counter"]
                            .expose_str()
                            .unwrap()
                            .parse()
                            .unwrap();
                        rec.fields
                            .insert("acme:counter".into(), SecretValue::new((n + 1).to_string()));
                    })
                    .unwrap();
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }

    let final_value = store.get("comp", "default").unwrap().unwrap();
    assert_eq!(
        final_value.fields["acme:counter"].expose_str(),
        Some("8"),
        "every update must be visible to the next one"
    );
}
