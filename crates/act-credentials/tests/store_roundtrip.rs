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
    assert_eq!(got.fields["std:value"].expose(), "tok");
    assert_eq!(got.host_only["std:refresh-token"].expose(), "rt");

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
