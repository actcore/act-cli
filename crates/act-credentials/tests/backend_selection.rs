use act_credentials::backend::{BackendChoice, select};

#[test]
fn auto_never_silently_degrades_to_a_file() {
    let dir = tempfile::tempdir().unwrap();
    // Force the keyring to look unavailable, as it is in a container.
    unsafe { std::env::set_var("ACT_CREDENTIALS_FORCE_NO_KEYRING", "1") };
    let outcome = select(BackendChoice::Auto, dir.path());
    unsafe { std::env::remove_var("ACT_CREDENTIALS_FORCE_NO_KEYRING") };

    let err = outcome
        .err()
        .expect("Auto must fail rather than write plaintext");
    let msg = err.to_string();
    assert!(
        msg.contains("keyring"),
        "the message names what was unavailable: {msg}"
    );
    assert!(
        msg.contains("--credentials-backend") || msg.contains("credentials-backend"),
        "the message names the explicit choice the operator must make: {msg}"
    );
}

#[test]
fn an_explicit_file_choice_is_honoured() {
    let dir = tempfile::tempdir().unwrap();
    let store = select(BackendChoice::File(dir.path().to_path_buf()), dir.path())
        .expect("explicit file backend is legitimate");
    assert!(store.writable());
    assert!(store.list(None).unwrap().is_empty());
}

/// Run manually on Windows: `cargo test -p act-credentials -- --ignored blob_size`
#[test]
#[ignore = "requires a real OS keyring"]
fn blob_size_ceiling() {
    use act_credentials::backend::keyring::KeyringStore;
    use act_credentials::record::{SecretRecord, SecretValue};
    use act_credentials::store::CredentialStore;
    use std::collections::BTreeMap;

    let dir = tempfile::tempdir().unwrap();
    let store = KeyringStore::new(dir.path().to_path_buf());
    for size in [1024usize, 2048, 4096, 8192] {
        let mut fields = BTreeMap::new();
        fields.insert(
            "std:access-token".to_string(),
            SecretValue::new("x".repeat(size)),
        );
        let rec = SecretRecord {
            kind: "std:oauth2".into(),
            fields,
            host_only: BTreeMap::new(),
            description: None,
            expires_at: None,
        };
        let outcome = store.put("size-probe", &format!("k{size}"), &rec);
        println!("size={size} outcome={outcome:?}");
        let _ = store.erase("size-probe", &format!("k{size}"));
    }
}
