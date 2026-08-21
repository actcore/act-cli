use act_credentials::backend::{BackendChoice, select};

#[test]
fn an_explicit_file_choice_is_honoured() {
    let dir = tempfile::tempdir().unwrap();
    let store = select(BackendChoice::File(dir.path().to_path_buf()), dir.path())
        .expect("explicit file backend is legitimate");
    assert!(store.list(None).unwrap().is_empty());
}
