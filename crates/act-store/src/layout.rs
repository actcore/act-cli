//! OCI image-layout directory mechanics. Knows files and blobs, not components.

use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

pub fn index_path(root: &Path) -> PathBuf {
    root.join("index.json")
}

pub fn oci_layout_path(root: &Path) -> PathBuf {
    root.join("oci-layout")
}

pub fn blobs_dir(root: &Path) -> PathBuf {
    root.join("blobs").join("sha256")
}

/// Path to a blob given its hex digest (no `sha256:` prefix).
pub fn blob_path(root: &Path, hex: &str) -> PathBuf {
    blobs_dir(root).join(hex)
}

/// Create the layout skeleton. Idempotent.
pub fn init(root: &Path) -> io::Result<()> {
    std::fs::create_dir_all(blobs_dir(root))?;
    let marker = oci_layout_path(root);
    if !marker.exists() {
        std::fs::write(&marker, b"{\"imageLayoutVersion\":\"1.0.0\"}")?;
    }
    Ok(())
}

/// Lowercase hex of the sha256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn has_blob(root: &Path, hex: &str) -> bool {
    blob_path(root, hex).is_file()
}

pub fn read_blob(root: &Path, hex: &str) -> io::Result<Vec<u8>> {
    std::fs::read(blob_path(root, hex))
}

/// Write `bytes` as a blob; returns its hex digest. Atomic (temp + rename);
/// a no-op if the blob already exists (content-addressed dedup).
pub fn write_blob(root: &Path, bytes: &[u8]) -> io::Result<String> {
    let hex = sha256_hex(bytes);
    let dest = blob_path(root, &hex);
    if dest.is_file() {
        return Ok(hex);
    }
    std::fs::create_dir_all(blobs_dir(root))?;
    let tmp = blobs_dir(root).join(format!(".{}.{}.tmp", hex, std::process::id()));
    std::fs::write(&tmp, bytes)?;
    match std::fs::rename(&tmp, &dest) {
        Ok(()) => Ok(hex),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn init_creates_layout_skeleton() {
        let dir = TempDir::new().unwrap();
        init(dir.path()).unwrap();
        assert!(dir.path().join("oci-layout").is_file());
        assert!(dir.path().join("blobs").join("sha256").is_dir());
        let marker = std::fs::read_to_string(dir.path().join("oci-layout")).unwrap();
        assert!(marker.contains("imageLayoutVersion"));
    }

    #[test]
    fn init_is_idempotent() {
        let dir = TempDir::new().unwrap();
        init(dir.path()).unwrap();
        init(dir.path()).unwrap();
    }

    #[test]
    fn write_blob_is_content_addressed_and_dedups() {
        let dir = TempDir::new().unwrap();
        init(dir.path()).unwrap();
        let hex1 = write_blob(dir.path(), b"hello").unwrap();
        let hex2 = write_blob(dir.path(), b"hello").unwrap();
        assert_eq!(hex1, hex2, "same bytes -> same digest");
        assert_eq!(
            hex1,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert!(blob_path(dir.path(), &hex1).is_file());
        assert_eq!(read_blob(dir.path(), &hex1).unwrap(), b"hello");
        assert!(has_blob(dir.path(), &hex1));
        assert!(!has_blob(dir.path(), "deadbeef"));
    }
}
