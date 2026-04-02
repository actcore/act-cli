use anyhow::{Result, bail};
use std::path::Path;

pub fn pack_skill_dir(project_dir: &Path) -> Result<Option<Vec<u8>>> {
    let skill_dir = project_dir.join("skill");

    if !skill_dir.exists() {
        return Ok(None);
    }

    if !skill_dir.join("SKILL.md").exists() {
        bail!("skill/ directory exists but is missing SKILL.md");
    }

    let mut buf = Vec::new();
    let mut builder = tar::Builder::new(&mut buf);
    builder.append_dir_all(".", &skill_dir)?;
    builder.finish()?;
    drop(builder);

    Ok(Some(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tar::Archive;
    use tempfile::TempDir;

    #[test]
    fn pack_skill_with_skill_md() {
        let tmp = TempDir::new().unwrap();
        let skill_dir = tmp.path().join("skill");
        fs::create_dir_all(&skill_dir).unwrap();
        fs::write(skill_dir.join("SKILL.md"), "# My Skill").unwrap();

        let result = pack_skill_dir(tmp.path()).unwrap();
        assert!(result.is_some(), "expected Some(bytes)");

        let bytes = result.unwrap();
        let mut archive = Archive::new(bytes.as_slice());
        let entries: Vec<String> = archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();

        assert!(
            entries.iter().any(|p| p == "SKILL.md"),
            "SKILL.md not found in tar; entries: {entries:?}"
        );
    }

    #[test]
    fn no_skill_dir_returns_none() {
        let tmp = TempDir::new().unwrap();
        let result = pack_skill_dir(tmp.path()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn skill_dir_without_skill_md_is_error() {
        let tmp = TempDir::new().unwrap();
        let skill_dir = tmp.path().join("skill");
        fs::create_dir_all(&skill_dir).unwrap();
        fs::write(skill_dir.join("other.txt"), "content").unwrap();

        let result = pack_skill_dir(tmp.path());
        assert!(result.is_err(), "expected an error");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("SKILL.md"),
            "error message should mention SKILL.md; got: {msg}"
        );
    }
}
