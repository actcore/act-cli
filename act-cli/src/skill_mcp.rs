//! SEP-2640 MCP Skills extension: serving an embedded `act:skill` package
//! over MCP.
//!
//! A component's `act:skill` custom section is an uncompressed tar of an
//! Agent Skills package (ACT-AGENTSKILLS.md). [`SkillArchive`] opens that
//! section in place: the component file is memory-mapped once, the tar is
//! indexed by `(offset, len)` ranges into the mapping, and file contents are
//! served as slices of the mmap — nothing is copied to the heap except
//! SKILL.md's frontmatter. Manifest digests are computed lazily, on the
//! first `skills/list` or `skills/get`, so clients that never ask pay
//! nothing.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use anyhow::Context as _;

/// The WASM custom section name holding the tar archive (ACT-AGENTSKILLS §2).
pub const SKILL_SECTION: &str = "act:skill";

/// The embedded skill package of a component, served as mmap slices.
pub struct SkillArchive {
    mmap: memmap2::Mmap,
    /// Relative path inside the skill → byte range into the mapping.
    entries: BTreeMap<String, (u64, u64)>,
    /// Parsed SKILL.md frontmatter; present when the section validated.
    frontmatter: Frontmatter,
    /// Lazily built SEP-2640 skill entry (manifest with digests).
    skill: OnceLock<rmcp::model::Skill>,
}

/// The `SKILL.md` frontmatter: the two fields SEP-2640 requires, plus every
/// additional scalar field the author wrote.
struct Frontmatter {
    name: String,
    description: String,
    extra: serde_json::Map<String, serde_json::Value>,
}

impl SkillArchive {
    /// Open the `act:skill` section of the component at `path`, or `None`
    /// when the component carries no skill.
    ///
    /// A malformed section — not a tar, no parsable SKILL.md frontmatter,
    /// a package without its `SKILL.md` — degrades to `None` with a warning:
    /// the component is served skillless rather than failing to start.
    pub fn open(path: &Path) -> anyhow::Result<Option<Arc<Self>>> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("opening component {}", path.display()))?;
        // SAFETY: read-only mapping of an existing file, never written.
        let mmap = unsafe { memmap2::Mmap::map(&file) }
            .with_context(|| format!("mapping component {}", path.display()))?;
        let Some(section) = find_section(&mmap, SKILL_SECTION) else {
            return Ok(None);
        };
        let section_bytes = &mmap[section.0 as usize..section.1 as usize];
        let entries = index_tar(section_bytes, section.0);
        let Some(skill_md) = entries.get("SKILL.md") else {
            tracing::warn!(
                "component has an {SKILL_SECTION} section without SKILL.md; serving without MCP skill"
            );
            return Ok(None);
        };
        let skill_md_bytes = &mmap[skill_md.0 as usize..(skill_md.0 + skill_md.1) as usize];
        let Some(frontmatter) = parse_frontmatter(skill_md_bytes) else {
            tracing::warn!(
                "component's {SKILL_SECTION} SKILL.md has no parsable frontmatter; serving without MCP skill"
            );
            return Ok(None);
        };
        Ok(Some(Arc::new(Self {
            mmap,
            entries,
            frontmatter,
            skill: OnceLock::new(),
        })))
    }

    /// The skill's `name` as declared in SKILL.md frontmatter — the single
    /// path segment between `skill://` and the package file path.
    pub fn frontmatter_name(&self) -> &str {
        &self.frontmatter.name
    }

    /// The SEP-2640 skill entry: URI, frontmatter, and the file manifest with
    /// digests. Computed on first use; the archive is immutable afterwards.
    pub fn skill(&self) -> &rmcp::model::Skill {
        self.skill.get_or_init(|| {
            let name = &self.frontmatter.name;
            let files: Vec<_> = self
                .entries
                .iter()
                .map(|(path, (off, len))| {
                    let bytes = &self.mmap[*off as usize..(*off + *len) as usize];
                    rmcp::model::SkillResource::from_bytes(format!("skill://{name}/{path}"), bytes)
                })
                .collect();
            let mut frontmatter = rmcp::model::SkillFrontmatter::new(
                self.frontmatter.name.clone(),
                self.frontmatter.description.clone(),
            );
            for (key, value) in &self.frontmatter.extra {
                frontmatter = frontmatter.with_field(key.clone(), value.clone());
            }
            rmcp::model::Skill::new(
                format!("skill://{name}/SKILL.md"),
                frontmatter,
                rmcp::model::SkillResources::Files(files),
            )
        })
    }

    /// The bytes of one file inside the package, as a slice of the mapping.
    pub fn file(&self, path: &str) -> Option<&[u8]> {
        let (off, len) = self.entries.get(path)?;
        Some(&self.mmap[*off as usize..(*off + *len) as usize])
    }

    /// Every file path in the package, sorted — the iteration order for
    /// extraction (`act skill`).
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    /// Direct children of the directory `dir` (a `skill://` URI without a
    /// trailing slash), as SEP-2640 `resources/directory/read` entries.
    /// `None` when `dir` is not a directory of this package — a file, or
    /// not part of the skill at all.
    pub fn directory_children(&self, dir: &str) -> Option<Vec<rmcp::model::Resource>> {
        const DIRECTORY_MIME: &str = "inode/directory";
        let prefix = format!("{dir}/");
        let name = &self.frontmatter.name;
        // A directory prefix only matches when the package really has a
        // file under it — `skill://name/typos` must not become a directory.
        // Keys are tar-relative, so each is expanded to its full
        // `skill://<name>/<path>` URI before the prefix test.
        if !self.entries.keys().any(|path| {
            format!("skill://{name}/{path}")
                .strip_prefix(&prefix)
                .is_some()
        }) {
            return None;
        }
        let mut children: Vec<rmcp::model::Resource> = Vec::new();
        for path in self.entries.keys() {
            let uri = format!("skill://{name}/{path}");
            let Some(relative) = uri.strip_prefix(&prefix) else {
                continue;
            };
            let child = match relative.split_once('/') {
                None => {
                    rmcp::model::Resource::new(format!("{prefix}{relative}"), relative.to_string())
                }
                // First segment of a deeper path is a subdirectory.
                Some((subdir, _)) => {
                    rmcp::model::Resource::new(format!("{prefix}{subdir}"), subdir.to_string())
                        .with_mime_type(DIRECTORY_MIME)
                }
            };
            if !children.iter().any(|c| c.uri == child.uri) {
                children.push(child);
            }
        }
        Some(children)
    }
}

/// The byte range `[start, end)` of the named custom section in `wasm`.
fn find_section(wasm: &[u8], name: &str) -> Option<(u64, u64)> {
    for payload in wasmparser::Parser::new(0).parse_all(wasm) {
        if let Ok(wasmparser::Payload::CustomSection(section)) = payload
            && section.name() == name
        {
            let start = section.data_offset();
            return Some((start, start + section.data().len() as u64));
        }
    }
    None
}

/// Index an uncompressed tar into relative paths → `(offset, len)` ranges
/// absolute within the component mapping (`base` = section start).
///
/// Entries whose path is absolute or carries a `..` segment are skipped
/// (ACT-AGENTSKILLS §5); directories are not listed.
fn index_tar(tar_bytes: &[u8], base: u64) -> BTreeMap<String, (u64, u64)> {
    let mut entries = BTreeMap::new();
    let mut archive = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    let Ok(entry_iter) = archive.entries() else {
        return entries;
    };
    for entry in entry_iter {
        let Ok(entry) = entry else { continue };
        let Ok(path) = entry.path() else { continue };
        let Some(path) = path.to_str() else { continue };
        if path.starts_with('/') || path.split('/').any(|seg| seg == "..") {
            continue;
        }
        if entry.header().entry_type().is_dir() {
            continue;
        }
        let Ok(size) = entry.header().entry_size() else {
            continue;
        };
        let offset = entry.raw_file_position();
        if size == 0 {
            continue;
        }
        entries.insert(path.to_string(), (base + offset, size));
    }
    entries
}

/// Parse the YAML frontmatter of a SKILL.md: `---`-delimited scalar
/// `key: value` pairs.
///
/// Only scalars are kept — SEP-2640 requires `name` and `description`, and
/// the rest ride along in `extra` as strings. A nested or list field cannot
/// be represented and is dropped at debug level.
fn parse_frontmatter(skill_md: &[u8]) -> Option<Frontmatter> {
    let text = std::str::from_utf8(skill_md).ok()?;
    let rest = text.strip_prefix("---\n")?;
    let (frontmatter, _body) = rest.split_once("\n---")?;
    let mut name = None;
    let mut description = None;
    let mut extra = serde_json::Map::new();
    for line in frontmatter.lines() {
        let Some((key, value)) = line.split_once(": ") else {
            continue;
        };
        let value = value.trim().trim_matches('"');
        match key {
            "name" => name = Some(value.to_string()),
            "description" => description = Some(value.to_string()),
            _ => {
                extra.insert(
                    key.to_string(),
                    serde_json::Value::String(value.to_string()),
                );
            }
        }
    }
    Some(Frontmatter {
        name: name?,
        description: description?,
        extra,
    })
}

/// Shared test fixtures: component binaries with an embedded skill package.
///
/// The `rmcp_bridge` tests drive the same archive through the MCP hooks, so
/// the builders live here rather than inside the local test module.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use std::path::PathBuf;

    /// Build a minimal component wasm with a custom section appended.
    ///
    /// Framing via `wasm-encoder` (the same crate `act-build pack` uses), so
    /// the fixture's section encoding is exactly production's.
    pub(crate) fn component_with_section(name: &str, payload: &[u8]) -> Vec<u8> {
        use wasm_encoder::Section as _;
        let mut wasm = b"\0asm\x0d\x00\x01\x00".to_vec();
        wasm_encoder::CustomSection {
            name: name.into(),
            data: payload.into(),
        }
        .append_to(&mut wasm);
        wasm
    }

    /// A tar archive built in memory: `(path, bytes)` entries.
    pub(crate) fn tar_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, bytes) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            if path.contains("..") || path.starts_with('/') {
                // `tar::Builder` refuses unsafe paths; a hostile archive has
                // no such scruples, so splice the entry in by hand. A GNU
                // header is 512 bytes with the path at offset 0 and the
                // size field as octal ASCII at offset 124.
                let mut header_bytes = [0u8; 512];
                header_bytes[..path.len()].copy_from_slice(path.as_bytes());
                let size_field = format!("{:011o}\0", bytes.len());
                header_bytes[124..124 + size_field.len()].copy_from_slice(size_field.as_bytes());
                // Checksum: sum of header bytes with the checksum field
                // itself read as spaces.
                header_bytes[148..156].copy_from_slice(b"        ");
                let sum: u32 = header_bytes.iter().map(|b| *b as u32).sum();
                let ck = format!("{:06o}\0 ", sum);
                header_bytes[148..156].copy_from_slice(ck.as_bytes());
                builder.get_mut().extend_from_slice(&header_bytes);
                builder.get_mut().extend_from_slice(bytes);
                // Pad the payload to a 512-byte boundary.
                let padding = (512 - bytes.len() % 512) % 512;
                builder.get_mut().extend(std::iter::repeat_n(0u8, padding));
            } else {
                builder
                    .append_data(&mut header, path, *bytes)
                    .expect("append");
            }
        }
        builder.into_inner().expect("tar built")
    }

    /// A SKILL.md with the given frontmatter lines and a body.
    pub(crate) fn skill_md(frontmatter: &[(&str, &str)], body: &str) -> Vec<u8> {
        let mut text = String::from("---\n");
        for (key, value) in frontmatter {
            text.push_str(&format!("{key}: {value}\n"));
        }
        text.push_str("---\n\n");
        text.push_str(body);
        text.into_bytes()
    }

    /// Write `bytes` to a temp file that outlives the test (the archive
    /// holds an mmap of it); leaked tempdirs are cleaned by the OS.
    pub(crate) fn written(bytes: &[u8]) -> PathBuf {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("component.wasm");
        std::fs::write(&path, bytes).expect("write");
        std::mem::forget(dir);
        path
    }

    /// A component whose skill package holds SKILL.md plus two files.
    pub(crate) fn component_with_skill() -> PathBuf {
        let skill_md = skill_md(
            &[
                ("name", "navigable"),
                ("description", "SQL navigation helpers"),
                ("license", "MIT"),
            ],
            "Use the query files.\n",
        );
        let tar = tar_of(&[
            ("SKILL.md", &skill_md),
            ("queries/basic.sql", &b"SELECT 1;"[..]),
            ("references/api.md", &b"# API"[..]),
        ]);
        written(&component_with_section("act:skill", &tar))
    }

    /// Open the fixture component's skill archive.
    pub(crate) fn skill_archive() -> Arc<SkillArchive> {
        SkillArchive::open(&component_with_skill())
            .expect("open succeeds")
            .expect("skill present")
    }

    #[test]
    fn fixtures_smoke() {
        let archive = skill_archive();
        assert_eq!(archive.frontmatter.name, "navigable");
        assert!(archive.file("queries/basic.sql").is_some());
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{component_with_section, skill_md, tar_of, written};
    use super::*;

    #[test]
    fn a_component_without_a_skill_section_opens_to_none() {
        let path = written(&component_with_section("act:component", b"junk"));
        let opened = SkillArchive::open(&path).expect("open succeeds");
        assert!(opened.is_none(), "no act:skill section means no skill");
    }

    #[test]
    fn the_skill_manifest_carries_frontmatter_and_digests() {
        let skill_md = skill_md(
            &[
                ("name", "component-sqlite"),
                ("description", "SQLite access"),
            ],
            "# Use the database\n",
        );
        let reference = b"SELECT 1;\n";
        let tar = tar_of(&[("SKILL.md", &skill_md), ("queries/basic.sql", reference)]);
        let path = written(&component_with_section("act:skill", &tar));

        let archive = SkillArchive::open(&path)
            .expect("open succeeds")
            .expect("skill section present");

        let skill = archive.skill();
        assert_eq!(skill.uri, "skill://component-sqlite/SKILL.md");
        assert_eq!(skill.frontmatter.name, "component-sqlite");
        assert_eq!(skill.frontmatter.description, "SQLite access");

        // The manifest digests describe the served bytes: verify() is
        // SEP-2640's own integrity check over exactly the slices handed out.
        let basic = archive
            .file("queries/basic.sql")
            .expect("file present in archive");
        assert_eq!(basic, reference);
        let rmcp::model::SkillResources::Files(entries) = &skill.resources else {
            panic!("a static embedded skill serves Files, not Dynamic");
        };
        let entry = entries
            .iter()
            .find(|e| e.uri == "skill://component-sqlite/queries/basic.sql")
            .expect("manifest lists the file");
        entry.verify(basic).expect("digest matches served bytes");

        let md = archive.file("SKILL.md").expect("SKILL.md present");
        assert_eq!(md, skill_md.as_slice());
    }

    #[test]
    fn escape_paths_are_dropped_from_the_manifest() {
        let skill_md = skill_md(
            &[("name", "escapee"), ("description", "path traversal test")],
            "body\n",
        );
        let tar = tar_of(&[
            ("SKILL.md", &skill_md),
            ("../outside.txt", b"no"),
            ("/absolute.txt", b"no"),
            ("fine.txt", b"yes"),
        ]);
        let path = written(&component_with_section("act:skill", &tar));
        let archive = SkillArchive::open(&path)
            .expect("open succeeds")
            .expect("skill section present");

        assert!(archive.file("../outside.txt").is_none());
        assert!(archive.file("/absolute.txt").is_none());
        assert_eq!(archive.file("fine.txt"), Some(&b"yes"[..]));
        let rmcp::model::SkillResources::Files(entries) = &archive.skill().resources else {
            panic!("static skill");
        };
        let uris: Vec<_> = entries.iter().map(|e| e.uri.as_str()).collect();
        assert_eq!(
            uris,
            ["skill://escapee/SKILL.md", "skill://escapee/fine.txt"]
        );
    }

    #[test]
    fn a_section_without_skill_md_is_served_skillless() {
        let tar = tar_of(&[("README.md", &b"no entry point"[..])]);
        let path = written(&component_with_section("act:skill", &tar));
        let opened = SkillArchive::open(&path).expect("open succeeds");
        assert!(opened.is_none(), "tar without SKILL.md is not a skill");
    }

    #[test]
    fn frontmatter_without_name_or_description_is_served_skillless() {
        let skill_md = skill_md(&[("name", "half")], "body\n"); // no description
        let tar = tar_of(&[("SKILL.md", &skill_md)]);
        let path = written(&component_with_section("act:skill", &tar));
        let opened = SkillArchive::open(&path).expect("open succeeds");
        assert!(opened.is_none());
    }

    #[test]
    fn directory_children_lists_files_and_subdirs() {
        let skill_md = skill_md(
            &[("name", "navigable"), ("description", "dir read test")],
            "body\n",
        );
        let tar = tar_of(&[
            ("SKILL.md", &skill_md),
            ("references/api.md", &b"# API"[..]),
            ("references/deep/eu.md", &b"# EU"[..]),
        ]);
        let path = written(&component_with_section("act:skill", &tar));
        let archive = SkillArchive::open(&path)
            .expect("open succeeds")
            .expect("skill present");

        let describe = |items: &[rmcp::model::Resource]| -> Vec<(String, String)> {
            items
                .iter()
                .map(|r| (r.uri.clone(), r.name.clone()))
                .collect()
        };

        let children = archive
            .directory_children("skill://navigable")
            .expect("root is a directory");
        assert_eq!(
            describe(&children),
            [
                (
                    "skill://navigable/SKILL.md".to_string(),
                    "SKILL.md".to_string()
                ),
                (
                    "skill://navigable/references".to_string(),
                    "references".to_string()
                ),
            ]
        );

        let nested = archive
            .directory_children("skill://navigable/references")
            .expect("references is a directory");
        assert_eq!(
            describe(&nested),
            [
                (
                    "skill://navigable/references/api.md".to_string(),
                    "api.md".to_string()
                ),
                (
                    "skill://navigable/references/deep".to_string(),
                    "deep".to_string()
                ),
            ]
        );

        // A file and a non-existent path are not directories.
        assert!(
            archive
                .directory_children("skill://navigable/SKILL.md")
                .is_none()
        );
        assert!(archive.directory_children("skill://absent").is_none());
    }

    /// The mapping outlives the `File` handle and the `open` stack frame:
    /// this pins that slices stay valid with only the archive alive.
    #[test]
    fn file_slices_survive_without_the_file_handle() {
        let skill_md = skill_md(&[("name", "persist"), ("description", "lifetime")], "b\n");
        let bytes = b"stable content";
        let tar = tar_of(&[("SKILL.md", &skill_md), ("blob.bin", bytes)]);
        let path = written(&component_with_section("act:skill", &tar));
        let archive = SkillArchive::open(&path)
            .expect("open")
            .expect("skill present");
        assert_eq!(archive.file("blob.bin"), Some(bytes.as_slice()));
    }
}
