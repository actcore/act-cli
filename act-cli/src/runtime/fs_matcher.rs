//! Layer 1 phase C1, part 1/2: glob matcher for filesystem policy.
//!
//! Compiles the resolved `FsConfig.allow` / `FsConfig.deny` lists into
//! `GlobSet`s and answers "is this absolute host path allowed?" The matcher
//! itself is hook-agnostic — it's consumed by the custom `HostDescriptor`
//! wrapper (part 2/2) at `open_at` time.
//!
//! Path normalisation rules:
//! - All patterns are canonicalised to absolute host paths at construction
//!   (`~` expansion, relative paths resolved against the current directory).
//! - All paths passed to `decide` must be absolute host paths, already
//!   canonicalised (symlinks resolved, `..` collapsed). The wrapper handles
//!   canonicalisation before calling into the matcher.
//! - Patterns accept `globset` syntax: `*`, `?`, `[...]`, `{a,b}`, `**`. A
//!   pattern ending in `/` or `/**` applies to the directory and everything
//!   below it.
//!
//! Decision rule:
//! - Mode = Deny → always `Deny`.
//! - Mode = Open → always `Allow`.
//! - Mode = Allowlist:
//!   - `Deny` if any deny pattern matches.
//!   - `Allow` if any allow pattern matches.
//!   - `Allow` if the path is a directory **ancestor** of any allowed
//!     pattern's literal prefix. WASI path resolution stats every
//!     intermediate directory when opening a nested path, so a user
//!     granting `/tmp/work/db.sqlite` implicitly grants traversal on
//!     `/tmp/work` and `/tmp` (metadata only — those dirs aren't
//!     "allowed" for listing, but they are for the traversal needed
//!     to reach the target).
//!   - `Deny` otherwise.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::config::{FsConfig, PolicyMode};

/// Result of a policy decision for one filesystem operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // wired in phase C1 part 2 (HostDescriptor wrapper)
pub enum FsDecision {
    Allow,
    Deny,
}

/// Compiled glob sets ready to decide access for a given host path.
#[derive(Debug, Clone)]
#[allow(dead_code)] // wired in phase C1 part 2 (HostDescriptor wrapper)
pub struct FsMatcher {
    mode: PolicyMode,
    allow: GlobSet,
    deny: GlobSet,
    /// Literal path prefix of each allow entry — the longest ancestor
    /// with no glob metacharacter. `/a/b/c.db` → `/a/b/c.db`;
    /// `/tmp/*.db` → `/tmp`; `/foo/bar/**` → `/foo/bar`. Used to permit
    /// traversal of intermediate directories on the path to any
    /// allowed target.
    allow_prefixes: Vec<PathBuf>,
}

impl FsMatcher {
    /// Compile a matcher from a resolved `FsConfig`.
    pub fn compile(cfg: &FsConfig) -> Result<Self> {
        let mut allow_prefixes = Vec::new();
        for pat in &cfg.allow {
            let expanded = expand_pattern(pat);
            allow_prefixes.push(PathBuf::from(literal_prefix(&expanded)));
        }
        Ok(Self {
            mode: cfg.mode,
            allow: compile_set("allow", &cfg.allow)?,
            deny: compile_set("deny", &cfg.deny)?,
            allow_prefixes,
        })
    }

    /// Decide whether an absolute, canonical host path may be opened/touched.
    pub fn decide(&self, path: &Path) -> FsDecision {
        match self.mode {
            PolicyMode::Deny => FsDecision::Deny,
            PolicyMode::Open => FsDecision::Allow,
            PolicyMode::Allowlist => {
                if self.deny.is_match(path) {
                    return FsDecision::Deny;
                }
                if self.allow.is_match(path) {
                    return FsDecision::Allow;
                }
                // Ancestor-traversal check: allow stat/open on any directory
                // that lies on the path to some allowed target.
                if self
                    .allow_prefixes
                    .iter()
                    .any(|prefix| is_ancestor(path, prefix))
                {
                    return FsDecision::Allow;
                }
                FsDecision::Deny
            }
        }
    }
}

/// Extract the longest leading path segment of `pattern` that contains no
/// glob metacharacter (`*`, `?`, `[`, `{`). That segment is the literal
/// prefix under which the glob might match.
fn literal_prefix(pattern: &str) -> &str {
    // Find the first component containing a metachar. Keep everything before it.
    let bytes = pattern.as_bytes();
    let mut last_boundary = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'/' {
            last_boundary = i;
        } else if matches!(b, b'*' | b'?' | b'[' | b'{') {
            return &pattern[..last_boundary];
        }
        i += 1;
    }
    // No metachar found — the whole pattern is literal.
    pattern
}

/// Is `candidate` an ancestor of `target` (i.e., `target` is `candidate`
/// with zero or more additional components)? Works by walking `target`'s
/// ancestor chain looking for an exact match. Returns `false` if
/// `candidate` is empty.
fn is_ancestor(candidate: &Path, target: &Path) -> bool {
    if candidate.as_os_str().is_empty() {
        return false;
    }
    for ancestor in target.ancestors() {
        if ancestor == candidate {
            return true;
        }
    }
    false
}

fn compile_set(label: &str, patterns: &[String]) -> Result<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        let expanded = expand_pattern(p);
        let glob = Glob::new(&expanded)
            .with_context(|| format!("invalid {label} glob '{p}' (expanded: '{expanded}')"))?;
        b.add(glob);
        // A directory pattern like `/foo/bar` (no trailing `/**`) should also
        // match descendants, so add `/foo/bar/**` alongside.
        if !expanded.ends_with("/**") && !expanded.contains('*') && !expanded.contains('?') {
            let descendants = format!("{expanded}/**");
            let glob = Glob::new(&descendants).with_context(|| {
                format!("invalid derived {label} glob '{descendants}' from '{p}'")
            })?;
            b.add(glob);
        }
    }
    b.build()
        .with_context(|| format!("failed to build {label} glob set"))
}

/// Expand `~` and make patterns absolute. Relative patterns are resolved
/// against the current directory; patterns beginning with `~` expand against
/// the home directory. `**` and other globset metacharacters are left intact.
///
/// On Windows, backslashes are normalised to forward slashes so the pattern
/// matches the `/`-separated paths globset operates on. User-written Windows
/// patterns should already use forward slashes (e.g. `C:/Users/alex/**`);
/// this normalisation only catches strays introduced by path joining.
fn expand_pattern(pattern: &str) -> String {
    let expanded = shellexpand::tilde(pattern).into_owned();
    let absolute = if Path::new(&expanded).is_absolute() {
        expanded
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(&expanded).to_string_lossy().into_owned(),
            Err(_) => expanded,
        }
    };
    #[cfg(windows)]
    {
        absolute.replace('\\', "/")
    }
    #[cfg(not(windows))]
    {
        absolute
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn cfg(mode: PolicyMode, allow: &[&str], deny: &[&str]) -> FsConfig {
        FsConfig {
            mode,
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn deny_mode_blocks_everything() {
        let m = FsMatcher::compile(&cfg(PolicyMode::Deny, &[], &[])).unwrap();
        assert_eq!(m.decide(&PathBuf::from("/tmp/anything")), FsDecision::Deny);
    }

    #[test]
    fn open_mode_allows_everything() {
        let m = FsMatcher::compile(&cfg(PolicyMode::Open, &[], &[])).unwrap();
        assert_eq!(m.decide(&PathBuf::from("/etc/passwd")), FsDecision::Allow);
    }

    #[test]
    fn allow_literal_path_matches_descendants() {
        let m = FsMatcher::compile(&cfg(PolicyMode::Allowlist, &["/tmp/work"], &[])).unwrap();
        assert_eq!(m.decide(&PathBuf::from("/tmp/work")), FsDecision::Allow);
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/work/sub/file.txt")),
            FsDecision::Allow
        );
        assert_eq!(m.decide(&PathBuf::from("/tmp/other")), FsDecision::Deny);
    }

    #[test]
    fn allow_trailing_double_star_matches_descendants() {
        let m = FsMatcher::compile(&cfg(PolicyMode::Allowlist, &["/tmp/work/**"], &[])).unwrap();
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/work/sub/file.txt")),
            FsDecision::Allow
        );
        assert_eq!(m.decide(&PathBuf::from("/tmp/other")), FsDecision::Deny);
    }

    #[test]
    fn deny_rules_beat_allow() {
        let m = FsMatcher::compile(&cfg(
            PolicyMode::Allowlist,
            &["/home/alex/**"],
            &["/home/alex/.ssh/**", "/home/alex/.aws/**"],
        ))
        .unwrap();
        assert_eq!(
            m.decide(&PathBuf::from("/home/alex/project/main.rs")),
            FsDecision::Allow
        );
        assert_eq!(
            m.decide(&PathBuf::from("/home/alex/.ssh/id_rsa")),
            FsDecision::Deny
        );
        assert_eq!(
            m.decide(&PathBuf::from("/home/alex/.aws/credentials")),
            FsDecision::Deny
        );
    }

    #[test]
    fn ripgrep_style_brace_expansion() {
        let m = FsMatcher::compile(&cfg(
            PolicyMode::Allowlist,
            &["/home/alex/{projects,work}/**"],
            &[],
        ))
        .unwrap();
        assert_eq!(
            m.decide(&PathBuf::from("/home/alex/projects/foo/lib.rs")),
            FsDecision::Allow
        );
        assert_eq!(
            m.decide(&PathBuf::from("/home/alex/work/docs/README.md")),
            FsDecision::Allow
        );
        assert_eq!(
            m.decide(&PathBuf::from("/home/alex/Downloads/x")),
            FsDecision::Deny
        );
    }

    #[test]
    fn ancestor_of_allowed_literal_file_is_traversable() {
        // Allowing /tmp/work/db.sqlite implicitly grants traversal on
        // /tmp/work and /tmp so the WASI path-walker can stat each
        // intermediate directory before reaching the target.
        let m =
            FsMatcher::compile(&cfg(PolicyMode::Allowlist, &["/tmp/work/db.sqlite"], &[])).unwrap();
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/work/db.sqlite")),
            FsDecision::Allow
        );
        assert_eq!(m.decide(&PathBuf::from("/tmp/work")), FsDecision::Allow);
        assert_eq!(m.decide(&PathBuf::from("/tmp")), FsDecision::Allow);
        assert_eq!(m.decide(&PathBuf::from("/")), FsDecision::Allow);
        // Sibling dir not on the path — still denied.
        assert_eq!(m.decide(&PathBuf::from("/tmp/other")), FsDecision::Deny);
        assert_eq!(m.decide(&PathBuf::from("/var")), FsDecision::Deny);
    }

    #[test]
    fn ancestor_of_glob_literal_prefix_is_traversable() {
        let m =
            FsMatcher::compile(&cfg(PolicyMode::Allowlist, &["/tmp/work/**/*.db"], &[])).unwrap();
        // Literal prefix is /tmp/work. Ancestors allowed.
        assert_eq!(m.decide(&PathBuf::from("/tmp/work")), FsDecision::Allow);
        assert_eq!(m.decide(&PathBuf::from("/tmp")), FsDecision::Allow);
        // A .db inside is allowed by the glob.
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/work/a/b.db")),
            FsDecision::Allow
        );
        // Non-.db file below is NOT allowed — ancestor rule only covers
        // *reaching* the allowed target, not reading siblings.
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/work/a/b.txt")),
            FsDecision::Deny
        );
    }

    #[test]
    fn ancestor_does_not_leak_past_first_glob_component() {
        // `/tmp/*.db` — the literal prefix is `/tmp`. Ancestors of that
        // (i.e. `/`) are traversable, but so is `/tmp` itself. What
        // shouldn't leak: a sibling of the glob target.
        let m = FsMatcher::compile(&cfg(PolicyMode::Allowlist, &["/tmp/*.db"], &[])).unwrap();
        assert_eq!(m.decide(&PathBuf::from("/tmp")), FsDecision::Allow);
        assert_eq!(m.decide(&PathBuf::from("/tmp/foo.db")), FsDecision::Allow);
        assert_eq!(m.decide(&PathBuf::from("/tmp/foo.txt")), FsDecision::Deny);
    }

    #[test]
    fn extension_glob() {
        let m = FsMatcher::compile(&cfg(PolicyMode::Allowlist, &["/tmp/**/*.md"], &[])).unwrap();
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/notes/today.md")),
            FsDecision::Allow
        );
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/notes/secret.txt")),
            FsDecision::Deny
        );
    }
}
