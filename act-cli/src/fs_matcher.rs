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
//! - Mode = Allowlist → `Deny` if any deny pattern matches; else `Allow`
//!   if any allow pattern matches; else `Deny`.

use std::path::Path;

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
}

impl FsMatcher {
    /// Compile a matcher from a resolved `FsConfig`.
    pub fn compile(cfg: &FsConfig) -> Result<Self> {
        Ok(Self {
            mode: cfg.mode,
            allow: compile_set("allow", &cfg.allow)?,
            deny: compile_set("deny", &cfg.deny)?,
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
                    FsDecision::Allow
                } else {
                    FsDecision::Deny
                }
            }
        }
    }
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
