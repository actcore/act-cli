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

use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::Decision;
use crate::grant::{FsConfig, PolicyError, PolicyMode};

/// The access type being requested on a filesystem path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsAccess {
    Read,
    Write,
}

/// Compiled glob sets ready to decide access for a given host path.
#[derive(Debug, Clone)]
#[allow(dead_code)] // wired in phase C1 part 2 (HostDescriptor wrapper)
pub struct FsMatcher {
    mode: PolicyMode,
    /// All allow entries (read + write) — used for Read access.
    read_allow: GlobSet,
    /// Only rw allow entries — used for Write access.
    write_allow: GlobSet,
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
    pub fn compile(cfg: &FsConfig) -> Result<Self, PolicyError> {
        let mut allow_prefixes = Vec::new();
        for entry in &cfg.allow {
            let expanded = expand_pattern(&entry.glob);
            allow_prefixes.push(PathBuf::from(literal_prefix(&expanded)));
        }
        let all_globs: Vec<String> = cfg.allow.iter().map(|e| e.glob.clone()).collect();
        let rw_globs: Vec<String> = cfg
            .allow
            .iter()
            .filter(|e| e.mode == act_types::FsMode::Rw)
            .map(|e| e.glob.clone())
            .collect();
        Ok(Self {
            mode: cfg.mode,
            read_allow: compile_set("read_allow", &all_globs)?,
            write_allow: compile_set("write_allow", &rw_globs)?,
            deny: compile_set("deny", &cfg.deny)?,
            allow_prefixes,
        })
    }

    /// Decide whether an absolute, canonical host path may be accessed.
    /// `access` specifies whether the operation is a read or write.
    pub fn decide(&self, path: &Path, access: FsAccess) -> Decision {
        let allow = match access {
            FsAccess::Read => &self.read_allow,
            FsAccess::Write => &self.write_allow,
        };
        match self.mode {
            PolicyMode::Deny => Decision::Deny,
            PolicyMode::Open => Decision::Allow,
            // Ask is bounded by the declared ceiling: run the same allow/deny
            // matching as Allowlist, but emit `Ask` (defer to the interactive
            // prompt) where Allowlist would emit `Allow`. Deny still wins, and
            // out-of-ceiling targets are denied WITHOUT prompting.
            // Ancestor traversal is only relevant for Read (directory stat).
            PolicyMode::Ask => {
                if self.deny.is_match(path) {
                    return Decision::Deny;
                }
                let in_ceiling = allow.is_match(path)
                    || (matches!(access, FsAccess::Read)
                        && self
                            .allow_prefixes
                            .iter()
                            .any(|prefix| is_ancestor(path, prefix)));
                if in_ceiling {
                    return Decision::Ask;
                }
                Decision::Deny
            }
            PolicyMode::Allowlist => {
                if self.deny.is_match(path) {
                    return Decision::Deny;
                }
                if allow.is_match(path) {
                    return Decision::Allow;
                }
                // Ancestor-traversal check: allow stat/open on any directory
                // that lies on the path to some allowed target.
                // Only relevant for Read (directory traversal).
                if matches!(access, FsAccess::Read)
                    && self
                        .allow_prefixes
                        .iter()
                        .any(|prefix| is_ancestor(path, prefix))
                {
                    return Decision::Allow;
                }
                Decision::Deny
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

fn compile_set(label: &str, patterns: &[String]) -> Result<GlobSet, PolicyError> {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        let expanded = expand_pattern(p);
        let glob = Glob::new(&expanded).map_err(|e| PolicyError::Glob {
            pat: p.clone(),
            source: e,
        })?;
        b.add(glob);
        // A directory pattern like `/foo/bar` (no trailing `/**`) should also
        // match descendants, so add `/foo/bar/**` alongside.
        if !expanded.ends_with("/**") && !expanded.contains('*') && !expanded.contains('?') {
            let descendants = format!("{expanded}/**");
            let glob = Glob::new(&descendants).map_err(|e| PolicyError::Glob {
                pat: descendants.clone(),
                source: e,
            })?;
            b.add(glob);
        }
    }
    b.build().map_err(|e| PolicyError::Glob {
        pat: label.to_string(),
        source: e,
    })
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
    use crate::grant::FsAllow;
    use std::path::PathBuf;

    fn cfg(mode: PolicyMode, allow: &[&str], deny: &[&str]) -> FsConfig {
        FsConfig {
            mode,
            allow: allow
                .iter()
                .map(|s| FsAllow {
                    glob: s.to_string(),
                    mode: act_types::FsMode::Rw,
                })
                .collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn deny_mode_blocks_everything() {
        let m = FsMatcher::compile(&cfg(PolicyMode::Deny, &[], &[])).unwrap();
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/anything"), FsAccess::Read),
            Decision::Deny
        );
    }

    #[test]
    fn open_mode_allows_everything() {
        let m = FsMatcher::compile(&cfg(PolicyMode::Open, &[], &[])).unwrap();
        assert_eq!(
            m.decide(&PathBuf::from("/etc/passwd"), FsAccess::Read),
            Decision::Allow
        );
    }

    #[test]
    fn allow_literal_path_matches_descendants() {
        let m = FsMatcher::compile(&cfg(PolicyMode::Allowlist, &["/tmp/work"], &[])).unwrap();
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/work"), FsAccess::Read),
            Decision::Allow
        );
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/work/sub/file.txt"), FsAccess::Read),
            Decision::Allow
        );
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/other"), FsAccess::Read),
            Decision::Deny
        );
    }

    #[test]
    fn allow_trailing_double_star_matches_descendants() {
        let m = FsMatcher::compile(&cfg(PolicyMode::Allowlist, &["/tmp/work/**"], &[])).unwrap();
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/work/sub/file.txt"), FsAccess::Read),
            Decision::Allow
        );
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/other"), FsAccess::Read),
            Decision::Deny
        );
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
            m.decide(&PathBuf::from("/home/alex/project/main.rs"), FsAccess::Read),
            Decision::Allow
        );
        assert_eq!(
            m.decide(&PathBuf::from("/home/alex/.ssh/id_rsa"), FsAccess::Read),
            Decision::Deny
        );
        assert_eq!(
            m.decide(
                &PathBuf::from("/home/alex/.aws/credentials"),
                FsAccess::Read
            ),
            Decision::Deny
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
            m.decide(
                &PathBuf::from("/home/alex/projects/foo/lib.rs"),
                FsAccess::Read
            ),
            Decision::Allow
        );
        assert_eq!(
            m.decide(
                &PathBuf::from("/home/alex/work/docs/README.md"),
                FsAccess::Read
            ),
            Decision::Allow
        );
        assert_eq!(
            m.decide(&PathBuf::from("/home/alex/Downloads/x"), FsAccess::Read),
            Decision::Deny
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
            m.decide(&PathBuf::from("/tmp/work/db.sqlite"), FsAccess::Read),
            Decision::Allow
        );
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/work"), FsAccess::Read),
            Decision::Allow
        );
        assert_eq!(
            m.decide(&PathBuf::from("/tmp"), FsAccess::Read),
            Decision::Allow
        );
        assert_eq!(
            m.decide(&PathBuf::from("/"), FsAccess::Read),
            Decision::Allow
        );
        // Sibling dir not on the path — still denied.
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/other"), FsAccess::Read),
            Decision::Deny
        );
        assert_eq!(
            m.decide(&PathBuf::from("/var"), FsAccess::Read),
            Decision::Deny
        );
    }

    #[test]
    fn ancestor_of_glob_literal_prefix_is_traversable() {
        let m =
            FsMatcher::compile(&cfg(PolicyMode::Allowlist, &["/tmp/work/**/*.db"], &[])).unwrap();
        // Literal prefix is /tmp/work. Ancestors allowed.
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/work"), FsAccess::Read),
            Decision::Allow
        );
        assert_eq!(
            m.decide(&PathBuf::from("/tmp"), FsAccess::Read),
            Decision::Allow
        );
        // A .db inside is allowed by the glob.
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/work/a/b.db"), FsAccess::Read),
            Decision::Allow
        );
        // Non-.db file below is NOT allowed — ancestor rule only covers
        // *reaching* the allowed target, not reading siblings.
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/work/a/b.txt"), FsAccess::Read),
            Decision::Deny
        );
    }

    #[test]
    fn ancestor_does_not_leak_past_first_glob_component() {
        // `/tmp/*.db` — the literal prefix is `/tmp`. Ancestors of that
        // (i.e. `/`) are traversable, but so is `/tmp` itself. What
        // shouldn't leak: a sibling of the glob target.
        let m = FsMatcher::compile(&cfg(PolicyMode::Allowlist, &["/tmp/*.db"], &[])).unwrap();
        assert_eq!(
            m.decide(&PathBuf::from("/tmp"), FsAccess::Read),
            Decision::Allow
        );
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/foo.db"), FsAccess::Read),
            Decision::Allow
        );
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/foo.txt"), FsAccess::Read),
            Decision::Deny
        );
    }

    #[test]
    fn extension_glob() {
        let m = FsMatcher::compile(&cfg(PolicyMode::Allowlist, &["/tmp/**/*.md"], &[])).unwrap();
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/notes/today.md"), FsAccess::Read),
            Decision::Allow
        );
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/notes/secret.txt"), FsAccess::Read),
            Decision::Deny
        );
    }

    #[test]
    fn ask_mode_defers_in_ceiling_paths() {
        // In Ask mode the matcher prompts (returns `Ask`) for paths inside the
        // declared ceiling, and hard-denies paths outside it (no prompt).
        let m = FsMatcher::compile(&cfg(PolicyMode::Ask, &["/tmp/**"], &[])).unwrap();
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/x"), FsAccess::Read),
            Decision::Ask
        );
        assert_eq!(
            m.decide(&PathBuf::from("/etc/passwd"), FsAccess::Read),
            Decision::Deny
        );
    }

    #[test]
    fn ask_mode_is_bounded_by_allow_ceiling() {
        // mode=Ask with allow=["/data/**"]: in-ceiling -> Ask (prompt),
        // out-of-ceiling -> Deny (no prompt). This is the security ceiling:
        // a path the component never declared must never even reach the
        // operator as a prompt.
        let m = FsMatcher::compile(&cfg(PolicyMode::Ask, &["/data/**"], &[])).unwrap();
        assert_eq!(
            m.decide(&PathBuf::from("/data/x"), FsAccess::Read),
            Decision::Ask
        );
        assert_eq!(
            m.decide(&PathBuf::from("/etc/passwd"), FsAccess::Read),
            Decision::Deny
        );
    }

    #[test]
    fn ask_mode_deny_rule_beats_ceiling() {
        // A deny rule wins over the ceiling even in Ask mode (no prompt).
        let m = FsMatcher::compile(&cfg(PolicyMode::Ask, &["/data/**"], &["/data/secrets/**"]))
            .unwrap();
        assert_eq!(
            m.decide(&PathBuf::from("/data/ok"), FsAccess::Read),
            Decision::Ask
        );
        assert_eq!(
            m.decide(&PathBuf::from("/data/secrets/key"), FsAccess::Read),
            Decision::Deny
        );
    }

    #[test]
    fn ask_mode_empty_ceiling_denies_everything() {
        // No declared paths → nothing is in the ceiling → every path denied
        // without prompting.
        let m = FsMatcher::compile(&cfg(PolicyMode::Ask, &[], &[])).unwrap();
        assert_eq!(
            m.decide(&PathBuf::from("/etc/passwd"), FsAccess::Read),
            Decision::Deny
        );
        assert_eq!(
            m.decide(&PathBuf::from("/tmp/x"), FsAccess::Read),
            Decision::Deny
        );
    }

    #[test]
    fn ro_entry_denies_write_allows_read() {
        use act_types::FsMode;
        let cfg = FsConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![FsAllow {
                glob: "/data/**".into(),
                mode: FsMode::Ro,
            }],
            deny: vec![],
        };
        let m = FsMatcher::compile(&cfg).unwrap();
        assert_eq!(
            m.decide(Path::new("/data/x.db"), FsAccess::Read),
            Decision::Allow
        );
        assert_eq!(
            m.decide(Path::new("/data/x.db"), FsAccess::Write),
            Decision::Deny
        );
    }

    /// End-to-end ask path: matcher in `Ask` mode defers, and the consent
    /// cache + scripted prompter resolve the verdict (per-path, remembered).
    #[cfg(feature = "host")]
    #[tokio::test]
    async fn ask_decision_resolved_through_consent_cache() {
        use crate::consent::{ConsentAsk, ConsentPrompter, DecisionCache, DenyPrompter};
        use std::sync::Mutex;

        struct Scripted {
            allow_path: String,
            calls: Mutex<usize>,
        }
        #[async_trait::async_trait]
        impl ConsentPrompter for Scripted {
            async fn decide(&self, ask: &ConsentAsk) -> bool {
                *self.calls.lock().unwrap() += 1;
                ask.key == self.allow_path
            }
        }

        // Ceiling covers both probed paths so the matcher defers (returns
        // `Ask`); the consent layer then resolves the per-path verdict.
        let m = FsMatcher::compile(&cfg(PolicyMode::Ask, &["/data/**", "/etc/**"], &[])).unwrap();
        let cache = DecisionCache::new();
        let p = Scripted {
            allow_path: "/data/ok".to_string(),
            calls: Mutex::new(0),
        };

        let mk_ask = |path: &str| ConsentAsk {
            cap_id: "wasi:filesystem".to_string(),
            key: path.to_string(),
            summary: format!("filesystem access: {path}"),
        };

        // Allowed path: matcher defers, prompt allows, repeat is cached.
        assert_eq!(
            m.decide(&PathBuf::from("/data/ok"), FsAccess::Read),
            Decision::Ask
        );
        assert!(cache.decide_cached(&p, mk_ask("/data/ok")).await);
        assert!(cache.decide_cached(&p, mk_ask("/data/ok")).await);
        assert_eq!(*p.calls.lock().unwrap(), 1, "second access must be cached");

        // Different, unscripted path: matcher defers, prompt denies.
        assert_eq!(
            m.decide(&PathBuf::from("/etc/shadow"), FsAccess::Read),
            Decision::Ask
        );
        assert!(!cache.decide_cached(&p, mk_ask("/etc/shadow")).await);

        // No channel → degrade ask to deny even for the otherwise-allowed path.
        let deny_cache = DecisionCache::new();
        assert!(
            !deny_cache
                .decide_cached(&DenyPrompter, mk_ask("/data/ok"))
                .await
        );
    }
}
