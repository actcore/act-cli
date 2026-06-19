//! Layer 1 phase C1, part 2/2: custom `wasi:filesystem` host impl that gates
//! `open_at` (and path-taking siblings) on the `FsMatcher`.
//!
//! The host-facing surface:
//! - `PolicyFilesystem` is a `HasData` marker used in place of the default
//!   `wasmtime_wasi::WasiFilesystem` when adding the `wasi:filesystem/types`
//!   and `wasi:filesystem/preopens` interfaces to the linker.
//! - `PolicyFilesystemCtxView<'a>` bundles the default `WasiFilesystemCtx`,
//!   the `ResourceTable`, the compiled `FsMatcher`, and a running map of
//!   `fd → absolute host path`. It implements `preopens::Host`, `types::Host`,
//!   `HostDescriptor`, and `HostDirectoryEntryStream`, mostly by delegating
//!   to a temp `WasiFilesystemCtxView` constructed from the same fields.
//! - Path-taking methods (`open_at`, `stat_at`, `readlink_at`,
//!   `create_directory_at`, `remove_directory_at`, `unlink_file_at`,
//!   `rename_at`, `link_at`, `symlink_at`, `metadata_hash_at`,
//!   `set_times_at`) resolve the parent fd's host path, join the
//!   guest-supplied relative path, canonicalise, and consult the matcher.
//!   Deny → `ErrorCode::NotPermitted`; allow → delegate and (for `open_at`)
//!   record the resulting fd's host path.
//!
//! fd→path tracking:
//! - Preopens are recorded at construction (we know their host paths from
//!   `derive_preopens` before calling `WasiCtxBuilder::preopened_dir`).
//!   Their Resource reps aren't known at that point; we match reps to host
//!   paths lazily the first time `get_directories()` is called.
//! - New descriptors produced by `open_at` are recorded with the
//!   canonicalised child path.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use path_clean::PathClean;
use wasmtime::component::{HasData, Resource, ResourceTable};
use wasmtime_wasi::filesystem::{WasiFilesystemCtx, WasiFilesystemCtxView};
use wasmtime_wasi::p2::bindings::filesystem::preopens;
use wasmtime_wasi::p2::bindings::filesystem::types::{
    self, ErrorCode, HostDescriptor, HostDirectoryEntryStream,
};
use wasmtime_wasi::p2::{DynInputStream, DynOutputStream, FsError, FsResult};

use act_types::{Capabilities, MountType};

use crate::config::PolicyMode;
use crate::runtime::consent::{ConsentAsk, ConsentPrompter, ConsentRisk, DecisionCache};
use crate::runtime::fs_matcher::{FsDecision, FsMatcher};

// ── Mounts → preopens ─────────────────────────────────────────────────────

/// A (guest path → host path) pair handed to wasmtime-wasi's `preopened_dir`.
///
/// With the virtual-root policy model the guest always sees the whole host
/// filesystem at `/` (Unix) or at `/c`, `/d`, ... (Windows drives); the
/// `FsMatcher` gates per-op access. These records are the bridge between
/// config and the wasmtime setup code.
#[derive(Debug, Clone, PartialEq)]
pub struct Preopen {
    pub guest: String,
    pub host: PathBuf,
}

/// A resolved mount: concrete guest path + (for binds) an expanded host dir.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedMount {
    pub kind: MountType,
    pub guest: String,
    /// Expanded host directory for `bind`; `None` for `root`.
    pub host: Option<PathBuf>,
}

/// Resolve a component's declared mounts into concrete topology.
///
/// Order: explicit `params.mounts`, then `mount-root` sugar (a `root` mount,
/// skipped if an explicit `root` mount already exists), then a default `root`
/// mount when nothing else is declared. Returns empty under `Deny` (the guest
/// can name nothing).
pub fn resolve_mounts(caps: &Capabilities, mode: PolicyMode) -> Vec<ResolvedMount> {
    if mode == PolicyMode::Deny {
        return Vec::new();
    }
    let declared = caps.fs_mounts().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "ignoring malformed wasi:filesystem mounts");
        Vec::new()
    });
    let has_explicit_root = declared.iter().any(|m| m.kind == MountType::Root);

    let mut out = Vec::new();
    for m in &declared {
        match m.kind {
            MountType::Bind => {
                if let (Some(g), Some(h)) = (m.guest.as_deref(), m.host.as_deref()) {
                    out.push(ResolvedMount {
                        kind: MountType::Bind,
                        guest: g.to_string(),
                        host: Some(expand_host_dir(h)),
                    });
                }
            }
            MountType::Root => out.push(ResolvedMount {
                kind: MountType::Root,
                guest: m.guest.as_deref().unwrap_or("/").to_string(),
                host: None,
            }),
        }
    }

    // mount-root sugar → a root mount. "/" and "" are treated as no-ops (NOT a
    // whole-fs root): a degenerate mount-root must never silently expose the
    // entire host filesystem next to declared binds. Use an explicit
    // `{type = "root"}` mount to combine whole-fs with binds.
    if !has_explicit_root
        && let Some(mr) = caps.fs_mount_root()
        && mr != "/"
        && !mr.is_empty()
    {
        out.push(ResolvedMount {
            kind: MountType::Root,
            guest: mr.to_string(),
            host: None,
        });
    }

    if out.is_empty() {
        out.push(ResolvedMount {
            kind: MountType::Root,
            guest: "/".to_string(),
            host: None,
        });
    }
    out
}

/// Expand `~` and make a host directory path absolute (no glob handling — this
/// is a directory, not a matcher pattern).
fn expand_host_dir(s: &str) -> PathBuf {
    let expanded = shellexpand::tilde(s).into_owned();
    let p = PathBuf::from(&expanded);
    if p.is_absolute() {
        p
    } else {
        std::env::current_dir().map(|c| c.join(&p)).unwrap_or(p)
    }
}

/// Build the preopen list from resolved mounts.
pub fn derive_preopens(mounts: &[ResolvedMount]) -> Vec<Preopen> {
    let mut out = Vec::new();
    for m in mounts {
        match m.kind {
            MountType::Bind => {
                if let Some(host) = &m.host {
                    out.push(Preopen {
                        guest: m.guest.clone(),
                        host: host.clone(),
                    });
                }
            }
            MountType::Root => out.extend(root_preopens_under(&m.guest)),
        }
    }
    out
}

/// Create missing `bind` host directories so they can be preopened. `root`
/// mounts point at the platform root and create nothing.
pub fn create_mount_dirs(mounts: &[ResolvedMount]) -> std::io::Result<()> {
    for m in mounts {
        if m.kind == MountType::Bind
            && let Some(host) = &m.host
        {
            std::fs::create_dir_all(host)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn root_preopens_under(guest: &str) -> Vec<Preopen> {
    vec![Preopen {
        guest: guest.to_string(),
        host: PathBuf::from("/"),
    }]
}

#[cfg(windows)]
fn root_preopens_under(guest: &str) -> Vec<Preopen> {
    let base = guest.trim_end_matches('/');
    let mut out = Vec::new();
    for letter in b'A'..=b'Z' {
        let c = letter as char;
        let host = PathBuf::from(format!("{}:\\", c));
        if std::fs::metadata(&host).is_ok() {
            let g = if base.is_empty() {
                format!("/{}", c.to_ascii_lowercase())
            } else {
                format!("{}/{}", base, c.to_ascii_lowercase())
            };
            out.push(Preopen { guest: g, host });
        }
    }
    out
}

#[cfg(not(any(unix, windows)))]
fn root_preopens_under(guest: &str) -> Vec<Preopen> {
    vec![Preopen {
        guest: guest.to_string(),
        host: PathBuf::from("/"),
    }]
}

// ── Wasmtime host impl ────────────────────────────────────────────────────

/// `HasData` marker for our policy-aware filesystem view.
pub struct PolicyFilesystem;

impl HasData for PolicyFilesystem {
    type Data<'a> = PolicyFilesystemCtxView<'a>;
}

/// Per-call view bundling all state the policy wrapper needs.
pub struct PolicyFilesystemCtxView<'a> {
    pub ctx: &'a mut WasiFilesystemCtx,
    pub table: &'a mut ResourceTable,
    pub matcher: &'a FsMatcher,
    pub fd_paths: &'a mut FdPathMap,
    /// Configured mode; drives the p3 preopens kill-switch. p3 path-taking
    /// ops can't be gated (upstream `Dir::open_at` is `pub(crate)`), so when
    /// mode is anything but `Open` we return zero preopens from p3 and p3
    /// guests can't acquire a `Descriptor::Dir` handle at all.
    pub mode: PolicyMode,
    /// Interactive-consent prompter, consulted when the matcher returns
    /// `FsDecision::Ask`. Shared across the store.
    pub prompter: Arc<dyn ConsentPrompter>,
    /// Per-session memory of ask decisions, keyed by `(cap-id, path)`.
    pub cache: Arc<DecisionCache>,
}

/// Tracks the host path associated with each open filesystem descriptor,
/// plus the configured preopen list (guest path → host path) used to fill
/// in the map lazily the first time the guest calls `get-directories`.
#[derive(Default, Debug)]
pub struct FdPathMap {
    pub preopens: Vec<(String, PathBuf)>,
    pub by_rep: HashMap<u32, PathBuf>,
}

/// Sync matcher outcome for one path op. `Deny` is folded into the `Err` arm
/// of `check_path_sync`; `Ask` carries owned `Arc` clones so the async prompt
/// resolution never borrows the (`!Sync`) view.
enum PathDecision {
    Allow(PathBuf),
    Ask {
        canonical: PathBuf,
        cache: Arc<DecisionCache>,
        prompter: Arc<dyn ConsentPrompter>,
    },
}

/// Resolve an `Ask`-mode filesystem decision via the interactive prompter
/// (cached per canonical path). Free function over owned data so the returned
/// future is `Send` (it captures only `Arc`s + a `PathBuf`, never the view).
async fn resolve_ask(
    cache: Arc<DecisionCache>,
    prompter: Arc<dyn ConsentPrompter>,
    canonical: PathBuf,
) -> FsResult<PathBuf> {
    let path = canonical.display().to_string();
    let allowed = cache
        .decide_cached(
            &*prompter,
            ConsentAsk {
                cap_id: act_types::constants::CAP_FILESYSTEM.to_string(),
                key: path.clone(),
                summary: format!("filesystem access: {path}"),
                risk: ConsentRisk::Normal,
            },
        )
        .await;
    if allowed {
        Ok(canonical)
    } else {
        tracing::warn!(path = %path, "fs policy: ask denied");
        Err(ErrorCode::NotPermitted.into())
    }
}

impl<'a> PolicyFilesystemCtxView<'a> {
    fn inner(&mut self) -> WasiFilesystemCtxView<'_> {
        WasiFilesystemCtxView {
            ctx: self.ctx,
            table: self.table,
        }
    }

    fn parent_path(&self, fd: &Resource<types::Descriptor>) -> Option<PathBuf> {
        self.fd_paths.by_rep.get(&fd.rep()).cloned()
    }

    /// Resolve `(parent_fd, rel_path)` to an absolute canonical host path and
    /// run it through the matcher. Returns `Ok(canonical)` on allow,
    /// `Err(NotPermitted)` on deny. In `Ask` mode the matcher defers and we
    /// resolve the verdict through the interactive consent prompter (cached
    /// per path). Records the resolved path for the caller to associate with a
    /// newly-opened fd if desired.
    ///
    /// This is the async entry point used by every path-taking method. It must
    /// NOT hold a borrow of `self` across the `.await` (the host descriptor
    /// futures must be `Send`, and `&PolicyFilesystemCtxView` is not `Sync`),
    /// so it is a *sync* fn that performs the matcher decision (borrowing
    /// `self`) and then returns a `Send` future that captures only owned data
    /// (`Arc` clones + the path) — never `self`.
    fn check_path(
        &self,
        parent_fd: &Resource<types::Descriptor>,
        rel: &str,
    ) -> impl Future<Output = FsResult<PathBuf>> + Send + 'static {
        let decision = self.check_path_sync(parent_fd, rel);
        async move {
            match decision? {
                PathDecision::Allow(canonical) => Ok(canonical),
                PathDecision::Ask {
                    canonical,
                    cache,
                    prompter,
                } => resolve_ask(cache, prompter, canonical).await,
            }
        }
    }

    /// Synchronous part of `check_path`: resolve + matcher decision. Borrows
    /// `self` but never awaits, so the borrow ends before `check_path`'s await.
    fn check_path_sync(
        &self,
        parent_fd: &Resource<types::Descriptor>,
        rel: &str,
    ) -> FsResult<PathDecision> {
        let Some(parent) = self.parent_path(parent_fd) else {
            // Parent fd has no tracked path — belongs to an unknown preopen
            // or was never witnessed. Deny conservatively.
            tracing::warn!(fd = parent_fd.rep(), "fs policy: untracked parent fd");
            return Err(ErrorCode::NotPermitted.into());
        };
        let canonical = parent.join(rel).clean();
        match self.matcher.decide(&canonical) {
            FsDecision::Allow => Ok(PathDecision::Allow(canonical)),
            FsDecision::Deny => {
                tracing::warn!(path = %canonical.display(), "fs policy: blocked");
                Err(ErrorCode::NotPermitted.into())
            }
            FsDecision::Ask => Ok(PathDecision::Ask {
                canonical,
                cache: self.cache.clone(),
                prompter: self.prompter.clone(),
            }),
        }
    }

    /// Called from `get_directories` on first use to align Resource reps with
    /// the host paths we configured at preopen time.
    fn populate_preopens(&mut self, entries: &[(Resource<types::Descriptor>, String)]) {
        for (res, guest_path) in entries {
            if self.fd_paths.by_rep.contains_key(&res.rep()) {
                continue;
            }
            let Some(host) = self
                .fd_paths
                .preopens
                .iter()
                .find(|(g, _)| g == guest_path)
                .map(|(_, h)| h.clone())
            else {
                continue;
            };
            self.fd_paths.by_rep.insert(res.rep(), host);
        }
    }
}

// ── preopens::Host ────────────────────────────────────────────────────────

impl preopens::Host for PolicyFilesystemCtxView<'_> {
    fn get_directories(&mut self) -> wasmtime::Result<Vec<(Resource<types::Descriptor>, String)>> {
        let entries = self.inner().get_directories()?;
        self.populate_preopens(&entries);
        Ok(entries)
    }
}

// ── types::Host ───────────────────────────────────────────────────────────

impl types::Host for PolicyFilesystemCtxView<'_> {
    fn convert_error_code(&mut self, err: FsError) -> wasmtime::Result<ErrorCode> {
        self.inner().convert_error_code(err)
    }
    fn filesystem_error_code(
        &mut self,
        err: Resource<wasmtime::Error>,
    ) -> wasmtime::Result<Option<ErrorCode>> {
        self.inner().filesystem_error_code(err)
    }
}

// ── HostDescriptor ────────────────────────────────────────────────────────
//
// Every method delegates to `self.inner()` after a policy check on
// path-taking methods. Non-path-taking methods operate on an already-opened
// Resource<Descriptor>; access was granted at open_at time so no further
// check is needed.

impl HostDescriptor for PolicyFilesystemCtxView<'_> {
    async fn advise(
        &mut self,
        fd: Resource<types::Descriptor>,
        offset: types::Filesize,
        len: types::Filesize,
        advice: types::Advice,
    ) -> FsResult<()> {
        self.inner().advise(fd, offset, len, advice).await
    }

    async fn sync_data(&mut self, fd: Resource<types::Descriptor>) -> FsResult<()> {
        self.inner().sync_data(fd).await
    }

    async fn get_flags(
        &mut self,
        fd: Resource<types::Descriptor>,
    ) -> FsResult<types::DescriptorFlags> {
        self.inner().get_flags(fd).await
    }

    async fn get_type(
        &mut self,
        fd: Resource<types::Descriptor>,
    ) -> FsResult<types::DescriptorType> {
        self.inner().get_type(fd).await
    }

    async fn set_size(
        &mut self,
        fd: Resource<types::Descriptor>,
        size: types::Filesize,
    ) -> FsResult<()> {
        self.inner().set_size(fd, size).await
    }

    async fn set_times(
        &mut self,
        fd: Resource<types::Descriptor>,
        atim: types::NewTimestamp,
        mtim: types::NewTimestamp,
    ) -> FsResult<()> {
        self.inner().set_times(fd, atim, mtim).await
    }

    async fn read(
        &mut self,
        fd: Resource<types::Descriptor>,
        len: types::Filesize,
        offset: types::Filesize,
    ) -> FsResult<(Vec<u8>, bool)> {
        self.inner().read(fd, len, offset).await
    }

    async fn write(
        &mut self,
        fd: Resource<types::Descriptor>,
        buf: Vec<u8>,
        offset: types::Filesize,
    ) -> FsResult<types::Filesize> {
        self.inner().write(fd, buf, offset).await
    }

    async fn read_directory(
        &mut self,
        fd: Resource<types::Descriptor>,
    ) -> FsResult<Resource<types::DirectoryEntryStream>> {
        self.inner().read_directory(fd).await
    }

    async fn sync(&mut self, fd: Resource<types::Descriptor>) -> FsResult<()> {
        self.inner().sync(fd).await
    }

    async fn create_directory_at(
        &mut self,
        fd: Resource<types::Descriptor>,
        path: String,
    ) -> FsResult<()> {
        let _checked = self.check_path(&fd, &path).await?;
        self.inner().create_directory_at(fd, path).await
    }

    async fn stat(&mut self, fd: Resource<types::Descriptor>) -> FsResult<types::DescriptorStat> {
        self.inner().stat(fd).await
    }

    async fn stat_at(
        &mut self,
        fd: Resource<types::Descriptor>,
        path_flags: types::PathFlags,
        path: String,
    ) -> FsResult<types::DescriptorStat> {
        let _checked = self.check_path(&fd, &path).await?;
        self.inner().stat_at(fd, path_flags, path).await
    }

    async fn set_times_at(
        &mut self,
        fd: Resource<types::Descriptor>,
        path_flags: types::PathFlags,
        path: String,
        atim: types::NewTimestamp,
        mtim: types::NewTimestamp,
    ) -> FsResult<()> {
        let _checked = self.check_path(&fd, &path).await?;
        self.inner()
            .set_times_at(fd, path_flags, path, atim, mtim)
            .await
    }

    async fn link_at(
        &mut self,
        fd: Resource<types::Descriptor>,
        old_path_flags: types::PathFlags,
        old_path: String,
        new_descriptor: Resource<types::Descriptor>,
        new_path: String,
    ) -> FsResult<()> {
        let _old = self.check_path(&fd, &old_path).await?;
        let _new = self.check_path(&new_descriptor, &new_path).await?;
        self.inner()
            .link_at(fd, old_path_flags, old_path, new_descriptor, new_path)
            .await
    }

    async fn open_at(
        &mut self,
        fd: Resource<types::Descriptor>,
        path_flags: types::PathFlags,
        path: String,
        oflags: types::OpenFlags,
        flags: types::DescriptorFlags,
    ) -> FsResult<Resource<types::Descriptor>> {
        let canonical = self.check_path(&fd, &path).await?;
        let new_fd = self
            .inner()
            .open_at(fd, path_flags, path, oflags, flags)
            .await?;
        self.fd_paths.by_rep.insert(new_fd.rep(), canonical);
        Ok(new_fd)
    }

    fn drop(&mut self, fd: Resource<types::Descriptor>) -> wasmtime::Result<()> {
        self.fd_paths.by_rep.remove(&fd.rep());
        HostDescriptor::drop(&mut self.inner(), fd)
    }

    async fn readlink_at(
        &mut self,
        fd: Resource<types::Descriptor>,
        path: String,
    ) -> FsResult<String> {
        let _checked = self.check_path(&fd, &path).await?;
        self.inner().readlink_at(fd, path).await
    }

    async fn remove_directory_at(
        &mut self,
        fd: Resource<types::Descriptor>,
        path: String,
    ) -> FsResult<()> {
        let _checked = self.check_path(&fd, &path).await?;
        self.inner().remove_directory_at(fd, path).await
    }

    async fn rename_at(
        &mut self,
        fd: Resource<types::Descriptor>,
        old_path: String,
        new_fd: Resource<types::Descriptor>,
        new_path: String,
    ) -> FsResult<()> {
        let _old = self.check_path(&fd, &old_path).await?;
        let _new = self.check_path(&new_fd, &new_path).await?;
        self.inner().rename_at(fd, old_path, new_fd, new_path).await
    }

    async fn symlink_at(
        &mut self,
        fd: Resource<types::Descriptor>,
        src_path: String,
        dest_path: String,
    ) -> FsResult<()> {
        let _checked = self.check_path(&fd, &dest_path).await?;
        self.inner().symlink_at(fd, src_path, dest_path).await
    }

    async fn unlink_file_at(
        &mut self,
        fd: Resource<types::Descriptor>,
        path: String,
    ) -> FsResult<()> {
        let _checked = self.check_path(&fd, &path).await?;
        self.inner().unlink_file_at(fd, path).await
    }

    fn read_via_stream(
        &mut self,
        fd: Resource<types::Descriptor>,
        offset: types::Filesize,
    ) -> FsResult<Resource<DynInputStream>> {
        self.inner().read_via_stream(fd, offset)
    }

    fn write_via_stream(
        &mut self,
        fd: Resource<types::Descriptor>,
        offset: types::Filesize,
    ) -> FsResult<Resource<DynOutputStream>> {
        self.inner().write_via_stream(fd, offset)
    }

    fn append_via_stream(
        &mut self,
        fd: Resource<types::Descriptor>,
    ) -> FsResult<Resource<DynOutputStream>> {
        self.inner().append_via_stream(fd)
    }

    async fn is_same_object(
        &mut self,
        a: Resource<types::Descriptor>,
        b: Resource<types::Descriptor>,
    ) -> wasmtime::Result<bool> {
        self.inner().is_same_object(a, b).await
    }

    async fn metadata_hash(
        &mut self,
        fd: Resource<types::Descriptor>,
    ) -> FsResult<types::MetadataHashValue> {
        self.inner().metadata_hash(fd).await
    }

    async fn metadata_hash_at(
        &mut self,
        fd: Resource<types::Descriptor>,
        path_flags: types::PathFlags,
        path: String,
    ) -> FsResult<types::MetadataHashValue> {
        let _checked = self.check_path(&fd, &path).await?;
        self.inner().metadata_hash_at(fd, path_flags, path).await
    }
}

// ── p3 preopens kill-switch ───────────────────────────────────────────────
//
// We can't mirror the full p2 matcher on p3 because `Dir::open_at` and
// friends are `pub(crate)` in wasmtime-wasi — shadowing `HostDescriptorWithStore`
// would need to reproject the Accessor via a `U: WasiFilesystemView` bound
// that the trait doesn't permit, and the sibling methods we'd need to call
// directly (`dir.open_at`, `dir.as_dir`) are gated.
//
// Instead we gate at preopens: if fs mode is anything other than `Open`,
// p3 `get_directories` returns an empty vec. A p3 guest with an empty
// preopen list can't construct a `Descriptor::Dir` resource, so every
// p3 path op fails before it reaches cap-std. Components that genuinely
// need p3 filesystem access must run under `policy.filesystem = "open"`.

impl wasmtime_wasi::p3::bindings::filesystem::preopens::Host for PolicyFilesystemCtxView<'_> {
    fn get_directories(
        &mut self,
    ) -> wasmtime::Result<
        Vec<(
            Resource<wasmtime_wasi::p3::bindings::filesystem::types::Descriptor>,
            String,
        )>,
    > {
        if self.mode != PolicyMode::Open {
            tracing::warn!(
                mode = ?self.mode,
                "p3 wasi:filesystem/preopens: returning empty; p3 path ops can't be matcher-gated",
            );
            return Ok(vec![]);
        }
        let mut inner = WasiFilesystemCtxView {
            ctx: self.ctx,
            table: self.table,
        };
        <WasiFilesystemCtxView as wasmtime_wasi::p3::bindings::filesystem::preopens::Host>::get_directories(&mut inner)
    }
}

// ── HostDirectoryEntryStream ──────────────────────────────────────────────

impl HostDirectoryEntryStream for PolicyFilesystemCtxView<'_> {
    async fn read_directory_entry(
        &mut self,
        stream: Resource<types::DirectoryEntryStream>,
    ) -> FsResult<Option<types::DirectoryEntry>> {
        self.inner().read_directory_entry(stream).await
    }

    fn drop(&mut self, stream: Resource<types::DirectoryEntryStream>) -> wasmtime::Result<()> {
        HostDirectoryEntryStream::drop(&mut self.inner(), stream)
    }
}

#[cfg(test)]
mod mount_tests {
    use super::*;
    use crate::config::PolicyMode;
    use act_types::{Capabilities, CapabilityRequest, MountType};
    use std::collections::BTreeMap;

    fn caps_with_mounts(mounts: serde_json::Value) -> Capabilities {
        let mut caps = Capabilities::default();
        let mut params = BTreeMap::new();
        params.insert("mounts".to_string(), mounts);
        caps.0.insert(
            "wasi:filesystem".into(),
            CapabilityRequest {
                params,
                ..Default::default()
            },
        );
        caps
    }

    #[test]
    fn deny_mode_yields_no_mounts() {
        let caps = caps_with_mounts(serde_json::json!([{ "guest": "/ows", "host": "/tmp/x" }]));
        assert!(resolve_mounts(&caps, PolicyMode::Deny).is_empty());
    }

    #[test]
    fn bind_only_component_gets_just_the_bind_preopen() {
        let caps = caps_with_mounts(serde_json::json!([{ "guest": "/ows", "host": "/tmp/x" }]));
        let mounts = resolve_mounts(&caps, PolicyMode::Ask);
        let pre = derive_preopens(&mounts);
        assert_eq!(pre.len(), 1);
        assert_eq!(pre[0].guest, "/ows");
        assert_eq!(pre[0].host, std::path::PathBuf::from("/tmp/x"));
    }

    #[test]
    fn no_mounts_declared_defaults_to_root() {
        let caps = Capabilities::default();
        let mounts = resolve_mounts(&caps, PolicyMode::Allowlist);
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].kind, MountType::Root);
        assert_eq!(mounts[0].guest, "/");
    }

    #[cfg(unix)]
    #[test]
    fn root_mount_preopens_the_filesystem_root() {
        let caps = caps_with_mounts(serde_json::json!([{ "type": "root", "guest": "/" }]));
        let pre = derive_preopens(&resolve_mounts(&caps, PolicyMode::Open));
        assert_eq!(pre.len(), 1);
        assert_eq!(pre[0].guest, "/");
        assert_eq!(pre[0].host, std::path::PathBuf::from("/"));
    }

    #[test]
    fn mount_root_sugar_becomes_a_root_mount() {
        let mut caps = Capabilities::default();
        let mut params = BTreeMap::new();
        params.insert("mount-root".to_string(), serde_json::json!("/data"));
        caps.0.insert(
            "wasi:filesystem".into(),
            CapabilityRequest {
                params,
                ..Default::default()
            },
        );
        let mounts = resolve_mounts(&caps, PolicyMode::Allowlist);
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].kind, MountType::Root);
        assert_eq!(mounts[0].guest, "/data");
    }

    #[test]
    fn mount_root_slash_is_noop_with_binds() {
        // A degenerate `mount-root = "/"` alongside binds must NOT silently add a
        // whole-fs root mount — the guest gets only the declared bind.
        let mut caps = Capabilities::default();
        let mut params = BTreeMap::new();
        params.insert(
            "mounts".to_string(),
            serde_json::json!([{ "guest": "/ows", "host": "/tmp/x" }]),
        );
        params.insert("mount-root".to_string(), serde_json::json!("/"));
        caps.0.insert(
            "wasi:filesystem".into(),
            CapabilityRequest {
                params,
                ..Default::default()
            },
        );
        let mounts = resolve_mounts(&caps, PolicyMode::Ask);
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].kind, MountType::Bind);
        assert_eq!(mounts[0].guest, "/ows");
    }

    #[test]
    fn explicit_root_suppresses_mount_root_sugar() {
        // An explicit `{type = "root"}` mount suppresses the mount-root sugar
        // entirely — `/data` is NOT added.
        let mut caps = Capabilities::default();
        let mut params = BTreeMap::new();
        params.insert(
            "mounts".to_string(),
            serde_json::json!([{ "type": "root", "guest": "/x" }]),
        );
        params.insert("mount-root".to_string(), serde_json::json!("/data"));
        caps.0.insert(
            "wasi:filesystem".into(),
            CapabilityRequest {
                params,
                ..Default::default()
            },
        );
        let mounts = resolve_mounts(&caps, PolicyMode::Allowlist);
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].kind, MountType::Root);
        assert_eq!(mounts[0].guest, "/x");
    }

    #[test]
    fn tilde_in_bind_host_is_expanded() {
        let caps = caps_with_mounts(serde_json::json!([{ "guest": "/ows", "host": "~/.ows" }]));
        let mounts = resolve_mounts(&caps, PolicyMode::Ask);
        let host = mounts[0].host.clone().unwrap();
        assert!(host.is_absolute());
        assert!(!host.to_string_lossy().starts_with('~'));
    }

    #[test]
    fn create_mount_dirs_makes_bind_targets() {
        let tmp = std::env::temp_dir().join(format!("act-mount-test-{}", std::process::id()));
        let target = tmp.join("nested");
        let mounts = vec![ResolvedMount {
            kind: MountType::Bind,
            guest: "/d".into(),
            host: Some(target.clone()),
        }];
        create_mount_dirs(&mounts).unwrap();
        assert!(target.is_dir());
        std::fs::remove_dir_all(&tmp).ok();
    }
}
