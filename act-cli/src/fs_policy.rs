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
//!   `FsConfig::preopens()` before calling `WasiCtxBuilder::preopened_dir`).
//!   Their Resource reps aren't known at that point; we match reps to host
//!   paths lazily the first time `get_directories()` is called.
//! - New descriptors produced by `open_at` are recorded with the
//!   canonicalised child path.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use wasmtime::component::{HasData, Resource, ResourceTable};
use wasmtime_wasi::filesystem::{WasiFilesystemCtx, WasiFilesystemCtxView};
use wasmtime_wasi::p2::bindings::filesystem::preopens;
use wasmtime_wasi::p2::bindings::filesystem::types::{
    self, ErrorCode, HostDescriptor, HostDirectoryEntryStream,
};
use wasmtime_wasi::p2::{DynInputStream, DynOutputStream, FsError, FsResult};

use crate::fs_matcher::{FsDecision, FsMatcher};

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
}

/// Tracks the host path associated with each open filesystem descriptor,
/// plus the configured preopen list (guest path → host path) used to fill
/// in the map lazily the first time the guest calls `get-directories`.
#[derive(Default, Debug)]
pub struct FdPathMap {
    pub preopens: Vec<(String, PathBuf)>,
    pub by_rep: HashMap<u32, PathBuf>,
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
    /// run it through the matcher. Returns `Ok(())` on allow,
    /// `Err(NotPermitted)` on deny. Records the resolved path for the
    /// caller to associate with a newly-opened fd if desired.
    fn check_path(&self, parent_fd: &Resource<types::Descriptor>, rel: &str) -> FsResult<PathBuf> {
        let Some(parent) = self.parent_path(parent_fd) else {
            // Parent fd has no tracked path — belongs to an unknown preopen
            // or was never witnessed. Deny conservatively.
            tracing::warn!(fd = parent_fd.rep(), "fs policy: untracked parent fd");
            return Err(ErrorCode::NotPermitted.into());
        };
        let candidate = parent.join(rel);
        let canonical = canonicalize_lossy(&candidate);
        match self.matcher.decide(&canonical) {
            FsDecision::Allow => Ok(canonical),
            FsDecision::Deny => {
                tracing::warn!(path = %canonical.display(), "fs policy: blocked");
                Err(ErrorCode::NotPermitted.into())
            }
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

/// Collapse `..` / `.` components without touching the filesystem. We don't
/// call `std::fs::canonicalize` because the path may not exist yet (e.g.
/// `create_directory_at` to a new dir). cap-std prevents `..` escape at the
/// actual OS syscall, but we want the matcher to see a stable path.
fn canonicalize_lossy(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            c => out.push(c.as_os_str()),
        }
    }
    out
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
        let _checked = self.check_path(&fd, &path)?;
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
        let _checked = self.check_path(&fd, &path)?;
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
        let _checked = self.check_path(&fd, &path)?;
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
        let _old = self.check_path(&fd, &old_path)?;
        let _new = self.check_path(&new_descriptor, &new_path)?;
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
        let canonical = self.check_path(&fd, &path)?;
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
        let _checked = self.check_path(&fd, &path)?;
        self.inner().readlink_at(fd, path).await
    }

    async fn remove_directory_at(
        &mut self,
        fd: Resource<types::Descriptor>,
        path: String,
    ) -> FsResult<()> {
        let _checked = self.check_path(&fd, &path)?;
        self.inner().remove_directory_at(fd, path).await
    }

    async fn rename_at(
        &mut self,
        fd: Resource<types::Descriptor>,
        old_path: String,
        new_fd: Resource<types::Descriptor>,
        new_path: String,
    ) -> FsResult<()> {
        let _old = self.check_path(&fd, &old_path)?;
        let _new = self.check_path(&new_fd, &new_path)?;
        self.inner().rename_at(fd, old_path, new_fd, new_path).await
    }

    async fn symlink_at(
        &mut self,
        fd: Resource<types::Descriptor>,
        src_path: String,
        dest_path: String,
    ) -> FsResult<()> {
        let _checked = self.check_path(&fd, &dest_path)?;
        self.inner().symlink_at(fd, src_path, dest_path).await
    }

    async fn unlink_file_at(
        &mut self,
        fd: Resource<types::Descriptor>,
        path: String,
    ) -> FsResult<()> {
        let _checked = self.check_path(&fd, &path)?;
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
        let _checked = self.check_path(&fd, &path)?;
        self.inner().metadata_hash_at(fd, path_flags, path).await
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
