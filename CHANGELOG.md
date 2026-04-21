# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.2] - 2026-04-22

### Changed

- **Stdio MCP server now uses the official [`rmcp`](https://docs.rs/rmcp) crate.** `act run <component> --mcp` is a thin bridge over `rmcp::ServerHandler` instead of the previous hand-rolled JSON-RPC dispatcher. No user-visible wire change — Claude Desktop, Cline, and Cursor continue to work unchanged. Enables future MCP features (new content types, streaming-HTTP transport, resources/prompts/sampling) by tracking rmcp upstream.

### Removed

- `act-cli/src/mcp.rs` (384-line hand-rolled JSON-RPC dispatcher). Functionality moved to `src/rmcp_bridge.rs`.

## [0.5.1] - 2026-04-22

### Fixed

- **`--fs-allow` now implicitly grants traversal of ancestor directories**
  on the path to any allowed target. WASI's path-resolver stats every
  intermediate directory when opening nested files; without this, users
  had to list each parent explicitly (`--fs-allow /tmp --fs-allow
  "$DB/**"` just to reach a file under `$DB`). An allow entry for
  `/tmp/work/db.sqlite` now implicitly permits `/tmp/work` and `/tmp`
  for directory traversal — sibling files in those directories remain
  denied.

## [0.5.0] - 2026-04-21

### Added

- **Runtime policy (Layer 1) for outgoing HTTP and filesystem access.** Declarative `allow` / `deny` / `open` modes, configured via `~/.config/act/config.toml` or CLI flags (`--fs-allow`, `--fs-deny`, `--http-allow`, `--http-deny`, `--fs-policy`, `--http-policy`). Filesystem gates every path op through a glob matcher with a virtual-root preopen (Unix: `/`; Windows: one `/c`, `/d`, … per accessible drive). HTTP gates each request by host / scheme / method / port / CIDR and filters DNS-resolved IPs against both deny- and allow-CIDR rules via a reqwest DNS resolver hook. Per-hop redirect policy re-checks each target URL.
- **Enforcing capability declarations.** Components' `[std.capabilities.*]` entries in `act.toml` are now a **ceiling** the host applies to the user's policy — missing declaration or declared-but-empty `allow` is a hard deny regardless of user config. `[std.capabilities."wasi:filesystem"].allow` takes `{path, mode}` entries with `mode = "ro"` / `"rw"`. `[std.capabilities."wasi:http"].allow` takes `{host, scheme?, methods?, ports?}`. Wildcards: `host = "*"` (any host), `path = "**"` (any path). `act-build pack` validates declarations at pack time.
- **reqwest-backed HTTP client** replacing wasmtime-wasi-http's `default_send_request`. Outgoing `wasi:http` requests route through a per-component `ActHttpClient`. Negotiates HTTP/2 via ALPN; HTTP/3 compiles in (`--cfg reqwest_unstable`) but stays dormant pending alt-svc cache warmup. SSE-friendly defaults: HTTP/2 keep-alive pings every 30s, TCP keep-alive, 10-minute idle-pool timeout.
- **Windows long-path support** via an embedded application manifest.
- **READMEs** ship with the `act` and `act-build` release packages.

### Changed

- **Metadata key renamed `[act-component]` → `[act]`** across `Cargo.toml` / `pyproject.toml` / `package.json`. Components must update the one-line key.
- **`act-types` bumped to 0.5** — required for the new `FilesystemAllow` / `HttpAllow` / `FsMode` types.
- **Deny-CIDR denials surface as `DnsError`** instead of `ConnectionRefused` by walking the reqwest error chain. Policy-denied requests are attributable to DNS rather than a refused socket.
- **p3 `wasi:filesystem/preopens` is shadowed** when fs policy is anything other than `open`. Returns zero preopens; p3 guests can't obtain a `Descriptor::Dir` and every path op fails at the default impl. Per-op gating for p3 filesystem awaits upstream wasmtime-wasi API changes.

### Removed

- **Advisory `warn_missing_capabilities` helper** — undeclared capability classes now hard-deny at policy check time, which is a stronger signal than a startup warning.

### Fixed

- `fs.deny` entries no longer silently ignored — unused rules now emit a warning at startup.

## [0.4.0] - 2026-04-18

### Changed

- Upgrade to `act:core@0.3.0`. Host runtime dispatches on the new `tool-result` variant: `streaming(stream<tool-event>)` uses the existing pipe-to-consumer path; `immediate(list<tool-event>)` pushes events directly into the consumer without stream machinery.
- Rename `StreamEvent` → `ToolEvent` throughout the runtime, HTTP, MCP, and CLI code paths.
- Remove the hardcoded 30s stream-consumption timeout; cancellation is now driven by the protocol (dropping the stream reader) or runtime-level interruption (epoch/fuel).
- Bump `act-types` to 0.4 and `wasmparser` / `wasm-encoder` to 0.247.

### Added

- `--version` flag on `act` and `act-build` binaries.

### Fixed

- `publish` CI steps are now idempotent and safe to re-run.

## [0.3.10] - 2026-04-15

### Fixed

- npm packages now preserve executable permissions on binaries (fixes silent failure when running `npx @actcore/act` on CI)
- npm shims (`bin/act`, `bin/act-build`) ensure executable permission before spawning the binary as a fallback

### Changed

- npm release pipeline packs `.tgz` archives before upload to preserve file permissions across artifact transfer
- Per-crate SBOM attestation in release workflow

## [0.3.8] - 2026-04-08

### Changed

- CI/release pipeline refactored into reusable workflows (`build-sbom.yml`, `build-docker.yml`, consolidated `build-pypi.yml` matrix), with stricter job dependencies so a partial build failure can no longer publish a split release across crates.io and PyPI.
- GitHub Release notes now come from `CHANGELOG.md` instead of auto-generated PR lists, so users see the humanized entry.
- Docker and SBOM builds now run on PRs (dry-run) to catch regressions before tag push.
- Explicit `timeout-minutes` added across all CI jobs to surface hangs instead of burning the 6h default.
- `ci.yml` now cancels stacked runs on fast re-pushes via a concurrency group.

### Fixed

- PyPI sdist upload rejection caused by a `License-File` path mismatch in maturin-generated metadata (license files are still shipped inside the sdist).
- SBOM artifact attestation path now matches the per-crate directory layout (`act-build/*.cdx.json`, `act-cli/*.cdx.json`).
- `build-docker.yml` no longer requests permissions its caller can't grant, which was preventing CI jobs from starting.

## [0.3.7] - 2026-04-08

### Fixed

- Release workflow now correctly bundles per-crate CycloneDX SBOMs generated by `cargo cyclonedx`, which previously produced an empty `sbom` artifact and broke the attest job.
- PyPI publish step is now idempotent across release re-runs (`skip-existing: true`) and emits verbose errors on upload failure.

## [0.3.6] - 2026-04-06

### Fixed

- Fix npm CI build failing with `EBADPLATFORM` by replacing `npm version --workspaces` with direct version substitution
- Fix pypi sdist build failing due to `../README.md` path in `pyproject.toml`

## [0.3.4] - 2026-04-03

### Added

- `act-build` crate — build tool for ACT WASM components, sharing the workspace with `act-cli`
- README files for both `act-cli` and `act-build`

### Changed

- MIME-aware display for `act call` output — content parts now rendered according to their MIME type
- Support for nested `ComponentInfo.std` structure
- Workspace metadata (version, license, repository, etc.) unified via `[workspace.package]` inheritance
- All dependencies updated to latest versions; `act-types` switched to 0.3 registry release

### Removed

- Redundant `cargo check` step from CI workflow

## [0.3.2] - 2026-03-29

### Added

- `--http` flag for `act run` — explicit HTTP transport selection, `--listen` now accepts port number or full address
- Universal agent skill (`skills/act/SKILL.md`) — works with Claude Code, Cursor, OpenCode, Codex, OpenClaw via `npx skills add actcore/act-cli`
- SECURITY.md with trusted publishing, SBOM, and sandbox policies
- Snap packaging (experimental)

### Changed

- npm root package moved to `@actcore/act`
- README rewritten with current CLI commands and platform support matrix

### Fixed

- OCI refs with numeric tags (e.g. `ghcr.io/actpkg/sqlite:0.1.0`) now resolved correctly
- Tracing filter uses `act=info` instead of `act_cli=info` to match binary name

## [0.3.1] - 2026-03-26

### Changed

- Publish workflow uses crates.io trusted publishing (OIDC) instead of long-lived API token

### Fixed

- SBOM artifact path in release workflow
- npm publish no longer misinterprets tarball paths as git URLs

## [0.3.0] - 2026-03-26

### Added

- Component references: all commands now accept HTTP/S URLs, OCI registry refs, and local paths (not just file paths). Remote components are cached in `~/.cache/act/components/`
- `act pull` command to download components from OCI registries or HTTP URLs with `-o`/`-O` flags
- `act info --tools --format text|json` for rich component introspection showing `std:skill`, metadata schema, tool annotations, usage hints, and tags
- Progress bars (indicatif) for HTTP and OCI downloads
- CycloneDX SBOM generation and attestation in release workflow

### Changed

- **Breaking:** CLI commands restructured — `serve` → `run -l`, `mcp` → `run --mcp`, `tools` → `info --tools`. Old commands removed.
- `act info` now shows `--format text` (markdown-like, default) or `--format json` (machine-readable)

### Fixed

- macOS setup action now uses separate x86_64/aarch64 binaries instead of removed universal binary

## [0.2.0] - 2026-03-18

### Added

- **Filesystem capabilities**: grant WASM components filesystem access via `--allow-dir guest:host` (directory mode) or `--allow-fs` (full access). Components declare `wasi:filesystem` capability; host warns if not granted.
- **Config file support**: load settings from `~/.config/act/config.toml` with named profiles (`--profile`), filesystem policies, and metadata injection. Override config path with `--config`.
- **`std:fs:mount-root` support**: components declare their preferred guest mount point; host adjusts directory mappings accordingly.
- **Profile metadata merging**: profile metadata merges with per-request metadata (CLI > profile > defaults).

### Changed

- `create_store()` now accepts filesystem configuration for WASI preopened directories.
- HTTP handlers merge base metadata (from profile/CLI) with per-request metadata.
- Switched `act-types` to path dependency for development.

[0.2.0]: https://github.com/actcore/act-cli/compare/0.1.0..0.2.0

## [0.1.0] - 2026-03-15

Initial release of the ACT CLI host — loads WebAssembly components and exposes them via HTTP, MCP, and CLI.

### Added

- `act serve` — serve a component as an ACT-HTTP server
- `act mcp` — serve a component over MCP stdio
- `act call` — invoke a tool directly from the command line
- `act info` — show component metadata (read from `act:component` custom section without instantiation)
- `act tools` — list tools exposed by a component
- HTTP transport with SSE streaming support
- MCP transport with tool annotations mapping
- Component metadata via `--metadata` / `--metadata-file` CLI flags
- CI pipeline with multi-platform builds (Linux, macOS, Windows, RISC-V)
- GitHub Release workflow with artifacts
- Setup action for component e2e testing (`actcore/act-cli/setup@v0`)

[0.1.0]: https://github.com/actcore/act-cli/tree/0.1.0
