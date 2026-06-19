# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - 2026-06-22

This release reworks the capability/sandbox surface into one uniform grant model
and switches to ask-by-default. It is a breaking release — the flag, metadata,
and default-policy changes are called out below.

### Added

- **`act inspect` subcommands.** `act inspect component-manifest --format json`
  dumps the raw `act:component` manifest (used by actpkg.dev for capability
  extraction); `act inspect tools` dumps the raw `list-tools` output.
- **TOON output format** (`--format toon`) for `info`, `store list`, and
  `inspect` — a compact, LLM-friendly encoding (~40% fewer tokens than JSON).
- **Declarative filesystem mounts.** Typed `bind`/`root` mounts declared by a
  component are resolved into wasmtime preopens, converging the legacy
  `mount-root` onto the same path-rewriting model. `act-build` validates declared
  mounts and warns on drift/redundant sugar.

### Changed

- **Uniform capability grant model (breaking).** The per-class
  `--fs-*/--http-*/--sockets-*` flags are replaced by generic, id-keyed grants:
  `--grant '<json>'`, `--allow <id>`, `--deny <id>`. Grants key on a capability
  id (`wasi:filesystem`, `wasi:http`, `wasi:sockets`, or a semantic class) with
  provider-defined constraints, resolving exact > longest `*`-prefix > default
  across the global/profile/CLI layers (default inherits across layers). HTTP
  CIDRs and socket port/protocol scoping are preserved. Built on the uniform
  `act-types` 0.11 capability model.
- **Ask-by-default (breaking).** With no grant, a capability now resolves to
  `ask` (prompt-on-access, remembered per session) instead of a hard deny.
  Interactive runs prompt on the TTY; `--mcp` runs prompt the client over an MCP
  elicitation channel; headless runs with no prompt channel degrade to deny.
  Prompts are bounded by the component's declared ceiling — out-of-ceiling access
  is denied without prompting.
- **`--metadata` split (breaking).** Repeatable `-m key=value` passes string
  metadata; `--metadata-json '<obj>'` passes a typed JSON object.

### Removed

- Per-class capability flags (`--fs-policy/--fs-allow/--fs-deny` and the `http`/
  `sockets` equivalents) and the `ACT_FS_ALLOW`/`ACT_HTTP_ALLOW`/
  `ACT_SOCKETS_ALLOW` env vars — superseded by the uniform grant flags and the
  `[policy]` config section.

## [0.8.4] - 2026-06-17

### Changed

- **`act-store` now follows the unified workspace version.** It was versioned
  independently (last published as `0.1.1`) and is now released in lockstep with
  `act` and `act-build` at `0.8.4`. This unblocks `cargo publish --workspace`,
  which had been aborting because `act-store@0.1.1` already existed on crates.io.

## [0.8.3] - 2026-06-16

### Added

- **`act-build pack --set <key>=<value>`** — override resolved component-metadata
  fields at pack time (e.g. `--set std.name=sqlite-vec`), for feature-conditional builds.

### Changed

- **`act-build init rust`** scaffolds components on **act-sdk 0.9** (lean
  `#[act_component]`, metadata embedded by `act-build pack`) with wit-bindgen 0.58.
- Bundled **`act-types` updated to 0.9** — the shared CBOR↔JSON `$bytes` envelope
  codec is now in the host (`info` / `call` output paths).

## [0.8.2] - 2026-06-11

### Added

- **`--max-memory`** flag (on `run` / `call` / `info`) caps a component's
  WebAssembly linear memory. Accepts a byte count or a size with a unit —
  binary (`512MiB`) or decimal (`512MB`). When a component tries to grow memory
  past the cap, the growth fails inside the sandbox instead of ballooning the
  host process — useful when running untrusted components (e.g. metadata/tool
  extraction with `act info --tools`).

## [0.8.1] - 2026-06-09

### Changed

- `act-build` now lowercases OCI repository names before pushing (tags are
  preserved), so pushes to registries that reject uppercase repositories
  succeed.
- Updated dependencies, including swapping the unmaintained `fs2` file-lock
  crate for `fs4` in `act-store`.

### Fixed

- `act-build validate` no longer rejects valid components. The tool-provider
  interface moved from `act:core` to the `act:tools` package; validate now
  recognizes `act:tools/tool-provider` instead of the obsolete
  `act:core/tool-provider`.
- `act-build` now reports the same manifest digest the registry stores. It
  previously hashed a non-canonical serialization while pushing canonical
  JSON, so digest-pinned pulls 404'd; it now hashes and pushes the identical
  canonical bytes, with a warn-only cross-check against the registry's
  returned digest.

## [0.8.0] - 2026-06-02

### Added

- **`act-store` workspace crate** — a content-addressed OCI image-layout
  component store shared between act-cli and act-toolserver. Resolves remote
  refs read-through, preserves upstream OCI manifests verbatim (so signatures
  remain meaningful), and collects connected artifacts on pull (sigstore
  bundle, SBOM, SLSA provenance, ...) via the OCI 1.1 referrers API. Lives
  at `<XDG_DATA_HOME>/act/store` (`~/.local/share/act/store` on Linux).
  Published to crates.io as a standalone library for downstream consumers.
- **`act store` subcommand group** for managing the local component store:
  - `act store list [--format text|json]` — list every stored component.
  - `act store update [<ref>]` — re-resolve stored refs and re-pull any
    whose upstream digest moved. Without an argument, updates every
    component; mutable tags (`:latest`, `:0.1`) advance, `@sha256:` pins
    never do.
  - `act store gc` — delete store blobs no longer referenced by any
    component.

### Changed

- **Remote refs resolve through the shared store** instead of the bespoke
  `~/.cache/act/components/<sha256(ref)>.wasm` cache. `act run`/`call`/`info`
  read-through the store (pulling on first use, then serving from disk).
  Local files still run in place; the store is populated for them only when
  you explicitly `act pull <file>`.
- **`act pull` now populates the shared store** (with referrer collection
  for OCI sources). `-o`/`-O` still optionally export a copy.
- **Component reference parsing is centralized in `act-store::Ref`** so
  act-cli and act-toolserver agree on how `oci://`, `https://`, `file://`,
  and bare refs are normalized.
- **Release workflow publishes the entire workspace to crates.io**
  (`cargo publish --workspace`), so new crates added anywhere in the
  workspace ship on the next tagged release without a workflow edit.

### Removed

- The legacy `~/.cache/act/components/<sha256(ref)>.wasm` cache is no longer
  written or consulted. Existing cache files are harmless leftovers you can
  delete by hand; act-store starts fresh in its own data dir.

## [0.7.7] - 2026-05-26

### Fixed

- MCP bridge now renders `application/json` and `application/*+json` tool
  output as readable text instead of base64. Components returning `Json<T>`
  previously surfaced unreadable base64 over MCP; JSON content now decodes
  verbatim, matching the ACT-HTTP transport.

## [0.7.6] - 2026-05-26

### Added

- `act run --session-args '<json>'`: pre-open a single session at startup and
  serve the component as "session-of-1". Every call transparently uses the
  pre-opened session, the session machinery is hidden from clients (no MCP
  virtual `open_session`/`close_session` tools, no `/sessions` HTTP endpoints),
  and any client-supplied `std:session-id` is overridden. Requires a component
  that exports `act:sessions/session-provider`. (Previously `--session-args`
  was available only on `act call` for a single invocation.)

## [0.7.5] - 2026-05-25

### Fixed

- `cargo install act-cli` now works without setting
  `RUSTFLAGS='--cfg reqwest_unstable'`. The unused reqwest `http3` feature has
  been dropped (HTTP/2 support is unaffected).

## [0.7.4] - 2026-05-24

### Added

- **`wasi:sockets` sandboxing** — restrict a component's outbound socket
  access with `--sockets-policy`, `--sockets-allow`, and `--sockets-deny`
  (host/CIDR + ports/protocols, e.g. `db:5432/tcp`), configurable via flags,
  the `ACT_SOCKETS_ALLOW` env var, or config profiles. Enforced as a
  capability ceiling in the wasmtime store.
- **`act-build init <lang>`** — scaffold a new component for Rust, Python, or
  JavaScript in one command, with `--output` to choose the target directory
  and ready-to-run test targets.
- **MCP over Streamable HTTP** — serve the MCP adapter over Streamable HTTP
  with `act run <component> --mcp --http`.
- **`file://` component references** — `act run file:///abs/path.wasm` now
  resolves to a local file. An explicit URI scheme (`file://`, `oci://`,
  `http(s)://`) is now authoritative and selects the reference kind directly
  instead of going through path/OCI guessing.

### Changed

- Upgraded dependencies, most notably wasmtime 43 -> 45.
- The MCP bridge now injects a `_meta` argument channel into tool schemas so
  LLM-driven MCP clients can pass `std:session-id` to session-provider
  components.

## [0.7.3] - 2026-05-09

### Added
- `act-build push <wasm> <ref>` — publish a WASM component as a CNCF
  Wasm OCI Artifact. The manifest carries an
  `application/vnd.wasm.config.v0+json` config blob (with
  `architecture`, `os`, `layerDigests`, and `component.{exports,
  imports}` derived from the component's exports/imports) per the
  [CNCF TAG-Runtime Wasm OCI Artifact spec](https://tag-runtime.cncf.io/wgs/wasm/deliverables/wasm-oci-artifact/),
  and the layer is `application/wasm`. Replaces inline `oras push`
  shell blocks in component justfiles.

  Flags: `--also-tag`, `--annotation key=value`, `--source`,
  `--description`, `--skip-if-identical` (matching-content skip /
  drift error), `--skip-if-exists` (unconditional skip for
  non-reproducible builds), `--dry-run`. Output ends with an
  oras-compatible `Digest: sha256:...` line so existing scripts that
  grep for it keep working.

  Auth resolution: `OCI_USERNAME`/`OCI_PASSWORD` env →
  `GITHUB_TOKEN` for ghcr.io → `~/.docker/config.json`
  (`DOCKER_CONFIG` honored) → anonymous.

### Changed
- `act` (host): `resolve_oci` now validates that the OCI layer media
  type is `application/wasm`. Empty/legacy media types log a
  warning; anything else is rejected.

## [0.7.2] - 2026-05-07

### Added
- `act call --session-args '{...}'`. When set, the host opens a
  session against the component before the call (`open-session(args,
  metadata)`), injects the returned id as `std:session-id` metadata
  for the tool call, prints the result, and closes the session
  before exit. The whole open / call / close cycle runs in one
  process, so the wasm instance stays alive for the full sequence.
  This makes session-aware components (bridges, stateful components)
  usable as ordinary one-shot CLI invocations:

  ```bash
  act call ghcr.io/actpkg/openapi-bridge:0.2.0 find_pets_by_status \
    --args '{"status":"sold"}' \
    --session-args '{"spec_url":"https://petstore3.swagger.io/api/v3/openapi.json"}' \
    --http-policy open
  ```

  If the component doesn't export `act:sessions/session-provider`,
  using `--session-args` is a clear error rather than a silent no-op.

## [0.7.1] - 2026-05-07

### Removed
- `act session open` and `act session close` CLI subcommands. They
  inherently can't deliver the primary use case for sessions
  (component-side ephemeral state) — each invocation is a one-shot
  process whose wasm instance dies on exit, so a session opened in
  one `act session open` is unusable from a subsequent `act call`.
  For real session work, use `act run --http` or `act run --mcp`,
  where the host process holds the wasm instance and the session
  lives as long as the host. `act session open-args-schema` stays
  — it's a useful smoke test that doesn't depend on persistent state.

## [0.7.0] - 2026-05-07

Adds first-class support for `act:sessions/session-provider`. Stateful
components (database connections, browser automation, REPLs, the new
`act-http-bridge` / `mcp-bridge` / `openapi-bridge`) can now expose
typed open-session args, and agents address per-session state via
`std:session-id` metadata.

### Added

- `act session open-args-schema | open | close` CLI subcommands.
- ACT-HTTP `/sessions/open-args-schema`, `POST /sessions`, and
  `DELETE /sessions/{id}` endpoints (per ACT-SESSIONS §6.2). Mapped
  to `std:session-not-found → 404` via the bumped act-types.
- MCP transport: synthetic `open_session` / `close_session` tools
  in `tools/list` for components that export session-provider, with
  `_meta.std:session-op` annotations (per ACT-SESSIONS §6.1).
- MCP `_meta.std:session-id` (and any other request-level meta keys)
  is now forwarded into the WIT call metadata so components see the
  agent's session-id.
- Host runtime tracks open session-ids per actor and auto-closes
  them on shutdown (ACT-SESSIONS §2.5).
- `tests/fixtures/sessions-canary.wasm` — hand-rolled canary
  exercising session-provider for host-side integration tests.

### Changed

- Bumped `act-types` 0.5 → 0.7. Drops the inline session HTTP wire
  types from `src/http.rs` in favour of the canonical
  `act_types::http::OpenSessionRequest` / `OpenSessionResponse`.

## [0.6.0] - 2026-04-29

### Breaking — WIT package layout
- World now imports `act:tools/tool-provider@0.1.0` instead of
  `act:core/tool-provider@0.3.0`. Components built against the old WIT
  will not load — rebuild with `act-sdk` 0.6.x (Rust) or `act-sdk-py`
  0.2.x.
- `call-tool` takes flat `(name, arguments, metadata)` instead of a
  `tool-call` record.
- `Error` replaces `ToolError` (the type lives in `act:core/types` now
  and is shared by non-tool providers).

### Added
- `-v` / `-vv` verbosity flag — opt-in plumbing logs (default level
  demoted to `info`).

### Changed
- **MCP transport rewritten on rmcp 1.5**: hand-rolled `src/mcp.rs`
  replaced with a thin `ActRmcpBridge` over the official Anthropic
  crate. Tool discovery, calls, content mapping, and error mapping
  go through `rmcp::model` types. Includes a stdio round-trip
  integration test.
- **`act info` text output restyled** with terminal colors (yellow
  component name, dimmed version, cyan tool names, green annotations).
  Output evaporates to plain text when stdout isn't a TTY or
  `NO_COLOR` is set. Tool parameters show `(optional)` markers; the
  `Option<T>` wrapper is stripped from rendered types.

### Removed
- The `--schema` flag on `act info`, the `/metadata-schema` HTTP
  route, the `metadata_schema` field on `act info` JSON output, and
  the rmcp bridge's metadata-schema fetch/inject path. The WIT
  function is gone in `act:tools@0.1.0`; a discovery mechanism is
  planned for a future minor version.

### Fixed
- `act info --tools --format text` now extracts the real inner type
  from schemars' `Option<T>` JSON Schema instead of rendering the
  union.

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
