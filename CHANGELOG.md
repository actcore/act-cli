# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
