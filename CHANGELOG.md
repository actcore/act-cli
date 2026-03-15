# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
