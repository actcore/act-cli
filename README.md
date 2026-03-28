# ACT CLI

CLI host for [ACT](https://actcore.dev) (Agent Component Tools) — run WebAssembly component tools from local files, HTTP URLs, or OCI registries.

## Install

```bash
npm i -g @actcore/act        # npm
pip install act-cli           # PyPI
cargo install act-cli         # crates.io
```

Pre-built binaries available on [GitHub Releases](https://github.com/actcore/act-cli/releases) and Docker (`ghcr.io/actcore/act`).

## Quick Start

```bash
# Discover tools in a component
act info --tools ghcr.io/actpkg/sqlite:0.1.0

# Call a tool
act call ghcr.io/actpkg/sqlite:0.1.0 query \
  --args '{"sql":"SELECT sqlite_version()"}' \
  --metadata '{"database_path":"/data/app.db"}' \
  --allow-dir /data:./data

# Serve over HTTP
act run -l ghcr.io/actpkg/sqlite:0.1.0

# Serve over MCP stdio
act run --mcp ghcr.io/actpkg/sqlite:0.1.0
```

Components can be referenced as:
- **OCI refs:** `ghcr.io/actpkg/sqlite:0.1.0`
- **HTTP URLs:** `https://example.com/component.wasm`
- **Local paths:** `./component.wasm`

Remote components are cached in `~/.cache/act/components/`.

## Commands

| Command | Description |
|---------|-------------|
| `run`   | Serve a component over ACT-HTTP (`-l`) or MCP stdio (`--mcp`) |
| `call`  | Call a tool directly, print result to stdout |
| `info`  | Show component metadata, tools, and schemas (`--tools`, `--format text\|json`) |
| `pull`  | Download a component from OCI or HTTP to local file |

## HTTP Endpoints (`run -l`)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/info` | Component metadata |
| `POST` | `/metadata-schema` | JSON Schema for metadata |
| `POST/QUERY` | `/tools` | List tools |
| `POST/QUERY` | `/tools/{name}` | Call a tool (SSE with `Accept: text/event-stream`) |

## Platform Support

| Architecture | Linux (GNU) | Linux (musl) | macOS | Windows | Docker |
|-------------|:-----------:|:------------:|:-----:|:-------:|:------:|
| x86_64      | ✓           | ✓            | ✓     | ✓       | ✓      |
| aarch64     | ✓           | ✓            | ✓     | ✓       | ✓      |
| riscv64     | ✓           | ✓            | —     | —       | ✓      |

RISC-V (`riscv64`) is a first-class target. Regressions on RISC-V are release-blocking.

## Building

```bash
cargo build --release
```

Set `RUST_LOG=act=debug` for verbose output.

## License

MIT OR Apache-2.0
