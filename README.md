# ACT CLI & Build Tools

Host and build [ACT](https://actcore.dev) (Agent Component Tools) WebAssembly components.

This repo contains two tools:

- **`act`** — run, call, inspect, and serve ACT components from local files, HTTP URLs, or OCI registries
- **`act-build`** — post-process compiled WASM components: embed metadata, skills, and custom sections

## Install

```bash
# act (CLI host)
npm i -g @actcore/act
pip install act-cli
cargo install act-cli

# act-build (build tool)
npm i -g @actcore/act-build
pip install act-build
cargo install act-build
```

Pre-built binaries available on [GitHub Releases](https://github.com/actcore/act-cli/releases) and Docker (`ghcr.io/actcore/act`).

## act — Component Host

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

### Commands

| Command | Description |
|---------|-------------|
| `run`   | Serve a component over ACT-HTTP (`-l`) or MCP stdio (`--mcp`) |
| `call`  | Call a tool directly, print result to stdout |
| `info`  | Show component metadata, tools, and schemas (`--tools`, `--format text\|json`) |
| `pull`  | Download a component from OCI or HTTP to local file |

### HTTP Endpoints (`run -l`)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/info` | Component metadata |
| `POST` | `/metadata-schema` | JSON Schema for metadata |
| `POST/QUERY` | `/tools` | List tools |
| `POST/QUERY` | `/tools/{name}` | Call a tool (SSE with `Accept: text/event-stream`) |

## act-build — Component Build Tool

```bash
# Embed act:component metadata, act:skill, and WASM custom sections
act-build pack target/wasm32-wasip2/release/my_component.wasm

# Validate without modifying
act-build validate target/wasm32-wasip2/release/my_component.wasm
```

Metadata is resolved via merge-patch from project manifests:

1. **Base** from `Cargo.toml`, `pyproject.toml`, or `package.json` (name, version, description)
2. **Inline patch** from the same manifest (`[package.metadata.act-component]`, `[tool.act-component]`, or `actComponent`)
3. **`act.toml`** — highest priority, applied last

## Platform Support

| Architecture | Linux (GNU) | Linux (musl) | macOS | Windows | Docker |
|-------------|:-----------:|:------------:|:-----:|:-------:|:------:|
| x86_64      | ✓           | ✓            | ✓     | ✓       | ✓      |
| aarch64     | ✓           | ✓            | ✓     | ✓       | ✓      |
| riscv64     | ✓           | ✓            | —     | —       | ✓      |

RISC-V (`riscv64`) is a first-class target. Regressions on RISC-V are release-blocking.

## Building

```bash
cargo build --release        # both tools
cargo build -p act-cli       # act only
cargo build -p act-build     # act-build only
```

Set `RUST_LOG=act=debug` for verbose output.

## License

MIT OR Apache-2.0
