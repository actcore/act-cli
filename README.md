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
  -m database_path=/data/app.db \
  --grant '{"wasi:filesystem":{"mode":"allowlist","allow":[{"path":"/data/**","mode":"rw"}]}}'

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
| `run`   | Serve a component over MCP — stdio (`--mcp`) or Streamable HTTP (`--mcp --http -l`) |
| `call`  | Call a tool directly, print result to stdout |
| `info`  | Show component metadata, tools, and schemas (`--tools`, `--format text\|json\|toon`) |
| `pull`  | Download a component from OCI or HTTP to local file |

### Audit trail

`run` and `call` write a structured audit trail to stderr: what component is running and under what capability modes, every capability decision as it resolves, and a per-call summary. It is on by default and independent of `RUST_LOG` — only `--no-audit` (or `[audit] enabled = false` in the config file) turns it off.

```
audit: act-cli/tests/fixtures/fs-canary.wasm sha256:92342c │ wasi:filesystem=ask wasi:http=deny wasi:sockets=deny
audit: ⚠ declared ask, no prompt channel — every access will be denied: wasi:filesystem
audit: ? ask-deny  wasi:filesystem  /tmp/probe.txt   denied by user
audit: ● read  tool-error 1ms  args:43ebc7  req:00392e
```

That's a real, captured transcript of one headless call with no `--grant`: the first line is the instantiation header (component, digest, resolved mode per capability class); the second warns that a declared `ask` capability has no prompt channel to answer it, so every access degrades to deny; the third is the immediate denial (denials and asks print the moment they resolve, never batched); the fourth is the per-call rollup — outcome, duration, an `args:` digest of the tool arguments (or the full values with `--audit-args`), and a `req:` id for joining this line back to a client log. Allowed operations coalesce into that rollup line instead of one line each, e.g. `filesystem: 12 read under /data/**`.

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

# Publish as a CNCF Wasm OCI Artifact
act-build push my_component.wasm ghcr.io/actpkg/my-component:0.1.0 \
  --also-tag latest \
  --source https://github.com/actpkg/my-component \
  --skip-if-identical
```

Metadata is resolved via merge-patch from project manifests:

1. **Base** from `Cargo.toml`, `pyproject.toml`, or `package.json` (name, version, description)
2. **Inline patch** from the same manifest (`[package.metadata.act-component]`, `[tool.act-component]`, or `actComponent`)
3. **`act.toml`** — highest priority, applied last

`act-build push` produces artifacts conformant with the [CNCF
TAG-Runtime Wasm OCI Artifact spec](https://tag-runtime.cncf.io/wgs/wasm/deliverables/wasm-oci-artifact/):
manifest config has media type `application/vnd.wasm.config.v0+json`
(with `architecture`, `os`, `layerDigests`, and
`component.{exports,imports}` derived from the component's exports
and imports), and the layer is `application/wasm`.

Authentication is resolved in order: `OCI_USERNAME`/`OCI_PASSWORD`
env, then `GITHUB_TOKEN` for `ghcr.io`, then `~/.docker/config.json`
(or `$DOCKER_CONFIG/config.json`), then anonymous.

## Platform Support

| Architecture | Linux (GNU) | Linux (musl) | macOS | Windows | Docker |
|-------------|:-----------:|:------------:|:-----:|:-------:|:------:|
| x86_64      | ✓           | ✓            | ✓     | ✓       | ✓      |
| aarch64     | ✓           | ✓            | ✓     | ✓       | ✓      |
| riscv64     | ✓           | ✓            | —     | —       | ✓      |

RISC-V (`riscv64`) is a first-class target. Regressions on RISC-V are release-blocking.

Released **glibc** binaries and wheels need **glibc 2.34 or newer** (Debian 12,
Ubuntu 22.04, RHEL 9 and later); the riscv64 wheel needs 2.39. The floor is one
symbol: DNS SVCB/HTTPS lookups call `res_query(3)`, which glibc did not export
under that name before 2.34. Nothing else in the binary requires past 2.33.
Older distributions are covered by the musl builds, which carry no such floor
because musl exports the symbol outright. Building from source does not lift
it — the call is the same one — so musl is the answer there, not `cargo build`.

## Building

```bash
cargo build --release        # both tools
cargo build -p act-cli       # act only
cargo build -p act-build     # act-build only
```

Set `RUST_LOG=act=debug` for verbose output.

## License

MIT OR Apache-2.0
