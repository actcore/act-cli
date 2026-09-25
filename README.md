# ACT CLI & Build Tools

Host and build [ACT](https://actcore.dev) (Agent Component Tools) WebAssembly components.

This repo contains two tools:

- **`act`** — run, call, inspect, and serve ACT components from local files, HTTP URLs, or OCI registries. Components built for `wasm32-wasip2` (with async) and `wasm32-wasip3` run the same way, under the same capability grants
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
act info --tools actpkg.dev/library/sqlite

# Call a tool. sqlite is session-based: --session-args opens a session for
# this one call. The grant lets it touch /data and nothing else.
act call actpkg.dev/library/sqlite query \
  --args '{"sql":"SELECT sqlite_version()"}' \
  --session-args '{"database_path":"/data/app.db"}' \
  --grant '{"wasi:filesystem":{"mode":"allowlist","allow":[{"path":"/data/**","mode":"rw"}]}}'

# Serve over MCP stdio
act run --mcp actpkg.dev/library/sqlite --allow wasi:filesystem

# Serve over MCP Streamable HTTP, at http://[::1]:3000/mcp
act run --mcp --http -l '[::1]:3000' actpkg.dev/library/sqlite --allow wasi:filesystem
```

Components can be referenced as:
- **OCI refs:** `actpkg.dev/library/sqlite` (a tag or `@sha256:` digest is optional)
- **HTTP URLs:** `https://example.com/component.wasm`
- **Local paths:** `./component.wasm`

Remote components are cached in `~/.cache/act/components/`.

### Commands

| Command | Description |
|---------|-------------|
| `run`     | Serve a component over MCP — stdio (`--mcp`) or Streamable HTTP (`--mcp --http -l`) |
| `call`    | Call a tool directly, print result to stdout |
| `info`    | Show component metadata, tools, and schemas (`--tools`, `--format text\|json\|toon`) |
| `skill`   | Extract the Agent Skills a component embeds |
| `pull`    | Download a component from OCI or HTTP to a local file |
| `session` | Show a session-based component's `open-args-schema` |
| `store`   | Manage the local component store (`list`, `update`, `gc`) |
| `inspect` | Read a component's raw manifest or tool list without instantiating it |
| `secret`  | Store credentials a component declares (there is no `get`) |
| `login`   | Provision a declared credential by prompting |

Capabilities are granted with `--allow <id>`, `--deny <id>` and `--grant '<json>'`,
or per profile in `~/.config/act/config.toml`. The default mode is `ask`: an
interactive run prompts, a headless one denies.

### Audit trail

`run` and `call` write a structured audit trail to stderr: what component is running and under what capability modes, every capability decision as it resolves, and a per-call summary. It is on by default and independent of `RUST_LOG` — only `--no-audit` (or `[audit] enabled = false` in the config file) turns it off.

```
audit: act-cli/tests/fixtures/fs-canary.wasm sha256:f17cda │ act:credentials=deny wasi:filesystem=ask wasi:http=deny wasi:sockets=deny
audit: ⚠ declared ask, no prompt channel — every access will be denied: wasi:filesystem
audit: ? ask-deny  wasi:filesystem  /tmp/probe.txt   no prompt channel  mode:ask
audit: ● read  tool-error 1ms  args:43ebc7  req:0005a4
```

That's a real, captured transcript of one headless call with no `--grant`: the first line is the instantiation header (component, digest, resolved mode per capability class); the second warns that a declared `ask` capability has no prompt channel to answer it, so every access degrades to deny; the third is the immediate denial (denials and asks print the moment they resolve, never batched); the fourth is the per-call rollup — outcome, duration, an `args:` digest of the tool arguments (or the full values with `--audit-args`), and a `req:` id for joining this line back to a client log. Allowed operations coalesce into that rollup line instead of one line each, e.g. `filesystem: 12 read under /data/**`.

### MCP over HTTP (`run --mcp --http`)

`act run --mcp --http -l <addr>` serves the same MCP server as stdio over
Streamable HTTP, at one endpoint: `/mcp`. `--http` requires `--mcp`. The
earlier REST binding (`/info`, `/tools`, …) was removed in 0.12.0.

## act-build — Component Build Tool

```bash
# Embed act:component metadata, act:skill, and WASM custom sections
act-build pack target/wasm32-wasip2/release/my_component.wasm

# Validate without modifying
act-build validate target/wasm32-wasip2/release/my_component.wasm

# Publish as a CNCF Wasm OCI Artifact
act-build push my_component.wasm ghcr.io/you/my-component:0.1.0 \
  --also-tag latest \
  --source https://github.com/actpkg/my-component \
  --skip-if-identical
```

Metadata is resolved via merge-patch from project manifests:

1. **Base** from `Cargo.toml`, `pyproject.toml`, or `package.json` (name, version, description)
2. **Inline patch** from the same manifest (`[package.metadata.act]`, `[tool.act]`, or `"act"` in `package.json`)
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

### Runtime requirement: glibc 2.34

A **glibc** build of `act` or `act-build` requires **glibc 2.34 or newer** —
Debian 12, Ubuntu 22.04, RHEL 9 and later. This is a supported-platform
commitment, not an incidental build setting: it is asserted in CI, and lowering
it is a breaking change.

Which channels it applies to:

| Channel | Affected |
|---|---|
| npm (`@actcore/act`, `@actcore/act-build`) | **No** — Linux packages ship musl binaries |
| PyPI `manylinux` wheels | Yes — 2.34; the riscv64 wheel needs 2.39 |
| GitHub Releases `*-linux-*-gnu` | Yes — 2.34 |
| GitHub Releases `*-linux-*-musl`, Docker | No |

The floor is one symbol. DNS SVCB/HTTPS lookups call `res_query(3)`, which
glibc did not export under that name before 2.34 — earlier releases had only
`__res_query`, and a modern glibc keeps that as a compat symbol new code cannot
link against, so there is no spelling that satisfies both. Nothing else in the
binary requires past glibc 2.33.

On an older distribution, use a musl build: musl exports the symbol outright and
carries no floor. Building from source does not lift the requirement — it is the
same call — so musl is the answer there, not `cargo build`.

## Building

```bash
cargo build --release        # both tools
cargo build -p act-cli       # act only
cargo build -p act-build     # act-build only
```

Set `RUST_LOG=act=debug` for verbose output.

## License

MIT OR Apache-2.0
