---
name: act
description: Run ACT WebAssembly component tools via `act call`. Use when the user asks to use an ACT component, run a .wasm tool, or needs sandboxed tools (SQLite, HTTP, filesystem, etc.) without system dependencies. Also use when you see references to ghcr.io/actpkg/ or .wasm component files.
license: MIT-0
compatibility: Requires act CLI (npm i -g @actcore/act) and shell/terminal access.
allowed-tools: Bash(act *) Bash(npx @actcore/act *) Bash(uvx --from act-cli act *)
metadata:
  author: actcore
  version: "0.3"
  act: {}
  openclaw:
    requires:
      bins:
        - act
---

# ACT Tools

Run self-contained WebAssembly component tools via the `act` CLI. No system dependencies, no Docker, no language runtimes — just `.wasm` binaries in a sandbox.

## Prerequisites

Verify that the correct `act` is available (not nektos/act for GitHub Actions):

```bash
act --help
```

The output must contain "ACT" or "Agent Component Tools". If it shows "Run GitHub Actions locally" or is not installed, use npx:

```bash
npx @actcore/act --help
```

If npx works, use `npx @actcore/act` instead of `act` for all commands below.

To install globally:

```bash
npm i -g @actcore/act
```

## Step 1: Discover tools

```bash
act info --tools --format json <component>
```

`<component>` is one of:
- OCI registry ref: `ghcr.io/actpkg/sqlite:0.1.0`
- HTTP URL: `https://example.com/component.wasm`
- Local file: `./component.wasm`

The output contains:
- `tools` — list of tool names, descriptions, and `parameters_schema`

Use `--format text` for a human-readable summary instead of JSON.

## Step 2: Call a tool

```bash
act call <component> <tool-name> --args '<json>' [options]
```

| Option | Purpose |
|--------|---------|
| `--args '<json>'` | Tool parameters (matches `parameters_schema`) |
| `--metadata '<json>'` | Per-call metadata (component-defined keys) |
| `--allow-dir guest:host` | Grant directory access to the sandbox |
| `--allow-fs` | Grant full filesystem access |

Output is JSON on stdout. Logs go to stderr.

Remote components are cached locally after first download.

## Step 3: Install component skills (optional)

ACT components MAY embed Agent Skills in their `.wasm` binary. Extract and install them:

```bash
act skill <component>
```

This extracts the embedded skill to `.agents/skills/<name>/`, making it available to all compatible agents. Skills from ACT components include `metadata.act` in their SKILL.md frontmatter.

## Example: SQLite

```bash
# Create a table
act call ghcr.io/actpkg/sqlite:0.1.0 execute-batch \
  --args '{"sql":"CREATE TABLE notes (id INTEGER PRIMARY KEY, text TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)"}' \
  --metadata '{"database_path":"/data/notes.db"}' \
  --allow-dir /data:/tmp/act-data

# Insert
act call ghcr.io/actpkg/sqlite:0.1.0 execute \
  --args '{"sql":"INSERT INTO notes (text) VALUES (?1)","params":["Hello from ACT"]}' \
  --metadata '{"database_path":"/data/notes.db"}' \
  --allow-dir /data:/tmp/act-data

# Query
act call ghcr.io/actpkg/sqlite:0.1.0 query \
  --args '{"sql":"SELECT * FROM notes"}' \
  --metadata '{"database_path":"/data/notes.db"}' \
  --allow-dir /data:/tmp/act-data
```

## Filesystem access

Components run sandboxed — no host filesystem access by default. If a tool fails with a capability or permission error, it likely needs `--allow-dir`:

```
--allow-dir /data:/path/on/host    # map guest /data → host directory
--allow-dir /data:./local-dir      # relative paths work
--allow-fs                         # full access (use with caution)
```

If a component works with files (paths in tool `parameters_schema` or component-defined metadata keys), it needs `--allow-dir`. The guest path must match the path passed in `--args` or `--metadata`.

Example: if you use path `/data/app.db`, grant access with `--allow-dir /data:./data`.

## Important

- Always run `act info --tools` first to discover tool names and schemas
- Pass `--metadata` on every call (stateless — no session)
- If a call fails with permission/capability error, add `--allow-dir`
- Components are sandboxed — they cannot access anything unless you grant it
