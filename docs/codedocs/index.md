---
title: "Getting Started"
description: "Use /actcore/act-cli to resolve, inspect, host, call, package, and validate ACT WebAssembly components."
---

/actcore/act-cli hosts ACT WebAssembly components with `act` and post-processes them with `act-build`.

## The Problem

- Shipping tool components as raw `.wasm` files is not enough if developers still need bespoke loaders, transport adapters, and caching.
- Sandboxing is easy to get wrong. Filesystem and outbound HTTP access need a deny-by-default model with explicit, auditable grants.
- Component metadata tends to drift across `Cargo.toml`, `pyproject.toml`, `package.json`, and ad hoc build scripts.
- The same component often needs to be used three ways: as a one-off CLI call, as an HTTP server, and as an MCP server.

## The Solution

`act` turns a local path, HTTP URL, or OCI reference into a runnable ACT host, while `act-build` embeds normalized metadata and optional skills directly into the compiled component.

```bash
act info --tools ghcr.io/actpkg/sqlite:0.1.0
act call --fs-policy open ghcr.io/actpkg/sqlite:0.1.0 query \
  --args '{"sql":"SELECT sqlite_version()"}'
act-build pack ./target/wasm32-wasip2/release/my_component.wasm
```

The host path is implemented in `act-cli/src/main.rs`, `act-cli/src/resolve.rs`, and `act-cli/src/runtime/mod.rs`. The build path lives in `act-build/src/manifest/mod.rs` and `act-build/src/pack.rs`.

## Installation

" "bun"]}>
<Tab value="npm">

```bash
npm install -g @actcore/act @actcore/act-build
```

</Tab>
<Tab value="pnpm">

```bash
pnpm add -g @actcore/act @actcore/act-build
```

</Tab>
<Tab value="yarn">

```bash
yarn global add @actcore/act @actcore/act-build
```

</Tab>
<Tab value="bun">

```bash
bun add -g @actcore/act @actcore/act-build
```

</Tab>
</Tabs>

Cargo, PyPI, Docker, and GitHub Releases are also supported distribution paths according to the workspace manifests in `Cargo.toml`, `act-cli/pyproject.toml`, and `act-build/pyproject.toml`.

## Quick Start

The smallest working flow is: inspect a component, then call a tool directly.

```bash
act info --tools ghcr.io/actpkg/sqlite:0.1.0
act call --fs-policy open ghcr.io/actpkg/sqlite:0.1.0 query \
  --args '{"sql":"SELECT sqlite_version()"}'
```

Expected output:

```text
# sqlite v0.1.0
...
## query
...
3.46.0
```

What happens internally:

1. `act info` resolves the OCI reference into the cache with `resolve::resolve`.
2. `runtime::read_component_info` reads the `act:component` custom section without instantiating the component.
3. `act call` instantiates the component, converts JSON arguments to CBOR, and sends a `ComponentRequest::CallTool` message to the actor loop.

## Key Features

- One CLI for `run`, `call`, `info`, `skill`, and `pull`.
- Deny-by-default filesystem and HTTP policy resolution with profile support.
- ACT-HTTP and MCP transports backed by the same component actor.
- OCI, HTTP, and local path resolution with on-disk caching.
- Build-time metadata merge-patching from Rust, Python, JavaScript, or `act.toml`.
- Optional `act:skill` packaging alongside standard WASM custom sections.

<Cards>
  <Card title="Architecture" href="/docs/architecture">See how resolution, policy, runtime, and transports fit together.</Card>
  <Card title="Core Concepts" href="/docs/component-references">Learn the concepts you need before extending or deploying the tools.</Card>
  <Card title="API Reference" href="/docs/api-reference/config">Inspect every public Rust type and function exported by the source modules.</Card>
</Cards>
