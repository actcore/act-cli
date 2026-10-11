---
title: "Packing and Validating Components"
description: "Turn a compiled component into a self-describing ACT artifact with embedded metadata and optional skills."
---

This guide walks through a typical `act-build` workflow. The target audience is a component author or build engineer who wants hosts to discover metadata, capability declarations, and skills directly from the `.wasm` artifact.

<Steps>
<Step>
### Put metadata in the project manifest

For a Rust project, start with `Cargo.toml` and add an inline ACT section:

```toml
[package]
name = "docs-search"
version = "0.1.0"
description = "Search tools for docs"
edition = "2024"

[package.metadata.act.std.capabilities."wasi:http"]
allow = [{ host = "api.example.com", scheme = "https" }]

[package.metadata.act.std.capabilities."wasi:filesystem"]
allow = [{ path = "/workspace/cache/**", mode = "rw" }]
```

The manifest reader in `act-build/src/manifest/cargo.rs` extracts the package fields into `ComponentInfo.std.*` and passes the inline `act` object back as a merge patch.
</Step>
<Step>
### Add a final override with act.toml when needed

Use `act.toml` for deployment-specific or workspace-external metadata:

```toml
[std]
name = "docs-search"
version = "0.1.0"
description = "Hosted search for docs and changelogs"

[extra]
"std:skill" = "Use this component for search-oriented workflows."
```

`manifest::resolve` applies `act.toml` after the language-specific manifest, so this is the highest-priority override layer.
</Step>
<Step>
### Embed an optional skill

If the component should ship with an agent skill, add a `skill/` directory:

```text
skill/
  SKILL.md
  references/
    usage.md
```

Then run:

```bash
act-build pack ./target/wasm32-wasip2/release/docs_search.wasm
```

`skill::pack_skill_dir` requires `skill/SKILL.md` to exist. If the directory exists without that file, `pack` fails instead of embedding a partial archive.
</Step>
<Step>
### Validate the result

Run validation before publishing:

```bash
act-build validate ./target/wasm32-wasip2/release/docs_search.wasm
act info --tools ./target/wasm32-wasip2/release/docs_search.wasm
```

`validate::run` checks for `act:component`, decodes it as CBOR, verifies `std.name` and `std.version`, and confirms the component exports `act:core/tool-provider`. The follow-up `act info` call is useful because it exercises the runtime-side metadata reader that other hosts will rely on.
</Step>
</Steps>

Problem solved: the final `.wasm` file becomes the delivery artifact, not a loose collection of separate metadata files. That is important for registries and OCI publishing, because hosts pulling the component later only need the binary.

One practical caution: `pack` rewrites the target file in place. If your build pipeline produces immutable artifacts or content-addressed filenames, copy the component before packing it or write the pack step into the artifact pipeline before digest calculation. Also note that `validate` does not confirm that runtime behavior matches the declared capability set. It confirms packaging integrity, not semantic correctness of the component's implementation.

Continue with [Component Packaging](/docs/component-packaging) for the conceptual model or [API Reference: build pipeline](/docs/api-reference/build-pipeline) for the low-level functions.
