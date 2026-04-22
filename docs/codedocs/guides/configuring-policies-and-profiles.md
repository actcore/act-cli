---
title: "Configuring Policies and Profiles"
description: "Create repeatable runtime policy profiles and understand when CLI overrides replace config-file settings."
---

This guide focuses on the configuration merge path implemented in `act-cli/src/config.rs`. The goal is to get deterministic runtime behavior without rewriting a long command line every time you call a component.

<Steps>
<Step>
### Create a config file

By default, `load_config` looks for `~/.config/act/config.toml`. Create that file with one or more reusable profiles:

```toml
log-level = "info"

[profile.sqlite.metadata]
database_path = "/workspace/data/app.db"

[profile.sqlite.policy.filesystem]
mode = "allowlist"
allow = ["/workspace/data/**"]

[profile.sqlite.policy.http]
mode = "deny"

[profile.fetcher.policy.http]
mode = "allowlist"
allow = [
  { host = "example.com", scheme = "https" },
  { host = "api.example.com", scheme = "https", methods = ["GET", "POST"] }
]
```

Profiles are keyed by name in `ConfigFile.profile`, and `get_profile` returns one by exact string match.
</Step>
<Step>
### Run a component with a profile

Use the profile name on any command that accepts `CommonOpts`:

```bash
act call ./sqlite_component.wasm query \
  --profile sqlite \
  --args '{"sql":"SELECT name FROM sqlite_master"}'
```

The host will merge profile metadata into the outgoing `Metadata` value and will resolve filesystem and HTTP policy from the profile first, then from top-level config if the profile lacks a policy section.
</Step>
<Step>
### Override the profile intentionally

CLI overrides win. If you pass any filesystem override flag, `resolve_fs_config` stops using the config file and builds a fresh `FsConfig` from CLI state only.

```bash
act call ./sqlite_component.wasm query \
  --profile sqlite \
  --fs-policy allowlist \
  --fs-allow '/workspace/data/**' \
  --fs-deny '/workspace/data/private/**' \
  --args '{"sql":"SELECT 1"}'
```

That behavior is deliberate. The code in `resolve_fs_config` and `resolve_http_config` treats CLI flags as a full override layer, not as an additive patch on top of profile values.
</Step>
<Step>
### Add metadata per invocation

Profile metadata and CLI metadata are merged as JSON objects, with CLI keys winning on collisions:

```bash
act call ./service_component.wasm invoke \
  --profile fetcher \
  --metadata '{"tenant":"staging","timeout_ms":5000}' \
  --args '{"operation":"status"}'
```

`resolve_metadata` ignores non-object JSON values. If you pass a string or array to `--metadata`, the merge result becomes empty rather than partially applied.
</Step>
</Steps>

Real-world pattern: keep broad defaults in the config file, then use CLI overrides only when you need a temporary narrowing or a one-off open policy for debugging. That keeps operator intent visible and makes it clear when a command is deviating from the normal policy envelope.

The main pitfall is assuming CLI overrides merge with profile rules. They do not. Once `CliPolicyOverrides::any_fs_override()` or `any_http_override()` is true, the corresponding config side is rebuilt from CLI values. If you need the profile's allowlist plus one extra CLI allow rule, you currently have to restate the profile rules on the command line or move that broader rule into the profile itself.

For the exact types and functions involved, see [API Reference: config](/docs/api-reference/config).
