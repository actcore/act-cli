# CLI Restructure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consolidate act-cli commands into a cleaner structure: `run` (unified serve), `call` (one-shot), `info` (rich introspection with `--tools`, `--format`, metadata, skill), `pull` (download skeleton). No backwards-compat aliases — clean break, e2e tests will be fixed separately.

**Architecture:** Replace five subcommands (`serve`, `mcp`, `call`, `info`, `tools`) with four (`run`, `call`, `info`, `pull`). The `info` command shows component metadata including `std:skill`, and with `--tools` also shows full tool metadata (`std:usage-hints`, `std:tags`, `std:read-only`, etc.) and metadata-schema. Two output formats: `text` (markdown-like, default) and `json` (compact, for machines).

**Tech Stack:** Rust, clap 4.6 (derive), serde_json, act-types 0.2.4, wasmtime 42

---

## File Structure

- **Modify:** `act-cli/src/main.rs` — New `Cli` enum with `Run`/`Call`/`Info`/`Pull`, new dispatch, new handler functions
- **Create:** `act-cli/src/format.rs` — `--format text|json` rendering for `info` command, handles component metadata, skill, tool metadata, metadata-schema
- **No changes:** `act-cli/src/http.rs`, `act-cli/src/mcp.rs`, `act-cli/src/runtime.rs`, `act-cli/src/config.rs`

---

### Task 1: Replace Cli enum and main dispatch

**Files:**
- Modify: `act-cli/src/main.rs:1-136`

- [ ] **Step 1: Add `mod format` and `OutputFormat` enum**

Add `mod format;` after `mod mcp;` (line 3). Add the enum before the `Cli` definition:

```rust
#[derive(clap::ValueEnum, Clone, Debug, Default)]
enum OutputFormat {
    #[default]
    Text,
    Json,
}
```

- [ ] **Step 2: Replace the Cli enum**

Replace lines 36–87 with:

```rust
#[derive(Parser)]
#[command(name = "act", about = "ACT — Agent Component Tools CLI")]
enum Cli {
    /// Run a component (serve over HTTP or MCP stdio)
    Run {
        /// Path to the .wasm component file
        component: PathBuf,

        /// Serve as MCP server over stdio
        #[arg(short, long)]
        mcp: bool,

        /// Serve as ACT-HTTP server. Optional address (default: [::1]:3000)
        #[arg(short, long, num_args = 0..=1, default_missing_value = "[::1]:3000")]
        listen: Option<SocketAddr>,

        #[command(flatten)]
        opts: CommonOpts,
    },
    /// Call a tool directly and print the result
    Call {
        /// Path to the .wasm component file
        component: PathBuf,

        /// Tool name to call
        tool: String,

        /// JSON arguments
        #[arg(long, default_value = "{}")]
        args: String,

        #[command(flatten)]
        opts: CommonOpts,
    },
    /// Show component info, metadata, and optionally list tools
    Info {
        /// Path to the .wasm component file
        component: PathBuf,

        /// Also list tools with full metadata (requires component instantiation)
        #[arg(short, long)]
        tools: bool,

        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,

        #[command(flatten)]
        opts: CommonOpts,
    },
    /// Download a component from OCI registry or HTTP URL
    Pull {
        /// OCI reference or HTTP URL
        #[arg(name = "ref")]
        reference: String,

        /// Write output to file
        #[arg(short = 'o')]
        output: Option<PathBuf>,

        /// Write output to file named from the reference
        #[arg(short = 'O', conflicts_with = "output")]
        output_from_ref: bool,
    },
}
```

- [ ] **Step 3: Replace main() dispatch**

Replace the entire `main()` function (lines 89–136) with:

```rust
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let env_filter = if std::env::var("RUST_LOG").is_ok() {
        tracing_subscriber::EnvFilter::from_default_env()
    } else {
        let config_path = match &cli {
            Cli::Run { opts, .. }
            | Cli::Call { opts, .. }
            | Cli::Info { opts, .. } => opts.config.as_deref(),
            Cli::Pull { .. } => None,
        };
        let log_level = config::load_config(config_path)
            .ok()
            .and_then(|c| c.log_level);
        let directive = match log_level.as_deref() {
            Some(level) => format!("act_cli={level}"),
            None => "act_cli=info".to_string(),
        };
        directive.parse().expect("valid log filter")
    };

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .init();

    match cli {
        Cli::Run {
            component,
            mcp,
            listen,
            opts,
        } => cmd_run(component, mcp, listen, opts).await,
        Cli::Call {
            component,
            tool,
            args,
            opts,
        } => cmd_call(component, tool, args, opts).await,
        Cli::Info {
            component,
            tools,
            format,
            opts,
        } => cmd_info(component, tools, format, opts).await,
        Cli::Pull {
            reference,
            output,
            output_from_ref,
        } => cmd_pull(reference, output, output_from_ref).await,
    }
}
```

- [ ] **Step 4: Check it parses (expect missing function errors)**

Run: `cd /mnt/devenv/workspace/act/act-cli && cargo check 2>&1 | grep "error\["`

Expected: errors about `cmd_run`, `cmd_call`, `cmd_info`, `cmd_pull` not found, and `mod format` file missing. No syntax/type errors in the enum.

---

### Task 2: Implement `cmd_run` and `cmd_call`, delete old functions

**Files:**
- Modify: `act-cli/src/main.rs` — delete `serve()`, `mcp_serve()`, `cli_call_tool()`, `cli_info()`, `cli_tools()`, add `cmd_run`, `run_mcp_stdio`, `run_http`, `cmd_call`

- [ ] **Step 1: Delete all old handler functions**

Delete these functions from `main.rs`:
- `serve()` (was lines 419–482)
- `mcp_serve()` (was lines 263–296)
- `cli_call_tool()` (was lines 184–261)
- `cli_info()` (was lines 298–305)
- `cli_tools()` (was lines 307–358)

- [ ] **Step 2: Add `cmd_run` with helpers**

```rust
async fn cmd_run(
    component_path: PathBuf,
    mcp: bool,
    listen: Option<SocketAddr>,
    opts: CommonOpts,
) -> Result<()> {
    if mcp && listen.is_some() {
        anyhow::bail!("MCP over HTTP (--mcp --listen) is not yet supported");
    }

    if mcp {
        return run_mcp_stdio(component_path, opts).await;
    }

    if let Some(addr) = listen {
        return run_http(component_path, Some(addr), opts).await;
    }

    // No flags — act-stdio (future)
    anyhow::bail!(
        "ACT stdio transport is not yet implemented.\n\
         Use -l / --listen for ACT-HTTP or -m / --mcp for MCP stdio."
    )
}

async fn run_mcp_stdio(component_path: PathBuf, opts: CommonOpts) -> Result<()> {
    let (_config, mut fs_config, metadata_value) = resolve_opts(&opts)?;

    let wasm_bytes = std::fs::read(&component_path).context("reading component file")?;
    let component_info = runtime::read_component_info(&wasm_bytes)?;
    let mount_root = component_info
        .metadata
        .get(act_types::constants::COMPONENT_FS_MOUNT_ROOT)
        .and_then(|v| v.as_str())
        .unwrap_or("/");
    config::apply_mount_root(&mut fs_config, mount_root);
    runtime::warn_missing_capabilities(&component_info, &fs_config);

    let metadata_kv: runtime::Metadata = metadata_value
        .as_ref()
        .map(|v| runtime::Metadata::from(v.clone()))
        .unwrap_or_default();

    let engine = runtime::create_engine()?;
    let component = runtime::load_component(&engine, &component_path)?;
    let linker = runtime::create_linker(&engine)?;
    let (instance, store) =
        runtime::instantiate_component(&engine, &component, &linker, &fs_config).await?;

    tracing::info!(
        name = %component_info.name,
        version = %component_info.version,
        "Loaded component (MCP stdio)"
    );

    let component_handle = runtime::spawn_component_actor(instance, store);
    mcp::run_stdio(component_info, component_handle, metadata_kv).await
}

async fn run_http(
    component_path: PathBuf,
    cli_listen: Option<SocketAddr>,
    opts: CommonOpts,
) -> Result<()> {
    let (config, mut fs_config, metadata_value) = resolve_opts(&opts)?;

    let addr: SocketAddr = match cli_listen {
        Some(a) => a,
        None => config
            .listen
            .as_deref()
            .map(|s| s.parse())
            .transpose()
            .context("invalid 'listen' in config file")?
            .unwrap_or_else(|| "[::1]:3000".parse().unwrap()),
    };

    let wasm_bytes = std::fs::read(&component_path).context("reading component file")?;
    let component_info = runtime::read_component_info(&wasm_bytes)?;
    let mount_root = component_info
        .metadata
        .get(act_types::constants::COMPONENT_FS_MOUNT_ROOT)
        .and_then(|v| v.as_str())
        .unwrap_or("/");
    config::apply_mount_root(&mut fs_config, mount_root);
    runtime::warn_missing_capabilities(&component_info, &fs_config);

    let resolved_metadata: runtime::Metadata = metadata_value
        .as_ref()
        .map(|v| runtime::Metadata::from(v.clone()))
        .unwrap_or_default();

    let engine = runtime::create_engine()?;
    let component = runtime::load_component(&engine, &component_path)?;
    let linker = runtime::create_linker(&engine)?;
    let (instance, store) =
        runtime::instantiate_component(&engine, &component, &linker, &fs_config).await?;

    tracing::info!(
        name = %component_info.name,
        version = %component_info.version,
        "Loaded component"
    );

    let component_handle = runtime::spawn_component_actor(instance, store);

    let state = Arc::new(http::AppState {
        info: component_info,
        component: component_handle,
        metadata: resolved_metadata,
    });

    tracing::info!(%addr, component = %component_path.display(), "ACT host listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, http::create_router(state))
        .await
        .context("server error")?;

    Ok(())
}
```

- [ ] **Step 3: Add `cmd_call`**

Same body as old `cli_call_tool`, just renamed:

```rust
async fn cmd_call(
    component_path: PathBuf,
    tool: String,
    args: String,
    opts: CommonOpts,
) -> Result<()> {
    let (_config, mut fs_config, metadata_value) = resolve_opts(&opts)?;

    let wasm_bytes = std::fs::read(&component_path).context("reading component file")?;
    let component_info = runtime::read_component_info(&wasm_bytes)?;
    let mount_root = component_info
        .metadata
        .get(act_types::constants::COMPONENT_FS_MOUNT_ROOT)
        .and_then(|v| v.as_str())
        .unwrap_or("/");
    config::apply_mount_root(&mut fs_config, mount_root);
    runtime::warn_missing_capabilities(&component_info, &fs_config);

    let metadata_kv: runtime::Metadata = metadata_value
        .as_ref()
        .map(|v| runtime::Metadata::from(v.clone()))
        .unwrap_or_default();

    let arguments: serde_json::Value =
        serde_json::from_str(&args).context("invalid --args JSON")?;
    let cbor_args = cbor::json_to_cbor(&arguments).context("encoding args as CBOR")?;

    let engine = runtime::create_engine()?;
    let component = runtime::load_component(&engine, &component_path)?;
    let linker = runtime::create_linker(&engine)?;
    let (instance, store) =
        runtime::instantiate_component(&engine, &component, &linker, &fs_config).await?;

    let component_handle = runtime::spawn_component_actor(instance, store);

    let tool_call = runtime::act::core::types::ToolCall {
        name: tool,
        arguments: cbor_args,
        metadata: metadata_kv.clone().into(),
    };

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::CallTool {
        call: tool_call,
        reply: reply_tx,
    };

    component_handle
        .send(request)
        .await
        .map_err(|_| anyhow::anyhow!("component actor unavailable"))?;

    match reply_rx.await? {
        Ok(result) => {
            for event in &result.events {
                match event {
                    runtime::act::core::types::StreamEvent::Content(part) => {
                        let data = cbor::decode_content_data(&part.data, part.mime_type.as_deref());
                        match data {
                            serde_json::Value::String(s) => println!("{s}"),
                            other => println!("{}", serde_json::to_string_pretty(&other)?),
                        }
                    }
                    runtime::act::core::types::StreamEvent::Error(err) => {
                        let ls = act_types::types::LocalizedString::from(&err.message);
                        anyhow::bail!("{}: {}", err.kind, ls.any_text());
                    }
                }
            }
            Ok(())
        }
        Err(runtime::ComponentError::Tool(te)) => {
            let ls = act_types::types::LocalizedString::from(&te.message);
            anyhow::bail!("{}: {}", te.kind, ls.any_text());
        }
        Err(runtime::ComponentError::Internal(e)) => Err(e),
    }
}
```

- [ ] **Step 4: Check compilation (expect cmd_info/cmd_pull missing)**

Run: `cd /mnt/devenv/workspace/act/act-cli && cargo check 2>&1 | grep "error\["`

Expected: errors only about `cmd_info`, `cmd_pull`, and missing `format` module.

---

### Task 3: Create `format.rs` with full metadata support

**Files:**
- Create: `act-cli/src/format.rs`

This module renders component info + tools with all their metadata for both text and JSON output.

- [ ] **Step 1: Write format.rs**

Create `act-cli/src/format.rs`:

```rust
use act_types::cbor;
use act_types::constants::*;
use act_types::types::{LocalizedString, Metadata};
use serde::Serialize;

use crate::runtime;

// ── JSON output types ──

#[derive(Serialize)]
pub struct InfoJson {
    pub name: String,
    pub version: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_language: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<CapabilityJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skill: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_schema: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<ToolJson>>,
}

#[derive(Serialize)]
pub struct CapabilityJson {
    pub id: String,
    pub required: bool,
}

#[derive(Serialize)]
pub struct ToolJson {
    pub name: String,
    pub description: String,
    pub parameters_schema: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_hints: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anti_usage_hints: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destructive: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub streaming: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

// ── Data passed into formatters ──

pub struct InfoData<'a> {
    pub info: &'a runtime::ComponentInfo,
    pub metadata_schema: Option<&'a str>,
    pub tools: Option<&'a [runtime::act::core::types::ToolDefinition]>,
}

// ── JSON builder ──

pub fn to_json(data: &InfoData) -> InfoJson {
    let skill = data
        .info
        .metadata
        .get(COMPONENT_SKILL)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    InfoJson {
        name: data.info.name.clone(),
        version: data.info.version.clone(),
        description: data.info.description.clone(),
        default_language: data.info.default_language.clone(),
        capabilities: data
            .info
            .capabilities
            .iter()
            .map(|c| CapabilityJson {
                id: c.id.clone(),
                required: c.required,
            })
            .collect(),
        skill,
        metadata_schema: data
            .metadata_schema
            .and_then(|s| serde_json::from_str(s).ok()),
        tools: data.tools.map(|list| list.iter().map(tool_to_json).collect()),
    }
}

fn tool_to_json(td: &runtime::act::core::types::ToolDefinition) -> ToolJson {
    let ls = LocalizedString::from(&td.description);
    let meta = Metadata::from(td.metadata.clone());

    let usage_hints: Option<String> = meta
        .get_as::<String>(META_USAGE_HINTS)
        .or_else(|| {
            meta.get_as::<Vec<(String, String)>>(META_USAGE_HINTS)
                .map(|pairs| {
                    LocalizedString::from(pairs).any_text().to_string()
                })
        });
    let anti_usage_hints: Option<String> = meta
        .get_as::<String>(META_ANTI_USAGE_HINTS)
        .or_else(|| {
            meta.get_as::<Vec<(String, String)>>(META_ANTI_USAGE_HINTS)
                .map(|pairs| {
                    LocalizedString::from(pairs).any_text().to_string()
                })
        });

    ToolJson {
        name: td.name.clone(),
        description: ls.any_text().to_string(),
        parameters_schema: serde_json::from_str(&td.parameters_schema)
            .unwrap_or(serde_json::json!({"type": "object"})),
        usage_hints,
        anti_usage_hints,
        tags: meta.get_as::<Vec<String>>(META_TAGS),
        read_only: meta.get_as::<bool>(META_READ_ONLY),
        idempotent: meta.get_as::<bool>(META_IDEMPOTENT),
        destructive: meta.get_as::<bool>(META_DESTRUCTIVE),
        streaming: meta.get_as::<bool>(META_STREAMING),
        timeout_ms: meta.get_as::<u64>(META_TIMEOUT_MS),
    }
}

// ── Text builder ──

pub fn to_text(data: &InfoData) -> String {
    let mut out = String::new();

    // Header
    out.push_str(&format!("# {} v{}\n", data.info.name, data.info.version));
    out.push_str(&data.info.description);
    out.push('\n');

    // Capabilities
    if !data.info.capabilities.is_empty() {
        out.push_str("\nCapabilities:\n");
        for cap in &data.info.capabilities {
            let req = if cap.required { " (required)" } else { "" };
            out.push_str(&format!("  {}{}\n", cap.id, req));
        }
    }

    // Skill
    if let Some(skill) = data
        .info
        .metadata
        .get(COMPONENT_SKILL)
        .and_then(|v| v.as_str())
    {
        out.push_str("\n## Skill\n");
        out.push_str(skill);
        if !skill.ends_with('\n') {
            out.push('\n');
        }
    }

    // Metadata schema
    if let Some(schema) = data.metadata_schema {
        out.push_str("\n## Metadata Schema\n");
        // Pretty-print the JSON schema for readability
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(schema) {
            if let Ok(pretty) = serde_json::to_string_pretty(&parsed) {
                out.push_str(&pretty);
            } else {
                out.push_str(schema);
            }
        } else {
            out.push_str(schema);
        }
        out.push('\n');
    }

    // Tools
    if let Some(tool_list) = data.tools {
        out.push('\n');
        for td in tool_list {
            let ls = LocalizedString::from(&td.description);
            let meta = Metadata::from(td.metadata.clone());

            out.push_str(&format!("## {}\n", td.name));
            out.push_str(&format!("{}\n", ls.any_text()));

            // Annotations line
            let mut annotations = Vec::new();
            if meta.get_as::<bool>(META_READ_ONLY) == Some(true) {
                annotations.push("read-only");
            }
            if meta.get_as::<bool>(META_IDEMPOTENT) == Some(true) {
                annotations.push("idempotent");
            }
            if meta.get_as::<bool>(META_DESTRUCTIVE) == Some(true) {
                annotations.push("destructive");
            }
            if meta.get_as::<bool>(META_STREAMING) == Some(true) {
                annotations.push("streaming");
            }
            if !annotations.is_empty() {
                out.push_str(&format!("[{}]\n", annotations.join(", ")));
            }

            if let Some(timeout) = meta.get_as::<u64>(META_TIMEOUT_MS) {
                out.push_str(&format!("Timeout: {}ms\n", timeout));
            }

            // Tags
            if let Some(tags) = meta.get_as::<Vec<String>>(META_TAGS) {
                if !tags.is_empty() {
                    out.push_str(&format!("Tags: {}\n", tags.join(", ")));
                }
            }

            // Usage hints
            if let Some(hints) = get_localized_text(&meta, META_USAGE_HINTS) {
                out.push_str(&format!("When to use: {}\n", hints));
            }
            if let Some(hints) = get_localized_text(&meta, META_ANTI_USAGE_HINTS) {
                out.push_str(&format!("When NOT to use: {}\n", hints));
            }

            // Parameters
            if let Ok(schema) =
                serde_json::from_str::<serde_json::Value>(&td.parameters_schema)
            {
                if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
                    let required: Vec<&str> = schema
                        .get("required")
                        .and_then(|r| r.as_array())
                        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                        .unwrap_or_default();

                    if !props.is_empty() {
                        out.push_str("Parameters:\n");
                        for (name, prop) in props {
                            let ty = prop
                                .get("type")
                                .and_then(|t| t.as_str())
                                .unwrap_or("any");
                            let req = if required.contains(&name.as_str()) {
                                "required"
                            } else {
                                "optional"
                            };
                            let desc = prop
                                .get("description")
                                .and_then(|d| d.as_str())
                                .unwrap_or("");
                            if desc.is_empty() {
                                out.push_str(&format!("  {name}: {ty} ({req})\n"));
                            } else {
                                out.push_str(&format!("  {name}: {ty} ({req}) — {desc}\n"));
                            }
                        }
                    }
                }
            }

            out.push('\n');
        }
    }

    out
}

/// Extract a localized-string metadata value as plain text.
fn get_localized_text(meta: &Metadata, key: &str) -> Option<String> {
    // Try plain string first
    meta.get_as::<String>(key).or_else(|| {
        // Try localized map — take any language
        meta.get_as::<Vec<(String, String)>>(key)
            .map(|pairs| LocalizedString::from(pairs).any_text().to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use act_types::ComponentInfo;

    fn sample_info() -> ComponentInfo {
        ComponentInfo {
            name: "test-component".to_string(),
            version: "1.0.0".to_string(),
            description: "A test component".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn text_without_tools() {
        let info = sample_info();
        let data = InfoData {
            info: &info,
            metadata_schema: None,
            tools: None,
        };
        let text = to_text(&data);
        assert!(text.contains("# test-component v1.0.0"));
        assert!(text.contains("A test component"));
        assert!(!text.contains("##"));
    }

    #[test]
    fn text_with_skill() {
        let mut info = sample_info();
        info.metadata.insert(
            COMPONENT_SKILL.to_string(),
            serde_json::json!("Use this tool when you need to query databases."),
        );
        let data = InfoData {
            info: &info,
            metadata_schema: None,
            tools: None,
        };
        let text = to_text(&data);
        assert!(text.contains("## Skill"));
        assert!(text.contains("Use this tool when you need to query databases."));
    }

    #[test]
    fn text_with_metadata_schema() {
        let info = sample_info();
        let schema = r#"{"type":"object","properties":{"api_key":{"type":"string"}}}"#;
        let data = InfoData {
            info: &info,
            metadata_schema: Some(schema),
            tools: None,
        };
        let text = to_text(&data);
        assert!(text.contains("## Metadata Schema"));
        assert!(text.contains("api_key"));
    }

    #[test]
    fn json_without_tools() {
        let info = sample_info();
        let data = InfoData {
            info: &info,
            metadata_schema: None,
            tools: None,
        };
        let json = to_json(&data);
        assert_eq!(json.name, "test-component");
        assert!(json.tools.is_none());
        assert!(json.skill.is_none());
    }

    #[test]
    fn json_serializes_cleanly() {
        let info = sample_info();
        let data = InfoData {
            info: &info,
            metadata_schema: None,
            tools: None,
        };
        let json = to_json(&data);
        let serialized = serde_json::to_string(&json).unwrap();
        assert!(serialized.contains("\"name\":\"test-component\""));
        // empty/None fields are skipped
        assert!(!serialized.contains("capabilities"));
        assert!(!serialized.contains("tools"));
        assert!(!serialized.contains("skill"));
    }

    #[test]
    fn text_with_capabilities() {
        let mut info = sample_info();
        info.capabilities
            .push(act_types::types::ComponentCapability {
                id: "wasi:filesystem".to_string(),
                required: true,
                description: None,
            });
        let data = InfoData {
            info: &info,
            metadata_schema: None,
            tools: None,
        };
        let text = to_text(&data);
        assert!(text.contains("wasi:filesystem (required)"));
    }
}
```

- [ ] **Step 2: Verify constants exist in act-types**

Run: `cd /mnt/devenv/workspace/act/act-sdk-rs && grep -E "META_USAGE_HINTS|META_ANTI_USAGE_HINTS|META_TAGS|META_STREAMING|META_TIMEOUT_MS|COMPONENT_SKILL" act-types/src/constants.rs`

Expected: all constants are defined. If any are missing, they need to be added to act-types first (separate task).

---

### Task 4: Implement `cmd_info` and `cmd_pull`

**Files:**
- Modify: `act-cli/src/main.rs` — add `cmd_info`, `cmd_pull`

- [ ] **Step 1: Add `cmd_info`**

This function:
- Always reads component info from custom section (no instantiation)
- With `--tools`: instantiates, calls `get-metadata-schema` and `list-tools`
- Passes everything to `format::to_text` or `format::to_json`

```rust
async fn cmd_info(
    component_path: PathBuf,
    show_tools: bool,
    output_format: OutputFormat,
    opts: CommonOpts,
) -> Result<()> {
    let wasm_bytes = std::fs::read(&component_path).context("reading component file")?;
    let component_info = runtime::read_component_info(&wasm_bytes)?;

    let mut metadata_schema_str: Option<String> = None;
    let mut tools: Option<Vec<runtime::act::core::types::ToolDefinition>> = None;

    if show_tools {
        let (_config, mut fs_config, metadata_value) = resolve_opts(&opts)?;
        let mount_root = component_info
            .metadata
            .get(act_types::constants::COMPONENT_FS_MOUNT_ROOT)
            .and_then(|v| v.as_str())
            .unwrap_or("/");
        config::apply_mount_root(&mut fs_config, mount_root);
        runtime::warn_missing_capabilities(&component_info, &fs_config);

        let metadata_kv: runtime::Metadata = metadata_value
            .as_ref()
            .map(|v| runtime::Metadata::from(v.clone()))
            .unwrap_or_default();

        let engine = runtime::create_engine()?;
        let component = runtime::load_component(&engine, &component_path)?;
        let linker = runtime::create_linker(&engine)?;
        let (instance, store) =
            runtime::instantiate_component(&engine, &component, &linker, &fs_config).await?;

        let component_handle = runtime::spawn_component_actor(instance, store);

        // Get metadata schema
        let (schema_tx, schema_rx) = tokio::sync::oneshot::channel();
        let schema_req = runtime::ComponentRequest::GetMetadataSchema {
            metadata: metadata_kv.clone(),
            reply: schema_tx,
        };
        component_handle
            .send(schema_req)
            .await
            .map_err(|_| anyhow::anyhow!("component actor unavailable"))?;
        if let Ok(Ok(schema)) = schema_rx.await {
            metadata_schema_str = schema;
        }

        // List tools
        let (tools_tx, tools_rx) = tokio::sync::oneshot::channel();
        let tools_req = runtime::ComponentRequest::ListTools {
            metadata: metadata_kv,
            reply: tools_tx,
        };
        component_handle
            .send(tools_req)
            .await
            .map_err(|_| anyhow::anyhow!("component actor unavailable"))?;
        match tools_rx.await? {
            Ok(list_response) => {
                tools = Some(list_response.tools);
            }
            Err(runtime::ComponentError::Tool(te)) => {
                let ls = act_types::types::LocalizedString::from(&te.message);
                anyhow::bail!("{}: {}", te.kind, ls.any_text());
            }
            Err(runtime::ComponentError::Internal(e)) => return Err(e),
        }
    }

    let data = format::InfoData {
        info: &component_info,
        metadata_schema: metadata_schema_str.as_deref(),
        tools: tools.as_deref(),
    };

    match output_format {
        OutputFormat::Json => {
            let json = format::to_json(&data);
            println!("{}", serde_json::to_string(&json)?);
        }
        OutputFormat::Text => {
            let text = format::to_text(&data);
            print!("{text}");
        }
    }

    Ok(())
}
```

- [ ] **Step 2: Add `cmd_pull` skeleton**

```rust
async fn cmd_pull(
    reference: String,
    _output: Option<PathBuf>,
    _output_from_ref: bool,
) -> Result<()> {
    anyhow::bail!(
        "pull is not yet implemented. Reference: {reference}\n\
         Planned: OCI registry and HTTP URL download support."
    )
}
```

- [ ] **Step 3: Verify full compilation**

Run: `cd /mnt/devenv/workspace/act/act-cli && cargo check`

Expected: clean, zero errors. If act-types is missing constants, see step 2 from Task 3 — add them first.

- [ ] **Step 4: Run all tests**

Run: `cd /mnt/devenv/workspace/act/act-cli && cargo test --target x86_64-unknown-linux-gnu`

Expected: all existing tests pass + new format tests pass.

- [ ] **Step 5: Verify help output**

Run: `cd /mnt/devenv/workspace/act/act-cli && cargo run -- --help`

Expected:
```
ACT — Agent Component Tools CLI

Usage: act <COMMAND>

Commands:
  run   Run a component (serve over HTTP or MCP stdio)
  call  Call a tool directly and print the result
  info  Show component info, metadata, and optionally list tools
  pull  Download a component from OCI registry or HTTP URL
  help  Print this message or the help of the given subcommand(s)
```

- [ ] **Step 6: Commit**

```bash
cd /mnt/devenv/workspace/act/act-cli
git add src/main.rs src/format.rs
git commit -m "feat!: restructure CLI commands

BREAKING: replace serve/mcp/info/tools with unified commands:
- act run [-m] [-l [addr]] — unified serve (MCP stdio or ACT-HTTP)
- act info [--tools] [--format text|json] — rich introspection
  (shows std:skill, metadata-schema, tool annotations/hints/tags)
- act pull <ref> — download skeleton (not yet implemented)
- act call — unchanged

Removed: act serve, act mcp, act tools"
```

---

### Task 5: Verify missing constants and add if needed

**Files:**
- Possibly modify: `act-sdk-rs/act-types/src/constants.rs`

- [ ] **Step 1: Check which constants exist**

Run: `cd /mnt/devenv/workspace/act/act-sdk-rs && grep -E "COMPONENT_SKILL|META_USAGE_HINTS|META_ANTI_USAGE_HINTS|META_TAGS|META_STREAMING|META_TIMEOUT_MS|META_READ_ONLY|META_IDEMPOTENT|META_DESTRUCTIVE" act-types/src/constants.rs`

- [ ] **Step 2: Add any missing constants**

For each missing constant, add to `act-types/src/constants.rs` following the pattern of existing ones. The values come from ACT-CONSTANTS.md section 3:

```rust
// Tool Definition Metadata (section 3)
pub const META_READ_ONLY: &str = "std:read-only";
pub const META_IDEMPOTENT: &str = "std:idempotent";
pub const META_DESTRUCTIVE: &str = "std:destructive";
pub const META_STREAMING: &str = "std:streaming";
pub const META_TIMEOUT_MS: &str = "std:timeout-ms";
pub const META_USAGE_HINTS: &str = "std:usage-hints";
pub const META_ANTI_USAGE_HINTS: &str = "std:anti-usage-hints";
pub const META_EXAMPLES: &str = "std:examples";
pub const META_TAGS: &str = "std:tags";

// Component Info (section 2)
pub const COMPONENT_SKILL: &str = "std:skill";
```

- [ ] **Step 3: Commit if changes were needed**

```bash
cd /mnt/devenv/workspace/act/act-sdk-rs
git add act-types/src/constants.rs
git commit -m "feat: add missing std: constants for tool metadata and skill"
```

Only commit if new constants were added. Skip if all already exist.
