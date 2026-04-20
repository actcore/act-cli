mod config;
mod format;
mod http;
mod mcp;
mod resolve;
mod runtime;

use act_types::cbor;
use resolve::ComponentRef;

use anyhow::{Context, Result};
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(clap::Args, Clone, Debug)]
struct CommonOpts {
    /// JSON metadata to pass to the component
    #[arg(short, long)]
    metadata: Option<String>,
    /// Path to a JSON metadata file
    #[arg(long)]
    metadata_file: Option<PathBuf>,

    /// Filesystem policy mode: deny | allowlist | open
    #[arg(long = "fs-policy")]
    fs_policy: Option<String>,
    /// Filesystem allow entry (path or path/**). Repeatable.
    #[arg(long = "fs-allow")]
    fs_allow: Vec<String>,
    /// Filesystem deny entry. Repeatable.
    #[arg(long = "fs-deny")]
    fs_deny: Vec<String>,

    /// HTTP policy mode: deny | allowlist | open
    #[arg(long = "http-policy")]
    http_policy: Option<String>,
    /// HTTP allow entry: hostname (`api.example.com`) or CIDR (`10.0.0.0/8`). Repeatable.
    #[arg(long = "http-allow")]
    http_allow: Vec<String>,
    /// HTTP deny entry. Repeatable.
    #[arg(long = "http-deny")]
    http_deny: Vec<String>,

    /// Use a named profile from the config file
    #[arg(long)]
    profile: Option<String>,
    /// Override config file location
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(clap::ValueEnum, Clone, Debug, Default)]
enum OutputFormat {
    #[default]
    Text,
    Json,
}

#[derive(Parser)]
#[command(name = "act", version, about = "ACT — Agent Component Tools CLI")]
enum Cli {
    /// Load a .wasm component and serve it (HTTP or MCP)
    Run {
        /// Component reference (path, URL, OCI ref, or name)
        component: ComponentRef,

        /// Serve over MCP stdio
        #[arg(long)]
        mcp: bool,

        /// Serve over ACT-HTTP
        #[arg(long)]
        http: bool,

        /// Listen address: [host]:port or just port (default: [::1]:3000)
        #[arg(short, long)]
        listen: Option<String>,

        #[command(flatten)]
        opts: CommonOpts,
    },
    /// Call a tool directly and print the result
    Call {
        /// Component reference (path, URL, OCI ref, or name)
        component: ComponentRef,

        /// Tool name to call
        tool: String,

        /// JSON arguments
        #[arg(long, default_value = "{}")]
        args: String,

        #[command(flatten)]
        opts: CommonOpts,
    },
    /// Show component info and optionally list tools
    Info {
        /// Component reference (path, URL, OCI ref, or name)
        component: ComponentRef,

        /// Instantiate component and list tools with full metadata
        #[arg(short, long)]
        tools: bool,

        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,

        #[command(flatten)]
        opts: CommonOpts,
    },
    /// Extract embedded Agent Skills from a component
    Skill {
        /// Component reference (path, URL, OCI ref, or name)
        component: ComponentRef,

        /// Output directory (default: .agents/skills/<name>/)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Pull a component from a registry
    Pull {
        /// Component reference (OCI ref, HTTP URL, or local path)
        #[arg(name = "ref")]
        reference: ComponentRef,

        /// Output file path
        #[arg(short = 'o')]
        output: Option<PathBuf>,

        /// Derive output filename from the ref
        #[arg(short = 'O', conflicts_with = "output")]
        output_from_ref: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Resolve log level: RUST_LOG env > config file log-level > default "act_cli=info"
    let env_filter = if std::env::var("RUST_LOG").is_ok() {
        tracing_subscriber::EnvFilter::from_default_env()
    } else {
        // Try loading config to get log-level (best effort — don't fail on missing config)
        let config_path = match &cli {
            Cli::Run { opts, .. } | Cli::Call { opts, .. } | Cli::Info { opts, .. } => {
                opts.config.as_deref()
            }
            Cli::Skill { .. } | Cli::Pull { .. } => None,
        };
        let log_level = config::load_config(config_path)
            .ok()
            .and_then(|c| c.log_level);
        let directive = match log_level.as_deref() {
            Some(level) => format!("act={level}"),
            None => "act=info".to_string(),
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
            http,
            listen,
            opts,
        } => cmd_run(component, mcp, http, listen, opts).await,
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
        Cli::Skill { component, output } => cmd_skill(component, output).await,
        Cli::Pull {
            reference,
            output,
            output_from_ref,
        } => cmd_pull(reference, output, output_from_ref).await,
    }
}

/// Parse JSON metadata from --metadata or --metadata-file CLI arguments.
fn parse_cli_metadata(
    metadata: Option<String>,
    metadata_file: Option<PathBuf>,
) -> Result<Option<serde_json::Value>> {
    match (metadata, metadata_file) {
        (Some(json_str), _) => Ok(Some(
            serde_json::from_str(&json_str).context("invalid --metadata JSON")?,
        )),
        (_, Some(path)) => {
            let contents = std::fs::read_to_string(&path).context("reading metadata file")?;
            Ok(Some(
                serde_json::from_str(&contents).context("invalid metadata file JSON")?,
            ))
        }
        (None, None) => Ok(None),
    }
}

struct ResolvedOpts {
    #[allow(dead_code)]
    config_file: config::ConfigFile,
    fs: config::FsConfig,
    http: config::HttpConfig,
    metadata: Option<serde_json::Value>,
}

fn resolve_opts(opts: &CommonOpts) -> Result<ResolvedOpts> {
    let config_file = config::load_config(opts.config.as_deref())?;
    let profile = match &opts.profile {
        Some(name) => Some(config::get_profile(&config_file, name)?),
        None => None,
    };
    let cli_overrides = config::CliPolicyOverrides {
        fs_mode: opts.fs_policy.clone(),
        fs_allow: opts.fs_allow.clone(),
        fs_deny: opts.fs_deny.clone(),
        http_mode: opts.http_policy.clone(),
        http_allow: opts.http_allow.clone(),
        http_deny: opts.http_deny.clone(),
    };
    let fs = config::resolve_fs_config(&config_file, profile, &cli_overrides)?;
    let http = config::resolve_http_config(&config_file, profile, &cli_overrides)?;
    let cli_metadata = parse_cli_metadata(opts.metadata.clone(), opts.metadata_file.clone())?;
    let merged_metadata = config::resolve_metadata(profile, cli_metadata.as_ref());
    let metadata = if merged_metadata.is_null() {
        None
    } else {
        Some(merged_metadata)
    };
    Ok(ResolvedOpts {
        config_file,
        fs,
        http,
        metadata,
    })
}

// ── Common component setup ───────────────────────────────────────────────────

/// A fully loaded and instantiated component, ready for tool calls.
struct PreparedComponent {
    info: runtime::ComponentInfo,
    handle: runtime::ComponentHandle,
    metadata: runtime::Metadata,
}

/// Resolve, load, and instantiate a component. Returns a running actor handle.
async fn prepare_component(
    component: &ComponentRef,
    opts: &CommonOpts,
) -> Result<PreparedComponent> {
    let resolved = resolve_opts(opts)?;

    let component_path = resolve::resolve(component, false).await?;
    let wasm_bytes = std::fs::read(&component_path).context("reading component file")?;
    let info = runtime::read_component_info(&wasm_bytes)?;

    let fs = resolved.fs;
    let http = resolved.http;

    let mut preopens = runtime::fs_policy::derive_preopens(&fs);
    let mount_root = info.std.capabilities.fs_mount_root().unwrap_or("/");
    runtime::fs_policy::apply_mount_root(&mut preopens, mount_root);

    let metadata: runtime::Metadata = resolved
        .metadata
        .as_ref()
        .map(|v| runtime::Metadata::from(v.clone()))
        .unwrap_or_default();

    tracing::info!(
        name = %info.std.name,
        version = %info.std.version,
        path = %component_path.display(),
        "Loading component"
    );

    let engine = runtime::create_engine()?;
    let wasm = runtime::load_component(&engine, &component_path)?;
    let linker = runtime::create_linker(&engine)?;
    let (instance, store) =
        runtime::instantiate_component(&engine, &wasm, &linker, &preopens, &http, &fs, &info)
            .await?;
    let handle = runtime::spawn_component_actor(instance, store);

    tracing::info!(name = %info.std.name, version = %info.std.version, "Component ready");

    Ok(PreparedComponent {
        info,
        handle,
        metadata,
    })
}

// ── Commands ─────────────────────────────────────────────────────────────────

/// Parse a listen address: either `[host]:port` or just a port number.
fn parse_listen_addr(s: &str) -> Result<SocketAddr> {
    // Try as full socket address first
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    // Try as port number
    if let Ok(port) = s.parse::<u16>() {
        return Ok(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port)));
    }
    anyhow::bail!("invalid listen address: {s} (expected [host]:port or port number)")
}

async fn cmd_run(
    component: ComponentRef,
    mcp: bool,
    http: bool,
    listen: Option<String>,
    opts: CommonOpts,
) -> Result<()> {
    if mcp && http {
        anyhow::bail!("--mcp and --http are mutually exclusive");
    }

    if mcp {
        let pc = prepare_component(&component, &opts).await?;
        return mcp::run_stdio(pc.info, pc.handle, pc.metadata).await;
    }

    if http || listen.is_some() {
        let addr = match &listen {
            Some(s) => parse_listen_addr(s)?,
            None => "[::1]:3000".parse().unwrap(),
        };

        let pc = prepare_component(&component, &opts).await?;

        let state = Arc::new(http::AppState {
            info: pc.info,
            component: pc.handle,
            metadata: pc.metadata,
        });

        tracing::info!(%addr, "ACT host listening");

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, http::create_router(state))
            .await
            .context("server error")?;
        return Ok(());
    }

    anyhow::bail!("Specify a transport: --http (ACT-HTTP server) or --mcp (MCP stdio)")
}

async fn cmd_call(
    component: ComponentRef,
    tool: String,
    args: String,
    opts: CommonOpts,
) -> Result<()> {
    let pc = prepare_component(&component, &opts).await?;

    let arguments: serde_json::Value =
        serde_json::from_str(&args).context("invalid --args JSON")?;
    let cbor_args = cbor::json_to_cbor(&arguments).context("encoding args as CBOR")?;

    let tool_call = runtime::act::core::types::ToolCall {
        name: tool,
        arguments: cbor_args,
        metadata: pc.metadata.clone().into(),
    };

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::CallTool {
        call: tool_call,
        reply: reply_tx,
    };

    pc.handle
        .send(request)
        .await
        .map_err(|_| anyhow::anyhow!("component actor unavailable"))?;

    match reply_rx.await? {
        Ok(result) => {
            for event in &result.events {
                match event {
                    runtime::act::core::types::ToolEvent::Content(part) => {
                        let mime = part.mime_type.as_deref().unwrap_or("application/cbor");
                        if mime.starts_with("text/")
                            || mime == "application/json"
                            || mime == "application/xml"
                        {
                            let text = String::from_utf8_lossy(&part.data);
                            println!("{text}");
                        } else if mime == "application/cbor" {
                            let json_val = act_types::cbor::cbor_to_json(&part.data)
                                .unwrap_or_else(|_| {
                                    serde_json::Value::String(format!(
                                        "[binary: {}, {} bytes]",
                                        mime,
                                        part.data.len()
                                    ))
                                });
                            match json_val {
                                serde_json::Value::String(s) => println!("{s}"),
                                other => println!("{}", serde_json::to_string_pretty(&other)?),
                            }
                        } else if std::io::IsTerminal::is_terminal(&std::io::stdout()) {
                            println!("[binary: {}, {} bytes]", mime, part.data.len());
                        } else {
                            use std::io::Write;
                            std::io::stdout().write_all(&part.data)?;
                        }
                    }
                    runtime::act::core::types::ToolEvent::Error(err) => {
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

async fn cmd_info(
    component: ComponentRef,
    show_tools: bool,
    output_format: OutputFormat,
    opts: CommonOpts,
) -> Result<()> {
    // Without --tools: just read custom section, no instantiation
    let component_path = resolve::resolve(&component, false).await?;
    let wasm_bytes = std::fs::read(&component_path).context("reading component file")?;
    let component_info = runtime::read_component_info(&wasm_bytes)?;

    let (metadata_schema, tools) = if show_tools {
        let pc = prepare_component(&component, &opts).await?;

        // Get metadata schema
        let (schema_tx, schema_rx) = tokio::sync::oneshot::channel();
        pc.handle
            .send(runtime::ComponentRequest::GetMetadataSchema {
                metadata: pc.metadata.clone(),
                reply: schema_tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("component actor unavailable"))?;

        let metadata_schema = match schema_rx.await? {
            Ok(schema) => schema,
            Err(runtime::ComponentError::Tool(te)) => {
                let ls = act_types::types::LocalizedString::from(&te.message);
                tracing::warn!("get-metadata-schema error: {}: {}", te.kind, ls.any_text());
                None
            }
            Err(runtime::ComponentError::Internal(e)) => {
                tracing::warn!("get-metadata-schema internal error: {e}");
                None
            }
        };

        // List tools
        let (tools_tx, tools_rx) = tokio::sync::oneshot::channel();
        pc.handle
            .send(runtime::ComponentRequest::ListTools {
                metadata: pc.metadata,
                reply: tools_tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("component actor unavailable"))?;

        let tools = match tools_rx.await? {
            Ok(list_response) => list_response.tools,
            Err(runtime::ComponentError::Tool(te)) => {
                let ls = act_types::types::LocalizedString::from(&te.message);
                anyhow::bail!("list-tools error: {}: {}", te.kind, ls.any_text());
            }
            Err(runtime::ComponentError::Internal(e)) => return Err(e),
        };

        (metadata_schema, Some(tools))
    } else {
        (None, None)
    };

    let data = format::InfoData {
        info: &component_info,
        metadata_schema,
        tools,
    };

    match output_format {
        OutputFormat::Text => print!("{}", format::to_text(&data)),
        OutputFormat::Json => {
            let json = format::to_json(&data)?;
            println!("{json}");
        }
    }

    Ok(())
}

async fn cmd_skill(component: ComponentRef, output: Option<PathBuf>) -> Result<()> {
    let component_path = resolve::resolve(&component, false).await?;
    let wasm_bytes = std::fs::read(&component_path).context("reading component file")?;

    // Find act:skill custom section
    let mut skill_data: Option<Vec<u8>> = None;
    for payload in wasmparser::Parser::new(0).parse_all(&wasm_bytes) {
        if let Ok(wasmparser::Payload::CustomSection(section)) = payload
            && section.name() == "act:skill"
        {
            skill_data = Some(section.data().to_vec());
            break;
        }
    }

    let tar_bytes = skill_data.context("component does not contain an act:skill section")?;

    // Determine output directory
    let component_info = runtime::read_component_info(&wasm_bytes)?;
    let out_dir = output.unwrap_or_else(|| {
        PathBuf::from(".agents")
            .join("skills")
            .join(&component_info.std.name)
    });

    std::fs::create_dir_all(&out_dir).with_context(|| format!("creating {}", out_dir.display()))?;

    // Extract tar
    let cursor = std::io::Cursor::new(tar_bytes);
    let mut archive = tar::Archive::new(cursor);
    archive
        .unpack(&out_dir)
        .with_context(|| format!("extracting skill to {}", out_dir.display()))?;

    println!("{}", out_dir.display());
    Ok(())
}

async fn cmd_pull(
    reference: ComponentRef,
    output: Option<PathBuf>,
    output_from_ref: bool,
) -> Result<()> {
    // Resolve to local path (downloads to cache for remote refs)
    // Always download fresh — pull is explicit user action
    let cached_path = resolve::resolve(&reference, true).await?;

    if let Some(out) = output {
        tokio::fs::copy(&cached_path, &out)
            .await
            .with_context(|| format!("copying to {}", out.display()))?;
        println!("{}", out.display());
    } else if output_from_ref {
        let ref_str = reference.to_string();
        let base = ref_str
            .rsplit('/')
            .next()
            .unwrap_or(&ref_str)
            .split(':')
            .next()
            .unwrap_or(&ref_str);
        let filename = if base.ends_with(".wasm") {
            base.to_string()
        } else {
            format!("{base}.wasm")
        };
        let out = PathBuf::from(&filename);
        tokio::fs::copy(&cached_path, &out)
            .await
            .with_context(|| format!("copying to {}", out.display()))?;
        println!("{}", out.display());
    } else {
        // No output flag — print cached path
        println!("{}", cached_path.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn parse_cli_metadata_from_string() {
        let result = parse_cli_metadata(Some(r#"{"key":"value"}"#.to_string()), None).unwrap();
        assert_eq!(result, Some(serde_json::json!({"key": "value"})));
    }

    #[test]
    fn parse_cli_metadata_from_file() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, r#"{{"port": 8080}}"#).unwrap();
        let result = parse_cli_metadata(None, Some(file.path().to_path_buf())).unwrap();
        assert_eq!(result, Some(serde_json::json!({"port": 8080})));
    }

    #[test]
    fn parse_cli_metadata_none() {
        let result = parse_cli_metadata(None, None).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn parse_cli_metadata_string_takes_precedence() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, r#"{{"from":"file"}}"#).unwrap();
        let result = parse_cli_metadata(
            Some(r#"{"from":"arg"}"#.to_string()),
            Some(file.path().to_path_buf()),
        )
        .unwrap();
        assert_eq!(result, Some(serde_json::json!({"from": "arg"})));
    }

    #[test]
    fn parse_cli_metadata_invalid_json() {
        assert!(parse_cli_metadata(Some("not json".to_string()), None).is_err());
    }

    #[test]
    fn metadata_from_json_object() {
        let json = serde_json::json!({"key": "value"});
        let meta = runtime::Metadata::from(json.clone());
        assert_eq!(meta.len(), 1);
        assert_eq!(meta.get("key"), Some(&serde_json::json!("value")));
    }

    #[test]
    fn metadata_from_json_non_object_is_empty() {
        let json = serde_json::json!("not an object");
        let meta = runtime::Metadata::from(json.clone());
        assert!(meta.is_empty());
    }
}
