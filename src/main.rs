mod config;
mod http;
mod mcp;
mod runtime;

use act_types::cbor;

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
    /// Map a host directory to a guest path (guest:host). Repeatable.
    #[arg(long = "allow-dir")]
    allow_dir: Vec<String>,
    /// Grant full filesystem access (host / → guest /)
    #[arg(long = "allow-fs")]
    allow_fs: bool,
    /// Use a named profile from the config file
    #[arg(long)]
    profile: Option<String>,
    /// Override config file location
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Parser)]
#[command(name = "act", about = "ACT — Agent Component Tools CLI")]
enum Cli {
    /// Load a .wasm component and serve it as an ACT-HTTP server
    Serve {
        /// Path to the .wasm component file
        component: PathBuf,

        /// Address to listen on (host:port). Default: [::1]:3000
        #[arg(short, long)]
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
    /// Load a .wasm component and serve it as an MCP server over stdio
    Mcp {
        /// Path to the .wasm component file
        component: PathBuf,

        #[command(flatten)]
        opts: CommonOpts,
    },
    /// Show component info (name, version, description, capabilities)
    Info {
        /// Path to the .wasm component file
        component: PathBuf,
    },
    /// List tools exposed by a component
    Tools {
        /// Path to the .wasm component file
        component: PathBuf,

        #[command(flatten)]
        opts: CommonOpts,
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
            Cli::Serve { opts, .. }
            | Cli::Call { opts, .. }
            | Cli::Mcp { opts, .. }
            | Cli::Tools { opts, .. } => opts.config.as_deref(),
            Cli::Info { .. } => None,
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
        Cli::Serve {
            component,
            listen,
            opts,
        } => serve(component, listen, opts).await,
        Cli::Call {
            component,
            tool,
            args,
            opts,
        } => cli_call_tool(component, tool, args, opts).await,
        Cli::Mcp { component, opts } => mcp_serve(component, opts).await,
        Cli::Info { component } => cli_info(component).await,
        Cli::Tools { component, opts } => cli_tools(component, opts).await,
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

fn resolve_opts(
    opts: &CommonOpts,
) -> Result<(
    config::ConfigFile,
    config::FsConfig,
    Option<serde_json::Value>,
)> {
    let config_file = config::load_config(opts.config.as_deref())?;
    let profile = match &opts.profile {
        Some(name) => Some(config::get_profile(&config_file, name)?),
        None => None,
    };
    let cli_overrides = config::CliOverrides {
        allow_fs: opts.allow_fs,
        allow_dir: opts.allow_dir.clone(),
    };
    let fs_config = config::resolve_fs_config(&config_file, profile, &cli_overrides)?;
    let cli_metadata = parse_cli_metadata(opts.metadata.clone(), opts.metadata_file.clone())?;
    let merged_metadata = config::resolve_metadata(profile, cli_metadata.as_ref());
    let metadata = if merged_metadata.is_null() {
        None
    } else {
        Some(merged_metadata)
    };
    Ok((config_file, fs_config, metadata))
}

async fn cli_call_tool(
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

async fn mcp_serve(component_path: PathBuf, opts: CommonOpts) -> Result<()> {
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

async fn cli_info(component_path: PathBuf) -> Result<()> {
    let wasm_bytes = std::fs::read(&component_path).context("reading component file")?;
    let info = runtime::read_component_info(&wasm_bytes)?;

    println!("{} v{}", info.name, info.version);
    println!("{}", info.description);
    Ok(())
}

async fn cli_tools(component_path: PathBuf, opts: CommonOpts) -> Result<()> {
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

    let component_handle = runtime::spawn_component_actor(instance, store);

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::ListTools {
        metadata: metadata_kv.clone(),
        reply: reply_tx,
    };

    component_handle
        .send(request)
        .await
        .map_err(|_| anyhow::anyhow!("component actor unavailable"))?;

    match reply_rx.await? {
        Ok(list_response) => {
            for td in &list_response.tools {
                let ls = act_types::types::LocalizedString::from(&td.description);
                println!("  {} — {}", td.name, ls.any_text());
            }
        }
        Err(runtime::ComponentError::Tool(te)) => {
            let ls = act_types::types::LocalizedString::from(&te.message);
            anyhow::bail!("{}: {}", te.kind, ls.any_text());
        }
        Err(runtime::ComponentError::Internal(e)) => return Err(e),
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

async fn serve(
    component_path: PathBuf,
    cli_listen: Option<SocketAddr>,
    opts: CommonOpts,
) -> Result<()> {
    let (config, mut fs_config, metadata_value) = resolve_opts(&opts)?;

    // Resolve listen address: CLI flag > config file > default
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
