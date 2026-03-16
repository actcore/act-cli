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

#[derive(Parser)]
#[command(name = "act", about = "ACT — Agent Component Tools CLI")]
enum Cli {
    /// Load a .wasm component and serve it as an ACT-HTTP server
    Serve {
        /// Path to the .wasm component file
        component: PathBuf,

        /// Address to listen on (host:port)
        #[arg(short, long, default_value = "[::1]:3000")]
        listen: SocketAddr,
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

        /// JSON metadata to pass to the component
        #[arg(short, long)]
        metadata: Option<String>,

        /// Path to a JSON metadata file
        #[arg(long)]
        metadata_file: Option<PathBuf>,
    },
    /// Load a .wasm component and serve it as an MCP server over stdio
    Mcp {
        /// Path to the .wasm component file
        component: PathBuf,

        /// JSON metadata to pass to the component
        #[arg(short, long)]
        metadata: Option<String>,

        /// Path to a JSON metadata file
        #[arg(long)]
        metadata_file: Option<PathBuf>,
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

        /// JSON metadata to pass to the component
        #[arg(short, long)]
        metadata: Option<String>,

        /// Path to a JSON metadata file
        #[arg(long)]
        metadata_file: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "act_cli=info".parse().expect("valid default filter"));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .init();

    match cli {
        Cli::Serve { component, listen } => serve(component, listen).await,
        Cli::Call {
            component,
            tool,
            args,
            metadata,
            metadata_file,
        } => cli_call_tool(component, tool, args, metadata, metadata_file).await,
        Cli::Mcp {
            component,
            metadata,
            metadata_file,
        } => mcp_serve(component, metadata, metadata_file).await,
        Cli::Info { component } => cli_info(component).await,
        Cli::Tools {
            component,
            metadata,
            metadata_file,
        } => cli_tools(component, metadata, metadata_file).await,
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

async fn cli_call_tool(
    component_path: PathBuf,
    tool: String,
    args: String,
    metadata: Option<String>,
    metadata_file: Option<PathBuf>,
) -> Result<()> {
    let metadata_json = parse_cli_metadata(metadata, metadata_file)?;
    let metadata_kv: runtime::Metadata = metadata_json
        .as_ref()
        .map(|v| runtime::Metadata::from(v.clone()))
        .unwrap_or_default();

    let arguments: serde_json::Value =
        serde_json::from_str(&args).context("invalid --args JSON")?;
    let cbor_args = cbor::json_to_cbor(&arguments).context("encoding args as CBOR")?;

    let engine = runtime::create_engine()?;
    let component = runtime::load_component(&engine, &component_path)?;
    let linker = runtime::create_linker(&engine)?;
    let (instance, store) = runtime::instantiate_component(&engine, &component, &linker).await?;

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

async fn mcp_serve(
    component_path: PathBuf,
    metadata: Option<String>,
    metadata_file: Option<PathBuf>,
) -> Result<()> {
    let metadata_json = parse_cli_metadata(metadata, metadata_file)?;
    let metadata_kv: runtime::Metadata = metadata_json
        .as_ref()
        .map(|v| runtime::Metadata::from(v.clone()))
        .unwrap_or_default();

    let wasm_bytes = std::fs::read(&component_path).context("reading component file")?;
    let component_info = runtime::read_component_info(&wasm_bytes)?;

    let engine = runtime::create_engine()?;
    let component = runtime::load_component(&engine, &component_path)?;
    let linker = runtime::create_linker(&engine)?;
    let (instance, store) = runtime::instantiate_component(&engine, &component, &linker).await?;

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

async fn cli_tools(
    component_path: PathBuf,
    metadata: Option<String>,
    metadata_file: Option<PathBuf>,
) -> Result<()> {
    let metadata_json = parse_cli_metadata(metadata, metadata_file)?;
    let metadata_kv: runtime::Metadata = metadata_json
        .as_ref()
        .map(|v| runtime::Metadata::from(v.clone()))
        .unwrap_or_default();

    let engine = runtime::create_engine()?;
    let component = runtime::load_component(&engine, &component_path)?;
    let linker = runtime::create_linker(&engine)?;
    let (instance, store) = runtime::instantiate_component(&engine, &component, &linker).await?;

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

async fn serve(component_path: PathBuf, addr: SocketAddr) -> Result<()> {
    let wasm_bytes = std::fs::read(&component_path).context("reading component file")?;
    let component_info = runtime::read_component_info(&wasm_bytes)?;

    let engine = runtime::create_engine()?;
    let component = runtime::load_component(&engine, &component_path)?;
    let linker = runtime::create_linker(&engine)?;

    let (instance, store) = runtime::instantiate_component(&engine, &component, &linker).await?;

    tracing::info!(
        name = %component_info.name,
        version = %component_info.version,
        "Loaded component"
    );

    let component_handle = runtime::spawn_component_actor(instance, store);

    let state = Arc::new(http::AppState {
        info: component_info,
        component: component_handle,
    });

    tracing::info!(%addr, component = %component_path.display(), "ACT host listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, http::create_router(state))
        .await
        .context("server error")?;

    Ok(())
}
