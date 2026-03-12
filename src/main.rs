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

        /// JSON config to pass to the component
        #[arg(short, long)]
        config: Option<String>,

        /// Path to a JSON config file
        #[arg(long)]
        config_file: Option<PathBuf>,
    },
    /// Load a .wasm component and serve it as an MCP server over stdio
    Mcp {
        /// Path to the .wasm component file
        component: PathBuf,

        /// JSON config to pass to the component
        #[arg(short, long)]
        config: Option<String>,

        /// Path to a JSON config file
        #[arg(long)]
        config_file: Option<PathBuf>,
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

        /// JSON config to pass to the component
        #[arg(short, long)]
        config: Option<String>,

        /// Path to a JSON config file
        #[arg(long)]
        config_file: Option<PathBuf>,
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
            config,
            config_file,
        } => cli_call_tool(component, tool, args, config, config_file).await,
        Cli::Mcp {
            component,
            config,
            config_file,
        } => mcp_serve(component, config, config_file).await,
        Cli::Info { component } => cli_info(component).await,
        Cli::Tools {
            component,
            config,
            config_file,
        } => cli_tools(component, config, config_file).await,
    }
}

/// Parse JSON config from --config or --config-file CLI arguments.
fn parse_cli_config(
    config: Option<String>,
    config_file: Option<PathBuf>,
) -> Result<Option<serde_json::Value>> {
    match (config, config_file) {
        (Some(json_str), _) => {
            Ok(Some(serde_json::from_str(&json_str).context("invalid --config JSON")?))
        }
        (_, Some(path)) => {
            let contents = std::fs::read_to_string(&path).context("reading config file")?;
            Ok(Some(serde_json::from_str(&contents).context("invalid config file JSON")?))
        }
        (None, None) => Ok(None),
    }
}

async fn cli_call_tool(
    component_path: PathBuf,
    tool: String,
    args: String,
    config: Option<String>,
    config_file: Option<PathBuf>,
) -> Result<()> {
    let config_json = parse_cli_config(config, config_file)?;
    let cbor_config = config_json
        .map(|v| cbor::json_to_cbor(&v))
        .transpose()
        .context("encoding config as CBOR")?;

    let arguments: serde_json::Value =
        serde_json::from_str(&args).context("invalid --args JSON")?;
    let cbor_args = cbor::json_to_cbor(&arguments).context("encoding args as CBOR")?;

    let engine = runtime::create_engine()?;
    let component = runtime::load_component(&engine, &component_path)?;
    let linker = runtime::create_linker(&engine)?;
    let (instance, _component_info, _config_schema, store) =
        runtime::instantiate_component(&engine, &component, &linker).await?;

    let component_handle = runtime::spawn_component_actor(instance, store);

    let tool_call = runtime::act::core::types::ToolCall {
        name: tool,
        arguments: cbor_args,
        metadata: Vec::new(),
    };

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::CallTool {
        config: cbor_config,
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
    config: Option<String>,
    config_file: Option<PathBuf>,
) -> Result<()> {
    let config_json = parse_cli_config(config, config_file)?;
    let cbor_config = config_json
        .map(|v| cbor::json_to_cbor(&v))
        .transpose()
        .context("encoding config as CBOR")?;

    let engine = runtime::create_engine()?;
    let component = runtime::load_component(&engine, &component_path)?;
    let linker = runtime::create_linker(&engine)?;
    let (instance, component_info, _config_schema, store) =
        runtime::instantiate_component(&engine, &component, &linker).await?;

    tracing::info!(
        name = %component_info.name,
        version = %component_info.version,
        "Loaded component (MCP stdio)"
    );

    let component_handle = runtime::spawn_component_actor(instance, store);

    mcp::run_stdio(component_info, component_handle, cbor_config).await
}

async fn cli_info(component_path: PathBuf) -> Result<()> {
    let engine = runtime::create_engine()?;
    let component = runtime::load_component(&engine, &component_path)?;
    let linker = runtime::create_linker(&engine)?;
    let (_instance, info, _config_schema, _store) =
        runtime::instantiate_component(&engine, &component, &linker).await?;

    let ls = act_types::types::LocalizedString::from(&info.description);
    println!("{} v{}", info.name, info.version);
    println!("{}", ls.any_text());
    if !info.capabilities.is_empty() {
        println!("\nCapabilities:");
        for cap in &info.capabilities {
            let req = if cap.required { " (required)" } else { "" };
            println!("  {}{}", cap.id, req);
        }
    }
    Ok(())
}

async fn cli_tools(
    component_path: PathBuf,
    config: Option<String>,
    config_file: Option<PathBuf>,
) -> Result<()> {
    let config_json = parse_cli_config(config, config_file)?;
    let cbor_config = config_json
        .map(|v| cbor::json_to_cbor(&v))
        .transpose()
        .context("encoding config as CBOR")?;

    let engine = runtime::create_engine()?;
    let component = runtime::load_component(&engine, &component_path)?;
    let linker = runtime::create_linker(&engine)?;
    let (instance, _info, _config_schema, store) =
        runtime::instantiate_component(&engine, &component, &linker).await?;

    let component_handle = runtime::spawn_component_actor(instance, store);

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::ListTools {
        config: cbor_config,
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

async fn serve(component_path: PathBuf, addr: SocketAddr) -> Result<()> {
    let engine = runtime::create_engine()?;
    let component = runtime::load_component(&engine, &component_path)?;
    let linker = runtime::create_linker(&engine)?;

    let (instance, component_info, config_schema, store) =
        runtime::instantiate_component(&engine, &component, &linker).await?;

    let ls = act_types::types::LocalizedString::from(&component_info.description);

    let info = act_types::http::ServerInfo {
        name: component_info.name.clone(),
        version: component_info.version.clone(),
        description: ls.any_text().to_string(),
        default_language: component_info.default_language.clone(),
        capabilities: None,
        metadata: None,
    };

    tracing::info!(
        name = %component_info.name,
        version = %component_info.version,
        "Loaded component"
    );

    let component_handle = runtime::spawn_component_actor(instance, store);

    let state = Arc::new(http::AppState {
        info,
        config_schema,
        component: component_handle,
    });

    tracing::info!(%addr, component = %component_path.display(), "ACT host listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, http::create_router(state))
        .await
        .context("server error")?;

    Ok(())
}
