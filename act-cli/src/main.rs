mod config;
mod format;
mod http;
mod resolve;
mod rmcp_bridge;
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
    /// Metadata to pass to the component as `key=value` (string value).
    /// Repeatable. For typed values use `--metadata-json` or `--metadata-file`.
    #[arg(short, long, value_name = "KEY=VALUE")]
    metadata: Vec<String>,
    /// JSON object of metadata to pass to the component
    #[arg(long, value_name = "JSON")]
    metadata_json: Option<String>,
    /// Path to a JSON metadata file
    #[arg(long)]
    metadata_file: Option<PathBuf>,

    /// Grant a capability: full JSON grant `{"<id>": "open"|{"mode":..,"allow":[..],"deny":[..]}}`.
    /// Repeatable / merged. For CI; interactive runs resolve grants by prompt (ask, later).
    #[arg(long = "grant")]
    grant: Vec<String>,
    /// Open a capability class by id (full declared ceiling), e.g. `--allow wasi:http`. Repeatable.
    #[arg(long = "allow")]
    allow: Vec<String>,
    /// Deny a capability class by id, e.g. `--deny db:drop-database`. Repeatable.
    #[arg(long = "deny")]
    deny: Vec<String>,

    /// Cap the component's wasm linear memory. Accepts a byte count or a size
    /// with a unit — binary (`512MiB`) or decimal (`512MB`). Growth past the cap
    /// fails inside the guest instead of ballooning the host process.
    #[arg(long = "max-memory", value_parser = parse_max_memory)]
    max_memory: Option<usize>,

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
    /// Token-Oriented Object Notation — compact, LLM-friendly encoding of the
    /// same data as `json` (~40% fewer tokens).
    Toon,
}

#[derive(Parser)]
#[command(name = "act", version, about = "ACT — Agent Component Tools CLI")]
struct Cli {
    /// Increase logging verbosity: -v = debug, -vv = trace
    /// (overridden by `RUST_LOG` if set)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
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

        /// Pre-open a single session at startup from this JSON object and
        /// run as session-of-1: every call uses the pre-opened session, the
        /// session machinery is hidden from clients (no virtual
        /// open_session/close_session tools, no /sessions endpoints), and any
        /// client-supplied std:session-id is ignored. Requires a component
        /// that exports act:sessions/session-provider.
        #[arg(long)]
        session_args: Option<String>,

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

        /// Session args as a JSON object. When set, the host opens a
        /// session before the call (`open-session(args, metadata)`),
        /// injects the returned id as `std:session-id` metadata for
        /// the tool call, and closes the session before exit. Use
        /// this when the component requires a session — bridges,
        /// stateful components — and you want the whole open/call/
        /// close cycle in one process.
        #[arg(long)]
        session_args: Option<String>,

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
    /// Inspect `act:sessions/session-provider` — currently only
    /// `open-args-schema`, since opening or closing a session from a
    /// one-shot CLI invocation cannot keep the underlying wasm state
    /// alive. For real session work, use `act run --http` or
    /// `act run --mcp` (the host process holds the wasm instance and
    /// the session lives as long as the host).
    #[command(subcommand)]
    Session(SessionCommand),
    /// Manage the local component store (list, update, gc).
    #[command(subcommand)]
    Store(StoreCommand),
    /// Inspect a component artifact (read-only, no instantiation).
    #[command(subcommand)]
    Inspect(InspectCommand),
}

#[derive(clap::Subcommand)]
enum StoreCommand {
    /// List components in the local store.
    List {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Re-resolve stored components and re-pull any whose digest moved.
    Update {
        /// A single ref to update (omit to update all stored components).
        #[arg(name = "ref")]
        reference: Option<ComponentRef>,
    },
    /// Delete store blobs no longer referenced by any component.
    Gc,
}

#[derive(clap::Subcommand)]
enum SessionCommand {
    /// Print the JSON Schema for `open-session` args.
    OpenArgsSchema {
        component: ComponentRef,
        #[command(flatten)]
        opts: CommonOpts,
    },
}

#[derive(clap::Subcommand)]
enum InspectCommand {
    /// Print the raw decoded `act:component` manifest (full ComponentInfo).
    ComponentManifest {
        /// Component reference (path, URL, OCI ref, or name)
        #[arg(name = "ref")]
        reference: ComponentRef,

        /// Output format (raw manifest is JSON; `cbor` reserved for future use)
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Log-filter priority: RUST_LOG env > -v flag > config `log-level` > default.
    let env_filter = if std::env::var("RUST_LOG").is_ok() {
        tracing_subscriber::EnvFilter::from_default_env()
    } else if cli.verbose > 0 {
        let level = match cli.verbose {
            1 => "debug",
            _ => "trace",
        };
        format!("act={level}").parse().expect("valid log filter")
    } else {
        // Try loading config for an override (best effort — don't fail on missing config).
        let config_path = match &cli.command {
            Command::Run { opts, .. } | Command::Call { opts, .. } | Command::Info { opts, .. } => {
                opts.config.as_deref()
            }
            Command::Skill { .. } | Command::Pull { .. } => None,
            Command::Session(sub) => match sub {
                SessionCommand::OpenArgsSchema { opts, .. } => opts.config.as_deref(),
            },
            Command::Store(_) | Command::Inspect(_) => None,
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

    match cli.command {
        Command::Run {
            component,
            mcp,
            http,
            listen,
            session_args,
            opts,
        } => cmd_run(component, mcp, http, listen, session_args, opts).await,
        Command::Call {
            component,
            tool,
            args,
            session_args,
            opts,
        } => cmd_call(component, tool, args, session_args, opts).await,
        Command::Info {
            component,
            tools,
            format,
            opts,
        } => cmd_info(component, tools, format, opts).await,
        Command::Skill { component, output } => cmd_skill(component, output).await,
        Command::Pull {
            reference,
            output,
            output_from_ref,
        } => cmd_pull(reference, output, output_from_ref).await,
        Command::Session(sub) => match sub {
            SessionCommand::OpenArgsSchema { component, opts } => {
                cmd_session_open_args_schema(component, opts).await
            }
        },
        Command::Store(sub) => match sub {
            StoreCommand::List { format } => cmd_list(format).await,
            StoreCommand::Update { reference } => cmd_update(reference).await,
            StoreCommand::Gc => cmd_gc().await,
        },
        Command::Inspect(cmd) => match cmd {
            InspectCommand::ComponentManifest { reference, format } => {
                cmd_inspect_component_manifest(reference, format).await
            }
        },
    }
}

/// Merge a JSON value (which must be an object) into `target`, with `source`
/// naming the CLI flag for error messages.
fn merge_metadata_object(
    target: &mut serde_json::Map<String, serde_json::Value>,
    value: serde_json::Value,
    source: &str,
) -> Result<()> {
    match value {
        serde_json::Value::Object(map) => {
            target.extend(map);
            Ok(())
        }
        _ => anyhow::bail!("{source} must be a JSON object"),
    }
}

/// Assemble CLI metadata from `--metadata-file`, `--metadata-json`, and
/// repeatable `-m/--metadata key=value` pairs.
///
/// Precedence (lowest to highest): file < `--metadata-json` < `key=value`.
/// `key=value` values are always strings; the value may contain `=` (only the
/// first `=` splits). Use `--metadata-json`/`--metadata-file` for typed values.
fn parse_cli_metadata(
    metadata: &[String],
    metadata_json: Option<&str>,
    metadata_file: Option<&std::path::Path>,
) -> Result<Option<serde_json::Value>> {
    let mut map = serde_json::Map::new();

    if let Some(path) = metadata_file {
        let contents = std::fs::read_to_string(path).context("reading metadata file")?;
        let value = serde_json::from_str(&contents).context("invalid metadata file JSON")?;
        merge_metadata_object(&mut map, value, "--metadata-file")?;
    }

    if let Some(json_str) = metadata_json {
        let value = serde_json::from_str(json_str).context("invalid --metadata-json JSON")?;
        merge_metadata_object(&mut map, value, "--metadata-json")?;
    }

    for pair in metadata {
        let (key, value) = pair
            .split_once('=')
            .with_context(|| format!("invalid --metadata '{pair}': expected key=value"))?;
        if key.is_empty() {
            anyhow::bail!("invalid --metadata '{pair}': empty key");
        }
        map.insert(
            key.to_string(),
            serde_json::Value::String(value.to_string()),
        );
    }

    if map.is_empty() {
        Ok(None)
    } else {
        Ok(Some(serde_json::Value::Object(map)))
    }
}

/// Parse a `--max-memory` value via the `bytesize` crate: a byte count or a
/// size with a unit, decimal (`512MB` = 512·10⁶) or binary (`512MiB` = 512·2²⁰).
fn parse_max_memory(s: &str) -> Result<usize, String> {
    let bytes = s
        .trim()
        .parse::<bytesize::ByteSize>()
        .map_err(|e| format!("invalid --max-memory value '{s}': {e}"))?
        .as_u64();
    let bytes =
        usize::try_from(bytes).map_err(|_| format!("--max-memory value too large: '{s}'"))?;
    if bytes == 0 {
        return Err(format!("--max-memory must be greater than 0: '{s}'"));
    }
    Ok(bytes)
}

struct ResolvedOpts {
    #[allow(dead_code)]
    config_file: config::ConfigFile,
    fs: config::FsConfig,
    http: config::HttpConfig,
    sockets: config::SocketsConfig,
    metadata: Option<serde_json::Value>,
    max_memory: Option<usize>,
}

fn resolve_opts(opts: &CommonOpts) -> Result<ResolvedOpts> {
    let config_file = config::load_config(opts.config.as_deref())?;
    let profile = match &opts.profile {
        Some(name) => Some(config::get_profile(&config_file, name)?),
        None => None,
    };
    let cli_grants = config::CliGrants {
        grant_json: opts.grant.clone(),
        allow_ids: opts.allow.clone(),
        deny_ids: opts.deny.clone(),
    };
    let grant_policy = config::build_grant_policy(&config_file, profile, &cli_grants)?;
    let fs = config::to_fs_config(&grant_policy)?;
    let http = config::to_http_config(&grant_policy)?;
    let sockets = config::to_sockets_config(&grant_policy)?;
    let cli_metadata = parse_cli_metadata(
        &opts.metadata,
        opts.metadata_json.as_deref(),
        opts.metadata_file.as_deref(),
    )?;
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
        sockets,
        metadata,
        max_memory: opts.max_memory,
    })
}

// ── Common component setup ───────────────────────────────────────────────────

/// A fully loaded and instantiated component, ready for tool calls.
struct PreparedComponent {
    info: runtime::ComponentInfo,
    handle: runtime::ComponentHandle,
    metadata: runtime::Metadata,
    /// Whether the component exports `act:sessions/session-provider`.
    has_sessions: bool,
}

/// Resolve, load, and instantiate a component. Returns a running actor handle.
///
/// `is_mcp` forces the headless `DenyPrompter` for `ask`-mode capabilities:
/// MCP runs over stdio, so there is no free terminal channel to prompt on and
/// `ask` must degrade to deny (fail-safe). For every other transport the
/// prompter is interactive only when stdin is a TTY.
async fn prepare_component(
    component: &ComponentRef,
    opts: &CommonOpts,
    is_mcp: bool,
) -> Result<PreparedComponent> {
    let resolved = resolve_opts(opts)?;

    let component_path = resolve::resolve(component, false).await?;
    let wasm_bytes = std::fs::read(&component_path).context("reading component file")?;
    let info = runtime::read_component_info(&wasm_bytes)?;

    let fs = resolved.fs;
    let http = resolved.http;
    let sockets = resolved.sockets;
    let max_memory = resolved.max_memory;

    let mut preopens = runtime::fs_policy::derive_preopens(&fs);
    let mount_root = info.std.capabilities.fs_mount_root().unwrap_or("/");
    runtime::fs_policy::apply_mount_root(&mut preopens, mount_root);

    let metadata: runtime::Metadata = resolved
        .metadata
        .as_ref()
        .map(|v| runtime::Metadata::from(v.clone()))
        .unwrap_or_default();

    tracing::debug!(
        name = %info.std.name,
        version = %info.std.version,
        path = %component_path.display(),
        "Loading component"
    );

    // Select the interactive-consent prompter for `ask`-mode capabilities.
    // Interactive (y/N on the terminal) only when stdin is a TTY and we're not
    // serving MCP over stdio; otherwise headless deny (fail-safe).
    let interactive = std::io::IsTerminal::is_terminal(&std::io::stdin()) && !is_mcp;
    let prompter: Arc<dyn runtime::consent::ConsentPrompter> = if interactive {
        Arc::new(runtime::consent::TtyPrompter)
    } else {
        Arc::new(runtime::consent::DenyPrompter)
    };
    let cache = Arc::new(runtime::consent::DecisionCache::new());

    let engine = runtime::create_engine()?;
    let wasm = runtime::load_component(&engine, &component_path)?;
    let linker = runtime::create_linker(&engine)?;
    let (instance, session_provider, store) = runtime::instantiate_component(
        &engine, &wasm, &linker, &preopens, &http, &fs, &sockets, &info, max_memory, prompter,
        cache,
    )
    .await?;
    let has_sessions = session_provider.is_some();
    let handle = runtime::spawn_component_actor(instance, session_provider, store);

    tracing::debug!(name = %info.std.name, version = %info.std.version, "Component ready");

    Ok(PreparedComponent {
        info,
        handle,
        metadata,
        has_sessions,
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

/// If `session_args` is set, open a single default session against the
/// prepared component and return its id (session-of-1, ACT-SESSIONS §3). The
/// session is closed automatically when the component actor shuts down
/// (`runtime` closes every tracked session on deinit).
async fn maybe_open_default_session(
    pc: &PreparedComponent,
    session_args: &Option<String>,
) -> Result<Option<String>> {
    match session_args {
        Some(json) => {
            if !pc.has_sessions {
                anyhow::bail!(
                    "--session-args was set, but the component does not export \
                     act:sessions/session-provider"
                );
            }
            Ok(Some(open_session_for_call(pc, json).await?))
        }
        None => Ok(None),
    }
}

async fn cmd_run(
    component: ComponentRef,
    mcp: bool,
    http: bool,
    listen: Option<String>,
    session_args: Option<String>,
    opts: CommonOpts,
) -> Result<()> {
    // Transport matrix:
    //   --mcp                 → MCP over stdio
    //   --http                → ACT-HTTP REST server
    //   --mcp --http          → MCP over Streamable HTTP at /mcp
    //   neither (with --listen) → ACT-HTTP REST server (back-compat)
    if mcp && http {
        let addr = match &listen {
            Some(s) => parse_listen_addr(s)?,
            None => "[::1]:3000".parse().unwrap(),
        };
        let pc = prepare_component(&component, &opts, true).await?;
        let default_session_id = maybe_open_default_session(&pc, &session_args).await?;
        return rmcp_bridge::run_http(
            addr,
            pc.info,
            pc.handle,
            pc.metadata,
            pc.has_sessions,
            default_session_id,
        )
        .await;
    }

    if mcp {
        if listen.is_some() {
            anyhow::bail!("--listen requires --http (MCP stdio has no listen address)");
        }
        let pc = prepare_component(&component, &opts, true).await?;
        let default_session_id = maybe_open_default_session(&pc, &session_args).await?;
        return rmcp_bridge::run_stdio(
            pc.info,
            pc.handle,
            pc.metadata,
            pc.has_sessions,
            default_session_id,
        )
        .await;
    }

    if http || listen.is_some() {
        let addr = match &listen {
            Some(s) => parse_listen_addr(s)?,
            None => "[::1]:3000".parse().unwrap(),
        };

        let pc = prepare_component(&component, &opts, false).await?;
        let default_session_id = maybe_open_default_session(&pc, &session_args).await?;

        let state = Arc::new(http::AppState {
            info: pc.info,
            component: pc.handle,
            metadata: pc.metadata,
            default_session_id,
        });

        tracing::info!(%addr, "ACT host listening");

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, http::create_router(state))
            .await
            .context("server error")?;
        return Ok(());
    }

    anyhow::bail!(
        "Specify a transport: --mcp (stdio), --http (ACT-HTTP server), or --mcp --http (MCP over HTTP)"
    )
}

async fn cmd_call(
    component: ComponentRef,
    tool: String,
    args: String,
    session_args: Option<String>,
    opts: CommonOpts,
) -> Result<()> {
    let pc = prepare_component(&component, &opts, false).await?;

    let arguments: serde_json::Value =
        serde_json::from_str(&args).context("invalid --args JSON")?;
    let cbor_args = cbor::json_to_cbor(&arguments).context("encoding args as CBOR")?;

    // If --session-args is set, open a session before the call and
    // close it on the way out. session-id is injected into the call's
    // metadata under `std:session-id`.
    let session_id = match session_args {
        Some(json) => {
            if !pc.has_sessions {
                anyhow::bail!(
                    "--session-args was set, but the component does not export \
                     act:sessions/session-provider"
                );
            }
            Some(open_session_for_call(&pc, &json).await?)
        }
        None => None,
    };

    let mut metadata = pc.metadata.clone();
    if let Some(ref id) = session_id {
        metadata.insert(
            act_types::constants::META_SESSION_ID,
            serde_json::Value::String(id.clone()),
        );
    }

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = runtime::ComponentRequest::CallTool {
        name: tool,
        arguments: cbor_args,
        metadata: metadata.into(),
        reply: reply_tx,
    };

    let send_result = pc.handle.send(request).await;
    let call_result = match send_result {
        Err(_) => Err(anyhow::anyhow!("component actor unavailable")),
        Ok(()) => match reply_rx.await {
            Err(_) => Err(anyhow::anyhow!("component actor dropped reply")),
            Ok(r) => Ok(r),
        },
    };

    // Best-effort close before returning the call result, so the
    // session is closed even if the call errored.
    if let Some(id) = session_id {
        close_session_best_effort(&pc, id).await;
    }

    let result = call_result?.map_err(|e| match e {
        runtime::ComponentError::Tool(te) => {
            let ls = act_types::types::LocalizedString::from(&te.message);
            anyhow::anyhow!("{}: {}", te.kind, ls.any_text())
        }
        runtime::ComponentError::Internal(e) => e,
    })?;

    for event in &result.events {
        match event {
            runtime::exports::act::tools::tool_provider::ToolEvent::Content(part) => {
                let mime = part.mime_type.as_deref().unwrap_or("application/cbor");
                if mime.starts_with("text/")
                    || mime == "application/json"
                    || mime == "application/xml"
                {
                    let text = String::from_utf8_lossy(&part.data);
                    println!("{text}");
                } else if mime == "application/cbor" {
                    let json_val = act_types::cbor::cbor_to_json(&part.data).unwrap_or_else(|_| {
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
            runtime::exports::act::tools::tool_provider::ToolEvent::Error(err) => {
                let ls = act_types::types::LocalizedString::from(&err.message);
                anyhow::bail!("{}: {}", err.kind, ls.any_text());
            }
        }
    }
    Ok(())
}

/// Marshal a JSON object of session args into the WIT shape and call
/// `open-session` against the prepared component. Returns the
/// allocated session-id.
async fn open_session_for_call(pc: &PreparedComponent, json: &str) -> Result<String> {
    let value: serde_json::Value =
        serde_json::from_str(json).context("invalid --session-args JSON")?;
    let serde_json::Value::Object(args_obj) = value else {
        anyhow::bail!("--session-args must be a JSON object");
    };
    let mut wit_args: Vec<(String, Vec<u8>)> = Vec::with_capacity(args_obj.len());
    for (key, value) in args_obj {
        let bytes =
            act_types::cbor::json_to_cbor(&value).context("encoding session arg as CBOR")?;
        wit_args.push((key, bytes));
    }

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    pc.handle
        .send(runtime::ComponentRequest::OpenSession {
            args: wit_args,
            metadata: pc.metadata.clone().into(),
            reply: reply_tx,
        })
        .await
        .map_err(|_| anyhow::anyhow!("component actor unavailable"))?;

    match reply_rx.await? {
        Ok(session) => Ok(session.id),
        Err(runtime::ComponentError::Tool(te)) => {
            let ls = act_types::types::LocalizedString::from(&te.message);
            anyhow::bail!("open-session failed: {}: {}", te.kind, ls.any_text());
        }
        Err(runtime::ComponentError::Internal(e)) => Err(e.context("open-session failed")),
    }
}

/// Best-effort close. Logs failures at debug; never propagates errors,
/// because the call result is what the user asked for and a failed
/// close should not surface as the command's exit code.
async fn close_session_best_effort(pc: &PreparedComponent, session_id: String) {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    if pc
        .handle
        .send(runtime::ComponentRequest::CloseSession {
            session_id: session_id.clone(),
            reply: reply_tx,
        })
        .await
        .is_err()
    {
        tracing::debug!(%session_id, "actor unavailable for close-session");
        return;
    }
    if let Err(e) = reply_rx.await {
        tracing::debug!(%session_id, error = %e, "close-session reply dropped");
    }
}

// ── Session subcommands ────────────────────────────────────────────────────

async fn cmd_session_open_args_schema(component: ComponentRef, opts: CommonOpts) -> Result<()> {
    let pc = prepare_component(&component, &opts, false).await?;
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    pc.handle
        .send(runtime::ComponentRequest::GetOpenSessionArgsSchema {
            metadata: pc.metadata.clone().into(),
            reply: reply_tx,
        })
        .await
        .map_err(|_| anyhow::anyhow!("component actor unavailable"))?;
    match reply_rx.await? {
        Ok(schema) => {
            // Pretty-print if it's valid JSON; otherwise print as-is.
            match serde_json::from_str::<serde_json::Value>(&schema) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v)?),
                Err(_) => println!("{schema}"),
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

async fn cmd_inspect_component_manifest(
    component: ComponentRef,
    format: OutputFormat,
) -> Result<()> {
    // Read the `act:component` custom section without instantiation — no
    // component code runs, safe against adversarial .wasm files.
    let component_path = resolve::resolve(&component, false).await?;
    let wasm_bytes = std::fs::read(&component_path).context("reading component file")?;
    let info = runtime::read_component_info(&wasm_bytes)?;

    // The raw manifest is structured data: `json` (default) emits verbatim
    // pretty JSON, `toon` emits the same shape in TOON. `text` has no
    // distinct manifest form, so it falls back to JSON.
    let rendered = match format {
        OutputFormat::Toon => format::to_toon(&info)?,
        OutputFormat::Json | OutputFormat::Text => format::to_manifest_json(&info)?,
    };
    println!("{rendered}");
    Ok(())
}

async fn cmd_info(
    component: ComponentRef,
    show_tools: bool,
    output_format: OutputFormat,
    opts: CommonOpts,
) -> Result<()> {
    // Component info (name, version, capabilities, embedded skill) is
    // read from the `act:component` custom section without
    // instantiation — that path runs no component code and is safe
    // against adversarial .wasm files. Code only runs when the user
    // opts in via `--tools` (list-tools).
    let component_path = resolve::resolve(&component, false).await?;
    let wasm_bytes = std::fs::read(&component_path).context("reading component file")?;
    let component_info = runtime::read_component_info(&wasm_bytes)?;

    let tools = if show_tools {
        let pc = prepare_component(&component, &opts, false).await?;

        let (tools_tx, tools_rx) = tokio::sync::oneshot::channel();
        pc.handle
            .send(runtime::ComponentRequest::ListTools {
                metadata: pc.metadata,
                reply: tools_tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("component actor unavailable"))?;

        match tools_rx.await? {
            Ok(list_response) => Some(list_response.tools),
            Err(runtime::ComponentError::Tool(te)) => {
                let ls = act_types::types::LocalizedString::from(&te.message);
                anyhow::bail!("list-tools error: {}: {}", te.kind, ls.any_text());
            }
            Err(runtime::ComponentError::Internal(e)) => return Err(e),
        }
    } else {
        None
    };

    let data = format::InfoData {
        info: &component_info,
        tools,
    };

    match output_format {
        OutputFormat::Text => print!("{}", format::to_text(&data)),
        OutputFormat::Json => {
            let json = format::to_json(&data)?;
            println!("{json}");
        }
        OutputFormat::Toon => {
            let toon = format::to_info_toon(&data)?;
            println!("{toon}");
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
    let store = resolve::open_store()?;
    let reference_str = reference.to_string();
    let stored = act_store::pull(&store, &reference_str)
        .await
        .with_context(|| format!("pulling {reference_str}"))?;

    // Path to the stored wasm blob (read-through hit; no re-pull).
    let stored_path = act_store::ensure(&store, &reference_str).await?;

    let export = output.or_else(|| {
        output_from_ref.then(|| {
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
            PathBuf::from(filename)
        })
    });

    if let Some(out) = export {
        tokio::fs::copy(&stored_path, &out)
            .await
            .with_context(|| format!("copying to {}", out.display()))?;
        println!("{}", out.display());
    } else {
        println!(
            "{} -> {} (sha256:{})",
            reference_str,
            stored_path.display(),
            stored.manifest_digest
        );
    }
    Ok(())
}

// ── Store subcommands ─────────────────────────────────────────────────────────

async fn cmd_list(format: OutputFormat) -> Result<()> {
    let store = resolve::open_store()?;
    let mut items = store.list()?;
    items.sort_by(|a, b| source_ref(&a.provenance).cmp(source_ref(&b.provenance)));
    let rows = || -> Vec<serde_json::Value> {
        items
            .iter()
            .map(|s| {
                serde_json::json!({
                    "ref": source_ref(&s.provenance),
                    "digest": s.provenance.digest,
                    "name": s.provenance.name,
                    "version": s.provenance.version,
                    "fetched_at": s.provenance.fetched_at,
                })
            })
            .collect()
    };
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&rows())?);
        }
        OutputFormat::Toon => {
            println!("{}", format::to_toon(&rows())?);
        }
        OutputFormat::Text => {
            if items.is_empty() {
                println!("(store is empty)");
            }
            for s in &items {
                println!(
                    "{}\t{}\t{}",
                    source_ref(&s.provenance),
                    s.provenance.version.as_deref().unwrap_or("-"),
                    s.provenance.digest
                );
            }
        }
    }
    Ok(())
}

async fn cmd_update(reference: Option<ComponentRef>) -> Result<()> {
    let store = resolve::open_store()?;
    let refs: Vec<String> = match reference {
        Some(r) => vec![r.to_string()],
        None => store
            .list()?
            .iter()
            .map(|s| source_ref(&s.provenance).to_string())
            .collect(),
    };
    if refs.is_empty() {
        println!("(store is empty)");
        return Ok(());
    }
    for r in refs {
        match act_store::update(&store, &r).await {
            Ok(act_store::UpdateOutcome::Unchanged) => println!("{r}\tunchanged"),
            Ok(act_store::UpdateOutcome::Updated { from, to }) => {
                println!("{r}\tupdated {from} -> {to}")
            }
            Ok(act_store::UpdateOutcome::NotStored) => println!("{r}\tnot stored"),
            Err(e) => eprintln!("{r}\tERROR: {e}"),
        }
    }
    Ok(())
}

async fn cmd_gc() -> Result<()> {
    let store = resolve::open_store()?;
    let removed = store.gc()?;
    println!("removed {removed} unreferenced blob(s)");
    Ok(())
}

/// The source ref (as typed) recorded in a provenance.
fn source_ref(p: &act_store::Provenance) -> &str {
    match &p.source {
        act_store::Source::Oci { reference } => reference,
        act_store::Source::Http { url, .. } => url,
        act_store::Source::Local { path } => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn parse_cli_metadata_kv_pair() {
        let result = parse_cli_metadata(&["key=value".to_string()], None, None).unwrap();
        assert_eq!(result, Some(serde_json::json!({"key": "value"})));
    }

    #[test]
    fn parse_cli_metadata_kv_values_are_strings() {
        // Bare `k=v` values are always strings; use --metadata-json for typed values.
        let result = parse_cli_metadata(&["port=8080".to_string()], None, None).unwrap();
        assert_eq!(result, Some(serde_json::json!({"port": "8080"})));
    }

    #[test]
    fn parse_cli_metadata_kv_repeatable() {
        let result =
            parse_cli_metadata(&["a=1".to_string(), "b=2".to_string()], None, None).unwrap();
        assert_eq!(result, Some(serde_json::json!({"a": "1", "b": "2"})));
    }

    #[test]
    fn parse_cli_metadata_kv_value_keeps_extra_equals() {
        // Split on the first `=` only; the value may contain `=`.
        let result = parse_cli_metadata(&["q=a=b".to_string()], None, None).unwrap();
        assert_eq!(result, Some(serde_json::json!({"q": "a=b"})));
    }

    #[test]
    fn parse_cli_metadata_kv_empty_value() {
        let result = parse_cli_metadata(&["key=".to_string()], None, None).unwrap();
        assert_eq!(result, Some(serde_json::json!({"key": ""})));
    }

    #[test]
    fn parse_cli_metadata_kv_missing_equals_is_error() {
        assert!(parse_cli_metadata(&["nokey".to_string()], None, None).is_err());
    }

    #[test]
    fn parse_cli_metadata_kv_empty_key_is_error() {
        assert!(parse_cli_metadata(&["=value".to_string()], None, None).is_err());
    }

    #[test]
    fn parse_cli_metadata_json_object() {
        let result = parse_cli_metadata(&[], Some(r#"{"key":"value","n":7}"#), None).unwrap();
        assert_eq!(result, Some(serde_json::json!({"key": "value", "n": 7})));
    }

    #[test]
    fn parse_cli_metadata_json_non_object_is_error() {
        assert!(parse_cli_metadata(&[], Some(r#""just a string""#), None).is_err());
    }

    #[test]
    fn parse_cli_metadata_invalid_json() {
        assert!(parse_cli_metadata(&[], Some("not json"), None).is_err());
    }

    #[test]
    fn parse_cli_metadata_kv_overrides_json() {
        // k=v pairs overlay --metadata-json (highest precedence among CLI sources).
        let result =
            parse_cli_metadata(&["b=3".to_string()], Some(r#"{"a":"1","b":"2"}"#), None).unwrap();
        assert_eq!(result, Some(serde_json::json!({"a": "1", "b": "3"})));
    }

    #[test]
    fn parse_max_memory_units_and_bytes() {
        assert_eq!(parse_max_memory("268435456").unwrap(), 256 << 20); // bare = bytes
        assert_eq!(parse_max_memory("256MiB").unwrap(), 256 << 20); // binary
        assert_eq!(parse_max_memory("1GiB").unwrap(), 1 << 30);
        assert_eq!(parse_max_memory("512KiB").unwrap(), 512 << 10);
        assert_eq!(parse_max_memory("256MB").unwrap(), 256_000_000); // decimal
    }

    #[test]
    fn parse_max_memory_rejects_garbage_and_zero() {
        assert!(parse_max_memory("12xyz").is_err());
        assert!(parse_max_memory("").is_err());
        assert!(parse_max_memory("0").is_err());
    }

    #[test]
    fn parse_cli_metadata_from_file_preserves_types() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, r#"{{"port": 8080}}"#).unwrap();
        let result = parse_cli_metadata(&[], None, Some(file.path())).unwrap();
        assert_eq!(result, Some(serde_json::json!({"port": 8080})));
    }

    #[test]
    fn parse_cli_metadata_none() {
        let result = parse_cli_metadata(&[], None, None).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn parse_cli_metadata_precedence_file_json_kv() {
        // file is the base; --metadata-json overlays it; k=v pairs overlay last.
        let mut file = NamedTempFile::new().unwrap();
        write!(file, r#"{{"a":"file","b":"file","c":"file"}}"#).unwrap();
        let result = parse_cli_metadata(
            &["c=kv".to_string()],
            Some(r#"{"b":"json","c":"json"}"#),
            Some(file.path()),
        )
        .unwrap();
        assert_eq!(
            result,
            Some(serde_json::json!({"a": "file", "b": "json", "c": "kv"}))
        );
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
