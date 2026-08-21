//! Embeddable wasmtime host for ACT components.
//!
//! This is the engine behind the `act` CLI, packaged so other hosts — a
//! toolserver, a gateway, anything that has to run a component the same way —
//! get identical capability decisions, credential namespacing, consent
//! routing and audit records rather than a second implementation of them.
//!
//! The crate is headless: it knows nothing about terminals, MCP, HTTP or
//! configuration files. A host supplies the decisions ([`RuntimeConfig`]) and
//! the channel it reaches a human on ([`ConsentConfig`]); the runtime supplies
//! everything downstream of that.
//!
//! ```no_run
//! # async fn example() -> anyhow::Result<()> {
//! let rt = act_runtime::ComponentRuntime::new()?;
//! let component = "ghcr.io/actpkg/sqlite:0.1.0".parse()?;
//!
//! // Ask-mode grants with a denying prompter: the headless default, and the
//! // reason a capability the operator did not grant stays denied rather than
//! // silently allowed when no one is there to ask.
//! let running = rt
//!     .load(
//!         &component,
//!         &act_runtime::RuntimeConfig::default(),
//!         act_runtime::ConsentConfig::deny(),
//!     )
//!     .await?;
//!
//! let tools = running.handle().list_tools(&Default::default()).await?;
//! let result = running
//!     .handle()
//!     .call_tool("query", Vec::new(), Vec::new(), None)
//!     .await?;
//! # let _ = (tools, result);
//! # Ok(())
//! # }
//! ```

pub mod audit;
pub mod consent;
pub mod credentials;
pub mod fs_policy;
pub mod http_client;
pub mod http_policy;
pub mod resolve;
mod runtime;
pub mod sessions;

mod actor;
mod engine;
mod info;
pub(crate) mod store;

// Generated bindings from WIT — fully auto-generated, no manual patching.
#[allow(unused_mut, unused_variables, dead_code)]
mod bindings;
pub use bindings::*;

#[cfg(test)]
mod tests;

pub use actor::{
    AuditContext, CallToolResult, ComponentHandle, Metadata, ToolProvider, instantiate_component,
    spawn_component_actor,
};
pub use engine::{create_engine, create_linker, load_component};
pub use info::{ComponentError, ComponentInfo, read_component_info};
pub use resolve::ComponentRef;
pub use runtime::{
    AuditOptions, ComponentRuntime, ConsentConfig, CredentialsSource, RunningComponent,
    RuntimeConfig,
};
pub use store::{HostState, create_store};
