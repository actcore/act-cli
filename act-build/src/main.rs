use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod manifest;
mod pack;
mod skill;
mod validate;
mod wasm;

#[derive(Parser)]
#[command(name = "act-build", about = "Build tool for ACT WASM components")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Post-process a WASM component: embed act:component, act:skill, WASM metadata
    Pack {
        /// Path to the compiled .wasm component
        wasm: PathBuf,
    },
    /// Validate a WASM component without modifying it
    Validate {
        /// Path to the .wasm component to validate
        wasm: PathBuf,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "act_build=info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Pack { wasm } => pack::run(&wasm),
        Command::Validate { wasm } => validate::run(&wasm),
    }
}
