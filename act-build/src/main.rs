use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod manifest;
mod oci_auth;
mod oci_config;
mod pack;
mod push;
mod skill;
mod validate;
mod wasm;

#[derive(Parser)]
#[command(
    name = "act-build",
    version,
    about = "Build tool for ACT WASM components"
)]
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
    /// Publish a WASM component as a CNCF Wasm OCI Artifact
    ///
    /// Pushes the component bytes as a single layer (`application/wasm`) with a
    /// `application/vnd.wasm.config.v0+json` config blob, per the CNCF
    /// TAG-Runtime Wasm OCI Artifact specification.
    Push {
        /// Path to the .wasm component
        wasm: PathBuf,
        /// OCI reference (e.g. `ghcr.io/actpkg/sqlite:0.1.0`)
        reference: String,
        /// Additional tag to apply to the same manifest (repeatable)
        #[arg(long = "also-tag", value_name = "TAG")]
        also_tags: Vec<String>,
        /// Additional manifest annotation `key=value` (repeatable)
        #[arg(long = "annotation", value_name = "KEY=VALUE", value_parser = push::parse_annotation)]
        annotations: Vec<(String, String)>,
        /// Set `org.opencontainers.image.source` annotation
        #[arg(long)]
        source: Option<String>,
        /// Override `org.opencontainers.image.description` annotation
        #[arg(long)]
        description: Option<String>,
        /// If the tag already exists with the same layer digest, skip; if it
        /// exists with a different digest, error out.
        #[arg(long = "skip-if-identical")]
        skip_if_identical: bool,
        /// Skip push unconditionally if any manifest exists for this tag.
        /// Use for non-reproducible builds where layer digests legitimately
        /// differ between runs.
        #[arg(long = "skip-if-exists")]
        skip_if_exists: bool,
        /// Compute everything but don't push or authenticate
        #[arg(long = "dry-run")]
        dry_run: bool,
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
        Command::Push {
            wasm,
            reference,
            also_tags,
            annotations,
            source,
            description,
            skip_if_identical,
            skip_if_exists,
            dry_run,
        } => push::run(
            &wasm,
            &reference,
            push::PushOptions {
                also_tags,
                annotations,
                source,
                description,
                dry_run,
                skip_if_identical,
                skip_if_exists,
            },
        ),
    }
}
