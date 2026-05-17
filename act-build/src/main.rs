use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

mod init;
mod manifest;
mod oci_auth;
mod oci_config;
mod pack;
mod push;
mod skill;
mod validate;
mod wasm;
mod wit_deps;

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

#[derive(Copy, Clone, Debug, ValueEnum)]
enum InitLang {
    Rust,
    Python,
    Js,
}

#[derive(Subcommand)]
enum Command {
    /// Scaffold a new component from a language template
    ///
    /// Example: `act-build init rust my-tool` creates `./my-tool/` with a
    /// working component skeleton ready for `just init && just build`.
    Init {
        /// Component language
        #[arg(value_enum)]
        lang: InitLang,
        /// Component name (positional). If omitted, init in the current
        /// directory using its basename as the name (like `cargo init`).
        name: Option<String>,
        /// Short human description (defaults to a placeholder).
        #[arg(long)]
        description: Option<String>,
        /// Declare wasi:http capability requirement.
        #[arg(long = "http")]
        needs_http: bool,
        /// Declare wasi:filesystem capability requirement.
        #[arg(long = "fs")]
        needs_filesystem: bool,
        /// Path to a local checkout of the template repo (overrides env var).
        #[arg(long = "template-path")]
        template_path: Option<PathBuf>,
        /// Skip `git init` in the generated directory.
        #[arg(long = "no-git")]
        no_git: bool,
    },
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
        Command::Init {
            lang,
            name,
            description,
            needs_http,
            needs_filesystem,
            template_path,
            no_git,
        } => init::run(init::InitOptions {
            language: match lang {
                InitLang::Rust => init::Language::Rust,
                InitLang::Python => init::Language::Python,
                InitLang::Js => init::Language::Js,
            },
            name,
            description,
            needs_http,
            needs_filesystem,
            template_path,
            no_git,
        }),
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
