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

/// Output format for commands that support machine-readable output.
#[derive(Copy, Clone, Debug, Default, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable text (default).
    #[default]
    Text,
    /// A single JSON document on stdout (logs go to stderr).
    Json,
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
        /// Directory to scaffold into. Defaults to `./<name>/` (or the current
        /// directory when no name is given). When set without a name, the
        /// component name is taken from this path's basename.
        #[arg(long = "output", short = 'o', value_name = "DIR")]
        output: Option<PathBuf>,
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
        /// Override a resolved component-metadata field, e.g.
        /// `--set std.name=sqlite-vec`. Repeatable. The value is set as a
        /// string, so only string-typed fields (name, version, description,
        /// default-language) are supported.
        #[arg(long = "set", value_name = "KEY=VALUE")]
        set: Vec<String>,
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
        /// OCI reference (e.g. `ghcr.io/actpkg/sqlite:0.1.0`).
        /// Falls back to the `ACT_REFERENCE` env var.
        #[arg(env = "ACT_REFERENCE")]
        reference: String,
        /// Additional tag to apply to the same manifest (repeatable)
        #[arg(long = "also-tag", value_name = "TAG")]
        also_tags: Vec<String>,
        /// Additional manifest annotation `key=value` (repeatable)
        #[arg(long = "annotation", value_name = "KEY=VALUE", value_parser = push::parse_annotation)]
        annotations: Vec<(String, String)>,
        /// Set `org.opencontainers.image.source` annotation.
        /// Falls back to the `ACT_SOURCE` env var.
        #[arg(long, env = "ACT_SOURCE")]
        source: Option<String>,
        /// Override `org.opencontainers.image.description` annotation.
        /// Falls back to the `ACT_DESCRIPTION` env var.
        #[arg(long, env = "ACT_DESCRIPTION")]
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
        /// Output format. `json` emits a minimal document on stdout
        /// (`{reference, status, digest, tags}`) so the manifest digest can be
        /// extracted with e.g. `... --format json | jq -r .digest`.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "act_build=info".into()),
        )
        // Logs to stderr so `--format json` keeps stdout pure JSON.
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Init {
            lang,
            name,
            output,
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
            output,
            description,
            needs_http,
            needs_filesystem,
            template_path,
            no_git,
        }),
        Command::Pack { wasm, set } => pack::run(&wasm, &set),
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
            format,
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
                format,
            },
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// RAII guard that restores an env var on drop. Env mutation is
    /// process-global, so the env-dependent assertions live in a single
    /// sequential test to avoid races with cargo's threaded runner.
    struct EnvGuard {
        key: String,
        prev: Option<String>,
    }
    impl EnvGuard {
        fn set(key: &str, value: &str) -> Self {
            let prev = std::env::var(key).ok();
            // SAFETY: env is mutated only within this single-threaded test.
            unsafe { std::env::set_var(key, value) };
            Self {
                key: key.into(),
                prev,
            }
        }
        fn unset(key: &str) -> Self {
            let prev = std::env::var(key).ok();
            unsafe { std::env::remove_var(key) };
            Self {
                key: key.into(),
                prev,
            }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.prev {
                    Some(v) => std::env::set_var(&self.key, v),
                    None => std::env::remove_var(&self.key),
                }
            }
        }
    }

    fn push_fields(cli: Cli) -> (String, Option<String>, Option<String>) {
        match cli.command {
            Command::Push {
                reference,
                source,
                description,
                ..
            } => (reference, source, description),
            _ => panic!("expected push command"),
        }
    }

    #[test]
    fn push_args_resolve_from_act_env_with_cli_override() {
        // Phase 1: env supplies the missing positional reference + source +
        // description.
        {
            let _r = EnvGuard::set("ACT_REFERENCE", "ghcr.io/actpkg/sqlite:0.1.0");
            let _s = EnvGuard::set("ACT_SOURCE", "https://github.com/actpkg/sqlite");
            let _d = EnvGuard::set("ACT_DESCRIPTION", "from env");

            let cli = Cli::try_parse_from(["act-build", "push", "comp.wasm"])
                .expect("reference should be satisfied by ACT_REFERENCE");
            let (reference, source, description) = push_fields(cli);
            assert_eq!(reference, "ghcr.io/actpkg/sqlite:0.1.0");
            assert_eq!(source.as_deref(), Some("https://github.com/actpkg/sqlite"));
            assert_eq!(description.as_deref(), Some("from env"));
        }

        // Phase 2: explicit CLI args take precedence over env.
        {
            let _r = EnvGuard::set("ACT_REFERENCE", "ghcr.io/env/ref:1");
            let _s = EnvGuard::set("ACT_SOURCE", "https://github.com/env/src");
            let _d = EnvGuard::set("ACT_DESCRIPTION", "env desc");

            let cli = Cli::try_parse_from([
                "act-build",
                "push",
                "comp.wasm",
                "ghcr.io/cli/ref:2",
                "--source",
                "https://github.com/cli/src",
                "--description",
                "cli desc",
            ])
            .expect("parse with explicit args");
            let (reference, source, description) = push_fields(cli);
            assert_eq!(reference, "ghcr.io/cli/ref:2");
            assert_eq!(source.as_deref(), Some("https://github.com/cli/src"));
            assert_eq!(description.as_deref(), Some("cli desc"));
        }

        // Phase 3: with neither CLI nor env, the required reference still errors.
        {
            let _r = EnvGuard::unset("ACT_REFERENCE");
            let _s = EnvGuard::unset("ACT_SOURCE");
            let _d = EnvGuard::unset("ACT_DESCRIPTION");

            let err = Cli::try_parse_from(["act-build", "push", "comp.wasm"]);
            assert!(
                err.is_err(),
                "reference must still be required when neither CLI arg nor env is set"
            );
        }
    }
}
