use anyhow::{Context, Result, anyhow, bail};
use include_dir::{Dir, DirEntry, include_dir};
use minijinja::{Environment, context};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, warn};
use walkdir::WalkDir;

/// Language templates, embedded at compile time from `templates/init/<lang>/`
/// in this crate. Source-of-truth lives there; `include_dir!` reads it
/// verbatim.
static TEMPLATE_RUST: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/templates/init/rust");
static TEMPLATE_PYTHON: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/templates/init/python");
static TEMPLATE_JS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/templates/init/js");

#[derive(Debug, Clone, Copy)]
pub enum Language {
    Rust,
    Python,
    Js,
}

impl Language {
    pub fn env_var(&self) -> &'static str {
        match self {
            Language::Rust => "ACT_TEMPLATE_RUST_PATH",
            Language::Python => "ACT_TEMPLATE_PYTHON_PATH",
            Language::Js => "ACT_TEMPLATE_JS_PATH",
        }
    }

    fn embedded(&self) -> &'static Dir<'static> {
        match self {
            Language::Rust => &TEMPLATE_RUST,
            Language::Python => &TEMPLATE_PYTHON,
            Language::Js => &TEMPLATE_JS,
        }
    }
}

#[derive(Debug)]
pub struct InitOptions {
    pub language: Language,
    /// Positional name. If `None`, init in the current directory using
    /// its basename as the component name.
    pub name: Option<String>,
    pub description: Option<String>,
    pub needs_http: bool,
    pub needs_filesystem: bool,
    /// Override the embedded template with a local directory (used when
    /// iterating on the template tree itself without a rebuild). The path
    /// is the template root, e.g. `act-build/templates/init/rust/`.
    pub template_path: Option<PathBuf>,
    pub no_git: bool,
}

enum TemplateSource {
    Filesystem(PathBuf),
    Embedded(&'static Dir<'static>),
}

pub fn run(opts: InitOptions) -> Result<()> {
    let source = resolve_template_source(&opts);
    if let TemplateSource::Filesystem(p) = &source
        && !p.is_dir()
    {
        bail!("template path {} is not a directory", p.display());
    }

    let (target_dir, name) = resolve_target(opts.name.as_deref())?;
    validate_name(&name)?;

    if target_dir.exists() && dir_has_entries(&target_dir)? {
        bail!(
            "target directory {} already exists and is not empty",
            target_dir.display()
        );
    }

    let ctx = build_context(&name, &opts);
    info!(
        target = %target_dir.display(),
        name = %name,
        embedded = matches!(source, TemplateSource::Embedded(_)),
        "scaffolding component"
    );

    std::fs::create_dir_all(&target_dir)
        .with_context(|| format!("creating {}", target_dir.display()))?;
    let env = Environment::new();
    match &source {
        TemplateSource::Filesystem(p) => render_filesystem(p, &target_dir, &env, &ctx)?,
        TemplateSource::Embedded(d) => render_embedded(d, &target_dir, &env, &ctx)?,
    }

    let wit_dir = target_dir.join("wit");
    let wit_fetched = if wit_dir.join("deps.toml").exists() {
        match crate::wit_deps::sync(&wit_dir) {
            Ok(()) => true,
            Err(e) => {
                warn!(error = %e, "wit deps fetch failed; you can re-run `act-build init` once network is available");
                false
            }
        }
    } else {
        false
    };

    if !opts.no_git {
        git_init(&target_dir);
    }

    eprintln!("Created component {} in {}", name, target_dir.display());
    eprintln!();
    eprintln!("Next steps:");
    if opts.name.is_some() {
        eprintln!("  cd {name}");
    }
    if !wit_fetched && wit_dir.join("deps.toml").exists() {
        eprintln!("  act-build init   # retry WIT fetch (failed during scaffold)");
    }
    eprintln!("  just build       # build wasm component");
    eprintln!("  just pack        # embed act:component metadata");
    Ok(())
}

fn resolve_template_source(opts: &InitOptions) -> TemplateSource {
    if let Some(p) = &opts.template_path {
        return TemplateSource::Filesystem(p.clone());
    }
    if let Ok(p) = std::env::var(opts.language.env_var()) {
        return TemplateSource::Filesystem(PathBuf::from(p));
    }
    TemplateSource::Embedded(opts.language.embedded())
}

fn resolve_target(name_arg: Option<&str>) -> Result<(PathBuf, String)> {
    let cwd = std::env::current_dir().context("getting current directory")?;
    match name_arg {
        Some(n) => Ok((cwd.join(n), n.to_string())),
        None => {
            let base = cwd
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| anyhow!("cannot derive component name from current directory"))?
                .to_string();
            Ok((cwd, base))
        }
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("component name is empty");
    }
    let first = name.chars().next().unwrap();
    if !first.is_ascii_lowercase() {
        bail!(
            "component name must start with a lowercase ASCII letter (got {:?})",
            name
        );
    }
    for c in name.chars() {
        let ok = c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
        if !ok {
            bail!(
                "component name contains invalid character {:?}; allowed: a-z, 0-9, '-'",
                c
            );
        }
    }
    Ok(())
}

fn build_context(name: &str, opts: &InitOptions) -> minijinja::Value {
    let module_name = name.replace('-', "_");
    let wasm_filename = format!("{module_name}.wasm");
    let description = opts
        .description
        .clone()
        .unwrap_or_else(|| format!("ACT component {name}"));

    context! {
        name => name,
        module_name => module_name,
        wasm_filename => wasm_filename,
        description => description,
        needs_http => opts.needs_http,
        needs_filesystem => opts.needs_filesystem,
    }
}

fn render_filesystem(
    template_dir: &Path,
    target_dir: &Path,
    env: &Environment,
    ctx: &minijinja::Value,
) -> Result<()> {
    for entry in WalkDir::new(template_dir).follow_links(false) {
        let entry = entry?;
        let rel = entry
            .path()
            .strip_prefix(template_dir)
            .expect("walkdir path under template_dir");
        if rel.as_os_str().is_empty() {
            continue;
        }
        let out_rel = strip_jinja_suffix(rel);
        let out_path = target_dir.join(&out_rel);

        if entry.file_type().is_dir() {
            std::fs::create_dir_all(&out_path)
                .with_context(|| format!("creating {}", out_path.display()))?;
            continue;
        }
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }

        let is_template = rel.extension().and_then(|s| s.to_str()) == Some("j2");
        if is_template {
            let src = std::fs::read_to_string(entry.path())
                .with_context(|| format!("reading {}", entry.path().display()))?;
            let rendered = env
                .render_str(&src, ctx)
                .with_context(|| format!("rendering {}", entry.path().display()))?;
            std::fs::write(&out_path, rendered)
                .with_context(|| format!("writing {}", out_path.display()))?;
        } else {
            std::fs::copy(entry.path(), &out_path)
                .with_context(|| format!("copying {}", out_path.display()))?;
        }
    }
    Ok(())
}

fn render_embedded(
    root: &Dir<'_>,
    target_dir: &Path,
    env: &Environment,
    ctx: &minijinja::Value,
) -> Result<()> {
    walk_embedded(root, root.path(), target_dir, env, ctx)
}

fn walk_embedded(
    dir: &Dir<'_>,
    root_path: &Path,
    target_dir: &Path,
    env: &Environment,
    ctx: &minijinja::Value,
) -> Result<()> {
    for entry in dir.entries() {
        match entry {
            DirEntry::Dir(sub) => {
                let rel = sub.path().strip_prefix(root_path).unwrap_or(sub.path());
                if !rel.as_os_str().is_empty() {
                    let out_path = target_dir.join(rel);
                    std::fs::create_dir_all(&out_path)
                        .with_context(|| format!("creating {}", out_path.display()))?;
                }
                walk_embedded(sub, root_path, target_dir, env, ctx)?;
            }
            DirEntry::File(f) => {
                let rel = f.path().strip_prefix(root_path).unwrap_or(f.path());
                let out_rel = strip_jinja_suffix(rel);
                let out_path = target_dir.join(&out_rel);
                if let Some(parent) = out_path.parent() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("creating {}", parent.display()))?;
                }
                let is_template = rel.extension().and_then(|s| s.to_str()) == Some("j2");
                if is_template {
                    let src = f
                        .contents_utf8()
                        .ok_or_else(|| anyhow!("embedded template file {:?} is not UTF-8", rel))?;
                    let rendered = env
                        .render_str(src, ctx)
                        .with_context(|| format!("rendering embedded {}", rel.display()))?;
                    std::fs::write(&out_path, rendered)
                        .with_context(|| format!("writing {}", out_path.display()))?;
                } else {
                    std::fs::write(&out_path, f.contents())
                        .with_context(|| format!("writing {}", out_path.display()))?;
                }
            }
        }
    }
    Ok(())
}

fn strip_jinja_suffix(rel: &Path) -> PathBuf {
    match rel.extension().and_then(|s| s.to_str()) {
        Some("j2") => rel.with_extension(""),
        _ => rel.to_path_buf(),
    }
}

fn dir_has_entries(p: &Path) -> Result<bool> {
    let mut rd = std::fs::read_dir(p).with_context(|| format!("reading {}", p.display()))?;
    Ok(rd.next().is_some())
}

fn git_init(target_dir: &Path) {
    let status = Command::new("git")
        .arg("init")
        .arg("--quiet")
        .current_dir(target_dir)
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => warn!(?s, "git init exited with non-zero status"),
        Err(e) => warn!(error = %e, "git init failed to spawn (skipping)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_names() {
        assert!(validate_name("my-tool").is_ok());
        assert!(validate_name("foo123").is_ok());
        assert!(validate_name("a").is_ok());

        assert!(validate_name("").is_err());
        assert!(validate_name("MyTool").is_err());
        assert!(validate_name("1tool").is_err());
        assert!(validate_name("my_tool").is_err()); // underscores disallowed
        assert!(validate_name("my.tool").is_err());
    }

    #[test]
    fn strips_j2_suffix() {
        assert_eq!(
            strip_jinja_suffix(Path::new("src/lib.rs.j2")),
            PathBuf::from("src/lib.rs")
        );
        assert_eq!(
            strip_jinja_suffix(Path::new("wit/world.wit")),
            PathBuf::from("wit/world.wit")
        );
    }

    #[test]
    fn embedded_rust_template_has_expected_files() {
        assert!(TEMPLATE_RUST.get_file("Cargo.toml.j2").is_some());
        assert!(TEMPLATE_RUST.get_file("src/lib.rs.j2").is_some());
        assert!(TEMPLATE_RUST.get_file("wit/world.wit").is_some());
        assert!(TEMPLATE_RUST.get_file(".cargo/config.toml").is_some());
    }

    #[test]
    fn embedded_python_template_has_expected_files() {
        assert!(TEMPLATE_PYTHON.get_file("pyproject.toml.j2").is_some());
        assert!(TEMPLATE_PYTHON.get_file("app.py.j2").is_some());
        assert!(TEMPLATE_PYTHON.get_file("justfile.j2").is_some());
        assert!(TEMPLATE_PYTHON.get_file("wit/world.wit").is_some());
        assert!(TEMPLATE_PYTHON.get_file("wit/deps.toml").is_some());
        assert!(TEMPLATE_PYTHON.get_file("skill/SKILL.md.j2").is_some());
    }

    #[test]
    fn embedded_js_template_has_expected_files() {
        assert!(TEMPLATE_JS.get_file("package.json.j2").is_some());
        assert!(TEMPLATE_JS.get_file("src/index.js.j2").is_some());
        assert!(TEMPLATE_JS.get_file("justfile.j2").is_some());
        assert!(TEMPLATE_JS.get_file("wit/world.wit").is_some());
        assert!(TEMPLATE_JS.get_file("wit/deps.toml").is_some());
        assert!(TEMPLATE_JS.get_file("skill/SKILL.md.j2").is_some());
    }
}
