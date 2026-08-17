//! `act secret set/list/rm` — the out-of-band write path for
//! `act:credentials` (spec §5.1). There is deliberately no `act secret get`:
//! nothing in this module ever prints a credential value. `SecretInfo`
//! (what `list` prints) has no field that could hold one, so that guarantee
//! is a property of the type it serializes, not a habit this code has to
//! maintain.
//!
//! `act login` (phase 2) is the other way of producing what gets written
//! here; both end at the same `CredentialStore::put`.

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::io::{IsTerminal, Read, Write};

use act_credentials::backend::{self, BackendChoice};
use act_credentials::kind::KindRegistry;
use act_credentials::record::SecretRecord;
use act_credentials::record::SecretValue;
use act_credentials::store::CredentialStore;

use crate::resolve::{self, ComponentRef};
use crate::runtime::credentials::backend_root;

#[derive(clap::Subcommand)]
pub enum SecretCmd {
    /// Write a credential into a component's profile.
    Set {
        /// Component reference (path, URL, OCI ref, or name) — the same
        /// value `act run` / `act call` use. This is the profile namespace.
        component: ComponentRef,
        #[arg(long, default_value = "default")]
        key: String,
        #[arg(long, default_value = "std:opaque")]
        kind: String,
        #[arg(long)]
        description: Option<String>,
        /// Read a JSON field map from stdin, e.g. `{"std:value":"..."}`.
        #[arg(long, conflicts_with = "from_command")]
        fields_stdin: bool,
        /// Run a command and read its JSON field map from stdout.
        #[arg(long)]
        from_command: Option<String>,
    },
    /// List stored credentials — key, kind, description, expiry. Never a value.
    List {
        /// Component reference to filter by (omit to list every component).
        component: Option<ComponentRef>,
    },
    /// Remove a credential.
    Rm {
        component: ComponentRef,
        #[arg(long)]
        key: String,
    },
}

/// Global flags `act secret` needs that aren't specific to one subcommand.
pub struct GlobalOpts {
    /// `--credentials-backend`, e.g. `file:/path/to/store`. `None` selects
    /// the platform default file-store location — the same one the runtime
    /// (`credential_host` in main.rs) reads from when `act run` / `act call`
    /// are invoked without the flag, so a secret set with no backend
    /// argument is found by a run with no backend argument.
    pub credentials_backend: Option<String>,
}

pub async fn cmd_secret(cmd: SecretCmd, opts: &GlobalOpts) -> Result<()> {
    match cmd {
        SecretCmd::Set {
            component,
            key,
            kind,
            description,
            fields_stdin,
            from_command,
        } => cmd_set(
            component,
            key,
            kind,
            description,
            fields_stdin,
            from_command,
            opts,
        ),
        SecretCmd::List { component } => cmd_list(component, opts),
        SecretCmd::Rm { component, key } => cmd_rm(component, key, opts),
    }
}

fn cmd_set(
    component: ComponentRef,
    key: String,
    kind: String,
    description: Option<String>,
    fields_stdin: bool,
    from_command: Option<String>,
    opts: &GlobalOpts,
) -> Result<()> {
    let registry = KindRegistry::builtin();
    validate_kind(&registry, &kind)?;

    // Validated (and, for a pipe with no source flag, refused) before we
    // touch the store — an unknown kind or a credential we shouldn't be
    // reading should never depend on whether the store is reachable.
    let fields = if fields_stdin {
        read_fields_from_stdin()?
    } else if let Some(cmd_str) = from_command.as_deref() {
        read_fields_from_command(cmd_str)?
    } else if std::io::stdin().is_terminal() {
        prompt_fields_interactively(&registry, &kind)?
    } else {
        anyhow::bail!(
            "no credential source: stdin is not a terminal, so a value \
             cannot be prompted for. Use --fields-stdin or --from-command."
        );
    };

    let choice = resolve_backend(opts.credentials_backend.as_deref())?;
    let root = backend_root(&choice).to_path_buf();
    let store = backend::select(choice.clone(), &root)
        .with_context(|| format!("opening credential store at {}", root.display()))?;
    disclose_if_first_write(&choice, store.as_ref())?;

    let profile = resolve::profile_key(&component);
    let record = SecretRecord {
        kind: kind.clone(),
        fields,
        host_only: BTreeMap::new(),
        description,
        expires_at: None,
    };
    store
        .put(&profile, &key, &record)
        .with_context(|| format!("writing credential '{key}' for {profile}"))?;

    println!("stored '{key}' ({kind}) for {profile}");
    Ok(())
}

fn cmd_list(component: Option<ComponentRef>, opts: &GlobalOpts) -> Result<()> {
    let choice = resolve_backend(opts.credentials_backend.as_deref())?;
    let root = backend_root(&choice).to_path_buf();
    let store = backend::select(choice, &root)
        .with_context(|| format!("opening credential store at {}", root.display()))?;

    // Keyed by profile, with or without a filter — one shape, and every row
    // says which profile it belongs to. A flat list would be ambiguous
    // across components (two `default` keys, no way to tell them apart) and,
    // worse, would hide the normalisation `profile_key` performs: this
    // listing is where an operator sees that `./x.wasm` was stored under its
    // absolute path.
    let profile = component.as_ref().map(resolve::profile_key);
    let profiles = match &profile {
        Some(p) => vec![p.clone()],
        None => store.components().context("listing credential profiles")?,
    };
    let mut out: BTreeMap<String, Vec<act_credentials::record::SecretInfo>> = BTreeMap::new();
    for p in profiles {
        let infos = store
            .list(Some(&p))
            .with_context(|| format!("listing credentials for {p}"))?;
        // A filtered listing of an empty profile prints `{}`, not a profile
        // with no credentials — "nothing stored" reads the same either way,
        // and it keeps the two paths' output identical.
        if !infos.is_empty() {
            out.insert(p, infos);
        }
    }
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn cmd_rm(component: ComponentRef, key: String, opts: &GlobalOpts) -> Result<()> {
    let choice = resolve_backend(opts.credentials_backend.as_deref())?;
    let root = backend_root(&choice).to_path_buf();
    let store = backend::select(choice, &root)
        .with_context(|| format!("opening credential store at {}", root.display()))?;

    let profile = resolve::profile_key(&component);
    // `erase` is idempotent, so without this check a typo in --key would
    // print "removed" and the operator would believe a credential had been
    // revoked when it is still there. Existence is asked of `get` rather
    // than `list` because `get` reads the store itself while `list` reads
    // the index beside it: a stale index must not be able to block the
    // removal of a real secret. The record is dropped here without being
    // read — nothing in this module can print a value.
    let exists = store
        .get(&profile, &key)
        .with_context(|| format!("reading credential '{key}' for {profile}"))?
        .is_some();
    anyhow::ensure!(
        exists,
        "no credential '{key}' for {profile}; `act secret list {profile}` \
         shows what is stored"
    );
    store
        .erase(&profile, &key)
        .with_context(|| format!("removing credential '{key}' for {profile}"))?;
    println!("removed '{key}' for {profile}");
    Ok(())
}

// ── Backend selection ───────────────────────────────────────────────────

/// Parse `--credentials-backend`, or fall back to the platform default file
/// store.
///
/// The parsing itself lives in `runtime::credentials` — next to the reader —
/// so `act secret set` and `act run` cannot disagree about what a backend
/// string means or where the default store is. What is decided here is only
/// what a *missing* default means: for a write it is fatal and names the
/// flag, where for a run it merely means there are no credentials to read.
fn resolve_backend(explicit: Option<&str>) -> Result<BackendChoice> {
    crate::runtime::credentials::resolve_backend(explicit)?.context(
        "no default credential store location on this platform; \
         pass --credentials-backend file:<path>",
    )
}

/// The file store is plaintext, protected only by filesystem permissions —
/// nothing here encrypts it (spec D13/§7.4). That is the only thing standing
/// between an operator and a false sense of protection, so it is stated
/// once, on the write that creates the store, rather than left to the docs.
///
/// "First write" is decided through the store's own `list`, not by
/// reaching into the file backend's on-disk layout: an empty store is one
/// nothing has ever been written to, regardless of which files that turns
/// out to mean. Matched on `choice` (rather than asserted for every
/// backend) so a future non-file backend doesn't inherit a plaintext
/// warning that no longer applies to it.
///
/// The permissions sentence is platform-specific because the guarantee is:
/// `act_credentials::index::write_private` chmods 0600 on unix and does
/// nothing anywhere else. A notice that overstated the protection on Windows
/// would be worse than none, since this notice is the whole of what the
/// operator is told.
fn disclose_if_first_write(choice: &BackendChoice, store: &dyn CredentialStore) -> Result<()> {
    #[cfg(unix)]
    const PROTECTION: &str = "The only protection is filesystem permissions — its files are written 0600, \
         readable only by this user.";
    #[cfg(not(unix))]
    const PROTECTION: &str = "The only protection is filesystem permissions — and on this platform ACT sets \
         none of its own: the files inherit whatever the containing directory grants.";

    match choice {
        BackendChoice::File(root) => {
            if store
                .list(None)
                .context("checking store contents")?
                .is_empty()
            {
                eprintln!(
                    "act secret: creating a new credential store under {}\n\
                     This store is PLAINTEXT: nothing in ACT encrypts it. {PROTECTION} \
                     Anyone who can read this user's files can read every credential \
                     kept here. There is no OS-keyring backend yet. \
                     (shown once per store)",
                    root.display()
                );
            }
        }
    }
    Ok(())
}

// ── Kind validation ─────────────────────────────────────────────────────

fn validate_kind(reg: &KindRegistry, kind: &str) -> Result<()> {
    if reg.get(kind).is_some() {
        return Ok(());
    }
    let known: Vec<&str> = reg.ids().collect();
    anyhow::bail!(
        "unknown credential kind '{kind}'; known kinds: {}",
        known.join(", ")
    );
}

// ── Field sources ────────────────────────────────────────────────────────

fn parse_fields_json(bytes: &[u8]) -> Result<BTreeMap<String, SecretValue>> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).context("field map is not valid JSON")?;
    let obj = value
        .as_object()
        .context("field map must be a JSON object of field-key -> string")?;
    let mut fields = BTreeMap::new();
    for (k, v) in obj {
        let s = v
            .as_str()
            .with_context(|| format!("field '{k}' must be a JSON string"))?;
        fields.insert(k.clone(), SecretValue::new(s));
    }
    Ok(fields)
}

fn read_fields_from_stdin() -> Result<BTreeMap<String, SecretValue>> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("reading --fields-stdin")?;
    parse_fields_json(buf.as_bytes())
}

fn read_fields_from_command(cmd: &str) -> Result<BTreeMap<String, SecretValue>> {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .with_context(|| format!("running --from-command '{cmd}'"))?;
    anyhow::ensure!(
        output.status.success(),
        "--from-command '{cmd}' exited with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    parse_fields_json(&output.stdout)
}

// ── Interactive prompting ───────────────────────────────────────────────

pub struct Prompt {
    pub field_key: String,
    pub label: String,
    pub hidden: bool,
}

/// Labels come from the registry, never from a caller or a component — a
/// component that could choose the wording would phish (spec §5.5).
pub fn prompts_for(reg: &KindRegistry, kind: &str) -> Option<Vec<Prompt>> {
    let def = reg.get(kind)?;
    Some(
        def.fields
            .iter()
            .filter(|f| f.required)
            .map(|f| Prompt {
                field_key: f.key.clone(),
                label: f.label.clone(),
                hidden: f.secret,
            })
            .collect(),
    )
}

fn prompt_fields_interactively(
    reg: &KindRegistry,
    kind: &str,
) -> Result<BTreeMap<String, SecretValue>> {
    let prompts = prompts_for(reg, kind)
        .ok_or_else(|| anyhow::anyhow!("unknown credential kind '{kind}'"))?;
    let mut fields = BTreeMap::new();
    for p in prompts {
        let value = if p.hidden {
            read_hidden_line(&p.label)?
        } else {
            read_visible_line(&p.label)?
        };
        fields.insert(p.field_key, SecretValue::new(value));
    }
    Ok(fields)
}

fn read_visible_line(label: &str) -> Result<String> {
    eprint!("{label}: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading from stdin")?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Reads one line with terminal echo turned off, so a hidden credential
/// never lands in scrollback or a screen-recording (spec §5.3). Shells out
/// to `stty` rather than pulling in a terminal-control crate — `act-cli`
/// carries none today, and this is a single interactive-only code path.
#[cfg(unix)]
fn read_hidden_line(label: &str) -> Result<String> {
    eprint!("{label}: ");
    std::io::stderr().flush().ok();
    let echo_disabled = std::process::Command::new("stty")
        .arg("-echo")
        .status()
        .is_ok_and(|s| s.success());
    let read_result = {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("reading from stdin")
            .map(|_| line)
    };
    if echo_disabled {
        let _ = std::process::Command::new("stty").arg("echo").status();
    }
    eprintln!();
    Ok(read_result?.trim_end_matches(['\n', '\r']).to_string())
}

/// No terminal-echo control implemented on this platform yet: the value is
/// visible while typed. A known gap, not a silent downgrade — it says so.
#[cfg(not(unix))]
fn read_hidden_line(label: &str) -> Result<String> {
    eprintln!(
        "(warning: hidden input is not implemented on this platform; typing will be visible)"
    );
    read_visible_line(label)
}

#[cfg(test)]
mod tests {
    use super::*;
    use act_credentials::kind::KindRegistry;
    use std::path::PathBuf;

    #[test]
    fn prompts_are_built_from_the_kind_registry_not_from_the_caller() {
        let reg = KindRegistry::builtin();
        let prompts = prompts_for(&reg, "std:basic").unwrap();
        assert_eq!(
            prompts.iter().map(|p| p.label.as_str()).collect::<Vec<_>>(),
            vec!["Username", "Password"]
        );
        assert!(
            prompts.iter().all(|p| p.hidden),
            "both halves of a basic credential are hidden"
        );

        let opaque = prompts_for(&reg, "std:opaque").unwrap();
        assert_eq!(opaque.len(), 1);
        assert_eq!(opaque[0].field_key, "std:value");

        assert!(prompts_for(&reg, "std:nonesuch").is_none());
    }

    #[test]
    fn optional_fields_are_not_prompted_for() {
        let reg = KindRegistry::builtin();
        let prompts = prompts_for(&reg, "std:oauth2").unwrap();
        let keys: Vec<&str> = prompts.iter().map(|p| p.field_key.as_str()).collect();
        assert_eq!(
            keys,
            vec!["std:access-token"],
            "expiry and scopes are derived, not typed"
        );
    }

    #[test]
    fn validate_kind_lists_the_known_kinds() {
        let reg = KindRegistry::builtin();
        assert!(validate_kind(&reg, "std:opaque").is_ok());
        let err = validate_kind(&reg, "std:nonesuch").unwrap_err().to_string();
        assert!(err.contains("std:opaque"), "{err}");
        assert!(err.contains("std:basic"), "{err}");
        assert!(err.contains("std:oauth2"), "{err}");
    }

    #[test]
    fn field_map_rejects_non_string_values() {
        let err = parse_fields_json(br#"{"std:value": 7}"#).unwrap_err();
        assert!(err.to_string().contains("std:value"));
    }

    #[test]
    fn resolve_backend_requires_the_file_scheme() {
        assert!(resolve_backend(Some("keyring")).is_err());
        assert!(resolve_backend(Some("file:")).is_err());
        let BackendChoice::File(p) = resolve_backend(Some("file:/tmp/x")).unwrap();
        assert_eq!(p, PathBuf::from("/tmp/x"));
    }
}
