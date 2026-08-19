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
use act_credentials::kind::{KindDef, KindRegistry};
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
        #[arg(long, default_value = "std:string")]
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
    // Built-ins plus whatever the operator defined. A missing directory is not
    // an error — it is the common case — and a malformed file is, because
    // silently ignoring it would present the operator with an "unknown kind"
    // for a kind they can see on disk.
    let registry = match crate::config::kinds_dir() {
        Some(dir) => KindRegistry::load(&dir).with_context(|| {
            format!("reading credential kind definitions from {}", dir.display())
        })?,
        None => KindRegistry::builtin(),
    };
    let def = validate_kind(&registry, &kind)?;

    // The store is opened, and its nature disclosed, *before* the credential
    // is read. Interactively the operator has to learn the store is plaintext
    // before typing a password into it — a disclosure that arrives afterwards
    // informs nobody of anything they can still act on. The same ordering
    // means a typo'd --credentials-backend fails before a secret has been
    // typed and thrown away. Kind validation stays ahead of both: it needs
    // neither the store nor the credential.
    let choice = resolve_backend(opts.credentials_backend.as_deref())?;
    let root = backend_root(&choice).to_path_buf();
    let store = backend::select(choice.clone(), &root)
        .with_context(|| format!("opening credential store at {}", root.display()))?;
    disclose_if_first_write(&choice, store.as_ref())?;

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
    validate_fields(def, &fields)?;

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
/// while the store is empty, rather than left to the docs.
///
/// This runs *before* the field is read (see `cmd_set`), which means the
/// write it is warning about has not happened yet and may never happen: the
/// field read can still fail, the kind can turn out invalid for the fields
/// given, or a symlink race in `write_private` can refuse the write outright.
/// The wording below is deliberately about the store's current, checkable
/// state ("holds no credentials") and what a write to it *would* mean, never
/// about an action already taken — an operator told "creating a new store"
/// right before a validation error would have been told something false.
///
/// "Empty" is decided through the store's own `list`, not by reaching into
/// the file backend's on-disk layout: a store nothing has been written to
/// reads as empty regardless of which files that turns out to mean — and,
/// symmetrically, `erase`-ing the last credential leaves `secrets.json` on
/// disk but empty, so "the file exists" is not a safe stand-in for "this
/// notice no longer applies." Matched on `choice` (rather than asserted for
/// every backend) so a future non-file backend doesn't inherit a plaintext
/// warning that no longer applies to it.
///
/// It names the file, not just the directory: an operator told that
/// permissions are the only protection needs to know what to chmod, back up,
/// or keep out of a sync client. The name comes from the backend
/// (`file::secrets_path`) so the notice cannot drift from what is written.
///
/// The permissions sentence is platform-specific because the guarantee is:
/// `act_credentials::index::write_private` creates at 0600 on unix and sets
/// nothing anywhere else. A notice that overstated the protection on Windows
/// would be worse than none, since this notice is the whole of what the
/// operator is told.
fn disclose_if_first_write(choice: &BackendChoice, store: &dyn CredentialStore) -> Result<()> {
    disclose_if_first_write_to(&mut std::io::stderr(), choice, store)
}

/// The writer is a parameter (rather than `eprintln!` inline) so the test
/// below can assert on exactly what an operator would see, instead of
/// re-deriving the same string the function itself builds.
fn disclose_if_first_write_to(
    out: &mut dyn Write,
    choice: &BackendChoice,
    store: &dyn CredentialStore,
) -> Result<()> {
    #[cfg(unix)]
    const PROTECTION: &str = "The only protection will be filesystem permissions — the file \
         will be created 0600, readable only by this user.";
    #[cfg(not(unix))]
    const PROTECTION: &str = "The only protection will be filesystem permissions — and on this \
         platform ACT sets none of its own: the file will inherit whatever the containing \
         directory grants.";

    match choice {
        BackendChoice::File(root) => {
            if store
                .list(None)
                .context("checking store contents")?
                .is_empty()
            {
                writeln!(
                    out,
                    "act secret: {} holds no credentials\n\
                     If this write succeeds, it will be the first one, and this store will \
                     be PLAINTEXT: nothing in ACT encrypts it. {PROTECTION} Anyone who can \
                     read this user's files will be able to read every credential kept \
                     here. There is no OS-keyring backend yet. \
                     (shown while the store is empty)",
                    backend::file::secrets_path(root).display()
                )
                .context("writing plaintext-store notice")?;
            }
        }
    }
    Ok(())
}

// ── Kind validation ─────────────────────────────────────────────────────

/// Returns the definition, not just `Ok(())`: the caller needs it to check
/// the fields against the kind that names them.
fn validate_kind<'a>(reg: &'a KindRegistry, kind: &str) -> Result<&'a KindDef> {
    if let Some(def) = reg.get(kind) {
        return Ok(def);
    }
    let known: Vec<&str> = reg.ids().collect();
    anyhow::bail!(
        "unknown credential kind '{kind}'; known kinds: {}",
        known.join(", ")
    );
}

/// A field map has to satisfy the kind that names it.
///
/// Without this, `--kind std:basic --fields-stdin '{"token":"…"}'` is stored
/// happily and the mistake surfaces much later, inside a component, as a
/// missing field it cannot explain. The interactive path is already
/// registry-driven and cannot produce a map that fails here; the two scripted
/// paths accept whatever they are handed, which is exactly where a typo
/// enters.
///
/// Missing required fields are an error. Unknown keys are a warning and are
/// stored: a kind lists what a *reader* can rely on, and a component may
/// legitimately be handed more than that — but an operator who misspelled
/// `std:usrname` should hear about it. Only names are printed; the values
/// they hold never are.
///
/// A *known* key's value must also match the JSON shape its `field_type`
/// promises — `std:string` a string, `std:oauth2` an object — or the
/// mismatch surfaces here, by name, instead of inside a component that
/// receives a string where the SDK expects a map and fails for a reason
/// nothing points back to this command.
fn validate_fields(def: &KindDef, fields: &BTreeMap<String, SecretValue>) -> Result<()> {
    let missing: Vec<&str> = def
        .fields
        .iter()
        .filter(|f| f.required)
        .map(|f| f.key.as_str())
        .filter(|k| !fields.contains_key(*k))
        .collect();
    if !missing.is_empty() {
        let given = if fields.is_empty() {
            "the field map is empty".to_string()
        } else {
            format!(
                "the field map has {}",
                fields.keys().cloned().collect::<Vec<_>>().join(", ")
            )
        };
        anyhow::bail!(
            "credential kind '{}' requires {} — {given}",
            def.id,
            missing.join(", ")
        );
    }
    for (key, value) in fields {
        let Some(field) = def.fields.iter().find(|f| &f.key == key) else {
            eprintln!(
                "act secret: warning: '{key}' is not a field of {}; storing it, but \
                 a component reading this credential by kind will not look for it",
                def.id
            );
            continue;
        };
        let json = value.expose();
        let shape_ok = match field.field_type.as_str() {
            "std:oauth2" => json.is_object(),
            _ => json.is_string(),
        };
        anyhow::ensure!(
            shape_ok,
            "field '{key}' of credential kind '{}' has type {}, which expects {}, \
             not {}",
            def.id,
            field.field_type,
            if field.field_type == "std:oauth2" {
                "an object"
            } else {
                "a string"
            },
            json_type_name(json)
        );
    }
    Ok(())
}

/// A short, human name for a JSON value's shape — used only in error text, so
/// an operator hears "a number", never a struct debug-print of the value
/// itself (which could be the mistyped credential).
fn json_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

// ── Field sources ────────────────────────────────────────────────────────

/// A field-key -> value map, read from `--fields-stdin` or `--from-command`.
/// Each value must be a JSON string (a `std:string` field) or a JSON object
/// (a `std:oauth2` field, or any future field type shaped like one) — every
/// other JSON type, including a bare number or `null`, is rejected here by
/// name, before it ever reaches `validate_fields`. Which shape a *particular*
/// field actually requires is not decided here: this function has no
/// `KindDef` to check against, only the raw map. `validate_fields` cross-
/// checks each value's shape against the field it names.
fn parse_fields_json(bytes: &[u8]) -> Result<BTreeMap<String, SecretValue>> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).context("field map is not valid JSON")?;
    let obj = value
        .as_object()
        .context("field map must be a JSON object of field-key -> value")?;
    let mut fields = BTreeMap::new();
    for (k, v) in obj {
        anyhow::ensure!(
            v.is_string() || v.is_object(),
            "field '{k}' must be a JSON string or object, not {}",
            json_type_name(v)
        );
        fields.insert(k.clone(), SecretValue::new(v.clone()));
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

#[derive(Debug)]
pub struct Prompt {
    pub field_key: String,
    pub label: String,
    pub hidden: bool,
}

/// Labels come from the registry, never from a caller or a component — a
/// component that could choose the wording would phish (spec §5.5).
///
/// Refuses outright if any required field's type is not `std:string`: an
/// `std:oauth2` field is acquired by a browser flow, not typed at a
/// terminal, and prompting for it would store a string where the SDK
/// expects an object — a mismatch that would surface much later, inside a
/// component, as a failure nothing points back to this command. `Result`
/// rather than `Option` so that refusal carries the reason.
pub fn prompts_for(reg: &KindRegistry, kind: &str) -> Result<Vec<Prompt>> {
    let def = reg
        .get(kind)
        .ok_or_else(|| anyhow::anyhow!("unknown credential kind '{kind}'"))?;
    if let Some(f) = def.fields.iter().find(|f| f.field_type != "std:string") {
        anyhow::bail!(
            "field {} has type {}, which cannot be typed at a prompt \
             (a {} value is acquired by its flow, not by hand)",
            f.key,
            f.field_type,
            f.field_type
        );
    }
    Ok(def
        .fields
        .iter()
        .filter(|f| f.required)
        .map(|f| Prompt {
            field_key: f.key.clone(),
            label: f.label.clone(),
            hidden: f.secret,
        })
        .collect())
}

fn prompt_fields_interactively(
    reg: &KindRegistry,
    kind: &str,
) -> Result<BTreeMap<String, SecretValue>> {
    let prompts = prompts_for(reg, kind)?;
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

/// Said before the operator types, never after, in every case where what they
/// type will be visible. Announcing a downgrade once it has happened tells
/// them only that their password is already in the scrollback.
const ECHO_WARNING: &str = "act secret: warning: terminal echo could not be turned off — what you type next \
     WILL be visible on screen and in your scrollback. Ctrl-C and use --fields-stdin \
     or --from-command to avoid it.";

/// Reads one line with terminal echo turned off, so a hidden credential
/// never lands in scrollback or a screen-recording (spec §5.3). Shells out
/// to `stty` rather than pulling in a terminal-control crate — `act-cli`
/// carries none today, and this is a single interactive-only code path.
///
/// If `stty` is missing or fails, the read still happens — refusing would
/// strand an operator whose terminal is otherwise fine — but it says so
/// first, so the choice to keep typing is theirs. Silently reading with echo
/// on would defeat the only thing this function exists for.
#[cfg(unix)]
fn read_hidden_line(label: &str) -> Result<String> {
    let echo_disabled = std::process::Command::new("stty")
        .arg("-echo")
        .status()
        .is_ok_and(|s| s.success());
    if !echo_disabled {
        eprintln!("{ECHO_WARNING}");
    }

    eprint!("{label}: ");
    std::io::stderr().flush().ok();
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
/// visible while typed. A known gap, not a silent downgrade — it says so,
/// with the same warning and at the same point as the unix arm's failure
/// path.
#[cfg(not(unix))]
fn read_hidden_line(label: &str) -> Result<String> {
    eprintln!("{ECHO_WARNING}");
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

        let string_kind = prompts_for(&reg, "std:string").unwrap();
        assert_eq!(string_kind.len(), 1);
        assert_eq!(string_kind[0].field_key, "std:value");

        assert!(prompts_for(&reg, "std:nonesuch").is_err());
    }

    // `optional_fields_are_not_prompted_for` used to exercise `std:oauth2`
    // (expiry and scopes as optional flat fields, filtered out because
    // `required` was false). That subject is gone: `std:oauth2` is now one
    // required field whose value is a map, and the property that replaced
    // it — the whole field is refused rather than partially prompted — is
    // `an_oauth2_field_cannot_be_prompted_for` below.

    /// It is acquired by a flow that does not exist yet. Prompting would
    /// store a string where the SDK expects an object, and the user would
    /// not learn why until the component failed much later.
    #[test]
    fn an_oauth2_field_cannot_be_prompted_for() {
        let reg = KindRegistry::builtin();
        let err = prompts_for(&reg, "std:oauth2").expect_err("must refuse");
        assert!(
            err.to_string().contains("std:oauth2"),
            "name the type: {err}"
        );
    }

    #[test]
    fn validate_kind_lists_the_known_kinds() {
        let reg = KindRegistry::builtin();
        assert!(validate_kind(&reg, "std:string").is_ok());
        let err = validate_kind(&reg, "std:nonesuch").unwrap_err().to_string();
        assert!(err.contains("std:string"), "{err}");
        assert!(err.contains("std:basic"), "{err}");
        assert!(err.contains("std:oauth2"), "{err}");
    }

    #[test]
    fn field_map_rejects_non_string_values() {
        let err = parse_fields_json(br#"{"std:value": 7}"#).unwrap_err();
        assert!(err.to_string().contains("std:value"));
    }

    #[test]
    fn a_string_is_still_rejected_where_a_number_was_given() {
        // The pre-existing guard: a bare number is not a credential value.
        assert!(parse_fields_json(br#"{"std:value": 7}"#).is_err());
    }

    #[test]
    fn an_object_is_accepted_for_an_oauth2_field() {
        let fields = parse_fields_json(
            br#"{"std:token": {"std:access-token": "at", "std:scopes": ["repo"]}}"#,
        )
        .expect("an object is valid for a std:oauth2 field");
        assert!(fields["std:token"].expose().is_object());
    }

    #[test]
    fn validate_fields_rejects_a_string_for_an_oauth2_field() {
        let reg = KindRegistry::builtin();
        let oauth = reg.get("std:oauth2").expect("std:oauth2 registered");
        let mut fields = BTreeMap::new();
        fields.insert("std:token".to_string(), SecretValue::new("not-an-object"));
        let err = validate_fields(oauth, &fields).unwrap_err().to_string();
        assert!(err.contains("std:token"), "{err}");
        assert!(err.contains("std:oauth2"), "{err}");
    }

    #[test]
    fn validate_fields_rejects_an_object_for_a_string_field() {
        let reg = KindRegistry::builtin();
        let string_kind = reg.get("std:string").expect("std:string registered");
        let mut fields = BTreeMap::new();
        fields.insert(
            "std:value".to_string(),
            SecretValue::new(serde_json::json!({"nested": true})),
        );
        let err = validate_fields(string_kind, &fields)
            .unwrap_err()
            .to_string();
        assert!(err.contains("std:value"), "{err}");
    }

    #[test]
    fn validate_fields_errors_on_a_missing_required_field() {
        let reg = KindRegistry::builtin();
        let basic = reg.get("std:basic").expect("std:basic registered");
        let mut fields = BTreeMap::new();
        fields.insert("std:username".to_string(), SecretValue::new("alice"));
        // std:password is required and absent — this must be an error, not a
        // credential silently missing half of what a component expects.
        let err = validate_fields(basic, &fields).unwrap_err().to_string();
        assert!(err.contains("std:password"), "{err}");
        assert!(err.contains("std:basic"), "{err}");
    }

    #[test]
    fn validate_fields_accepts_an_undefined_key_rather_than_rejecting_it() {
        let reg = KindRegistry::builtin();
        let string_kind = reg.get("std:string").expect("std:string registered");
        let mut fields = BTreeMap::new();
        fields.insert("std:value".to_string(), SecretValue::new("v"));
        fields.insert("std:bogus".to_string(), SecretValue::new("x"));
        // A key the kind doesn't define is a warning, not a rejection: a kind
        // lists what a *reader* can rely on, and a component may legitimately
        // be handed more than that. Only the required-field check may bail.
        assert!(validate_fields(string_kind, &fields).is_ok());
    }

    #[test]
    fn resolve_backend_requires_the_file_scheme() {
        assert!(resolve_backend(Some("keyring")).is_err());
        assert!(resolve_backend(Some("file:")).is_err());
        let BackendChoice::File(p) = resolve_backend(Some("file:/tmp/x")).unwrap();
        assert_eq!(p, PathBuf::from("/tmp/x"));
    }

    /// Unit-level coverage of `disclose_if_first_write_to` alone: it drives
    /// the function directly against an empty then a non-empty store, so a
    /// wording regression fails fast without paying for a subprocess.
    ///
    /// This is *not* the regression guard for finding 3 (the notice printing
    /// after fields were read, not before) — that ordering bug lives in
    /// `cmd_set`, which this test never calls. The guard is
    /// `the_plaintext_notice_shows_on_the_first_set_and_falls_silent_on_the_second`
    /// in `tests/secret_cli.rs`, which runs the real `act secret set` binary
    /// twice and reads its real stderr.
    #[test]
    fn the_plaintext_notice_shows_once_per_store_then_falls_silent() {
        let dir = tempfile::tempdir().unwrap();
        let choice = BackendChoice::File(dir.path().to_path_buf());
        let store = backend::select(choice.clone(), dir.path()).unwrap();

        let mut first_run = Vec::new();
        disclose_if_first_write_to(&mut first_run, &choice, store.as_ref()).unwrap();
        let first_run = String::from_utf8(first_run).unwrap();
        assert!(first_run.contains("PLAINTEXT"), "{first_run}");
        let secrets_path = backend::file::secrets_path(dir.path());
        assert!(
            first_run.contains(&secrets_path.display().to_string()),
            "{first_run}"
        );

        // The write the first run's disclosure was standing in front of.
        store
            .put(
                "example-component",
                "default",
                &SecretRecord {
                    kind: "std:opaque".to_string(),
                    fields: BTreeMap::from([(
                        "std:value".to_string(),
                        SecretValue::new("first-secret"),
                    )]),
                    host_only: BTreeMap::new(),
                    description: None,
                    expires_at: None,
                },
            )
            .unwrap();

        let mut second_run = Vec::new();
        disclose_if_first_write_to(&mut second_run, &choice, store.as_ref()).unwrap();
        let second_run = String::from_utf8(second_run).unwrap();
        assert!(
            second_run.is_empty(),
            "a store that already holds a credential must not repeat the notice: {second_run}"
        );
    }
}
