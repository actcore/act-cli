//! `act secret set/list/rm` — the out-of-band write path for
//! `act:credentials` (design §5.1). There is deliberately no `act secret get`:
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
use act_credentials::field::{FieldDef, FieldRegistry};
use act_credentials::record::SecretRecord;
use act_credentials::record::SecretValue;
use act_credentials::store::CredentialStore;

use crate::resolve::{self, ComponentRef};
use crate::runtime::credentials::backend_root;

#[derive(clap::Subcommand)]
pub enum SecretCmd {
    /// Write a credential into a component's profile.
    Set(SetArgs),
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

/// Arguments to `act secret set`. Grouped rather than spread across the
/// subcommand: threading each one through to `cmd_set` as its own positional
/// is what clippy's `too_many_arguments` is for.
#[derive(clap::Args)]
pub struct SetArgs {
    /// Component reference (path, URL, OCI ref, or name) — the same
    /// value `act run` / `act call` use. This is the profile namespace.
    pub component: ComponentRef,
    #[arg(long, default_value = "default")]
    pub key: String,
    /// Name a field to store, repeatable and required: a credential IS its set
    /// of named fields. `--field acme:username --field acme:password` is a
    /// password credential; `--field acme:token` is a single API token.
    ///
    /// No field name is well-known — whoever stores the credential names it, in
    /// their own namespace (the `std:` one is the spec's and is refused here).
    /// A name resolves to a secret `std:string` labelled by itself, or to an
    /// operator's own definition in `$XDG_CONFIG_HOME/act/fields/`.
    ///
    /// `--field NAME=TYPE` states a type a name cannot carry: write
    /// `--field acme:token=std:oauth2` for a value that is an OAuth map rather
    /// than a string. A component that declares its fields states the type
    /// there, and its user never types this.
    #[arg(long = "field", value_name = "NAME[=TYPE]", required = true)]
    pub field: Vec<String>,
    #[arg(long)]
    pub description: Option<String>,
    /// Read a JSON field map from stdin, e.g. `{"acme:token":"..."}`.
    #[arg(long, conflicts_with = "from_command")]
    pub fields_stdin: bool,
    /// Run a command and read its JSON field map from stdout.
    #[arg(long)]
    pub from_command: Option<String>,
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
        SecretCmd::Set(args) => cmd_set(args, opts),
        SecretCmd::List { component } => cmd_list(component, opts),
        SecretCmd::Rm { component, key } => cmd_rm(component, key, opts),
    }
}

fn cmd_set(args: SetArgs, opts: &GlobalOpts) -> Result<()> {
    let SetArgs {
        component,
        key,
        field,
        description,
        fields_stdin,
        from_command,
    } = args;
    // Whatever the operator defined, and nothing else. A missing directory is
    // not an error — it is the common case — and a malformed file is, because
    // silently ignoring it would present the operator with a field definition
    // they can see on disk but the command cannot.
    let registry = match crate::config::fields_dir() {
        Some(dir) => FieldRegistry::load(&dir).with_context(|| {
            format!(
                "reading credential field definitions from {}",
                dir.display()
            )
        })?,
        None => FieldRegistry::default(),
    };
    // The fields to store, in the order they were named. An operator's own
    // definition brings its label, type and secrecy; anything else is a secret
    // string labelled by its own name (design §3.2 — meaning lives in names, so
    // a name is presented verbatim rather than dressed in invented words).
    // `--field` is `required` at the clap layer, so an empty list never
    // reaches here and there is no second guard for it: two enforcement points
    // for one rule means one of them is untested.
    let defs: Vec<FieldDef> = field
        .iter()
        .map(|arg| field_def_from_arg(arg, &registry))
        .collect::<Result<_>>()?;

    // The store is opened, and its nature disclosed, *before* the credential
    // is read. Interactively the operator has to learn the store is plaintext
    // before typing a password into it — a disclosure that arrives afterwards
    // informs nobody of anything they can still act on. The same ordering
    // means a typo'd --credentials-backend fails before a secret has been
    // typed and thrown away. Parsing `--field` stays ahead of both: it needs
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
        prompt_fields_interactively(&defs)?
    } else {
        anyhow::bail!(
            "no credential source: stdin is not a terminal, so a value \
             cannot be prompted for. Use --fields-stdin or --from-command."
        );
    };
    validate_fields(&defs, &fields)?;

    let profile = resolve::profile_key(&component);
    let record = SecretRecord {
        // Every credential is a set of named fields now, so the stored `kind`
        // says exactly that. The WIT requires the field; this is the true thing
        // to put in it.
        kind: crate::login_cmd::KIND_FIELDS.to_string(),
        fields,
        host_only: BTreeMap::new(),
        description,
        expires_at: None,
    };
    store
        .put(&profile, &key, &record)
        .with_context(|| format!("writing credential '{key}' for {profile}"))?;

    // Prompt order, filtered by what is actually in the record — an optional
    // field that was skipped was never stored and must not be reported as if
    // it were.
    let names: Vec<&str> = defs
        .iter()
        .map(|d| d.key.as_str())
        .filter(|k| record.fields.contains_key(*k))
        .collect();
    println!("stored '{key}' for {profile}: {}", names.join(", "));
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
///
/// `pub(crate)` so `act login` (which also writes) resolves a backend the
/// same way rather than growing its own copy of this wrapper.
pub(crate) fn resolve_backend(explicit: Option<&str>) -> Result<BackendChoice> {
    crate::runtime::credentials::resolve_backend(explicit)?.context(
        "no default credential store location on this platform; \
         pass --credentials-backend file:<path>",
    )
}

/// The file store is plaintext, protected only by filesystem permissions —
/// nothing here encrypts it (design D13/§7.4). That is the only thing standing
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
/// A field map has to satisfy the fields that were asked for.
///
/// Without this, `--field acme:username --fields-stdin '{"token":"…"}'` is
/// stored happily and the mistake surfaces much later, inside a component, as a
/// missing field it cannot explain. The interactive path is already
/// registry-driven and cannot produce a map that fails here; the two scripted
/// paths accept whatever they are handed, which is exactly where a typo
/// enters.
///
/// Missing required fields are an error. Unknown keys are a warning and are
/// stored: the asked-for list is what a *reader* can rely on, and a component
/// may legitimately be handed more than that — but an operator who misspelled
/// `std:usrname` should hear about it. Only names are printed; the values
/// they hold never are.
///
/// A *known* key's value must also match the JSON shape its `field_type`
/// promises — `std:string` a string, `std:oauth2` an object — or the
/// mismatch surfaces here, by name, instead of inside a component that
/// receives a string where the SDK expects a map and fails for a reason
/// nothing points back to this command.
fn validate_fields(defs: &[FieldDef], fields: &BTreeMap<String, SecretValue>) -> Result<()> {
    let missing: Vec<&str> = defs
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
        anyhow::bail!("missing {} — {given}", missing.join(", "));
    }
    for (key, value) in fields {
        let Some(field) = defs.iter().find(|f| &f.key == key) else {
            // Refused, not warned. `--field` names every field explicitly, so a
            // key that is not among them is a disagreement between what the
            // operator asked for and what their helper produced — and the
            // material lands in a plaintext store either way. A warning is the
            // wrong instrument for that: `--from-command` is a CI shape, and
            // nobody reads stderr there.
            //
            // (An earlier version stored it. That rule dates from when a
            // credential's shape came from its kind, so extra keys were
            // plausibly meaningful; now nothing asked for this one.)
            anyhow::bail!(
                "'{key}' was not among the fields asked for ({}); nothing was \
                 stored. Name it with --field, or leave it out of the input.",
                defs.iter()
                    .map(|d| d.key.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        };
        let json = value.expose();
        let shape_ok = match field.field_type.as_str() {
            "std:oauth2" => json.is_object(),
            _ => json.is_string(),
        };
        anyhow::ensure!(
            shape_ok,
            "field '{key}' has type {}, which expects {}, not {}",
            field.field_type,
            if field.field_type == "std:oauth2" {
                "an object"
            } else {
                "a string"
            },
            json_type_name(json)
        );

        // An object is not enough. `as_oauth2` treats a missing or mistyped
        // member as ABSENT rather than as an error, so an oauth2 field without
        // an access token stores cleanly and then reads as "no credential" —
        // and a float expiry reads as "never expires", a string scopes list as
        // "grants nothing". Before this migration the three members were
        // required top-level fields and this input was a hard error; keeping it
        // an error here is what stops the migration loosening the check.
        // Members and encodings: ACT-CONSTANTS.md §8.3.
        if field.field_type == "std:oauth2" {
            let members = json.as_object().expect("checked by shape_ok above");
            anyhow::ensure!(
                members
                    .get("std:access-token")
                    .is_some_and(|v| v.is_string()),
                "field '{key}' is a std:oauth2 credential but has no \
                 'std:access-token' string; a component reading it would see no \
                 credential at all rather than an error"
            );
            if let Some(exp) = members.get("std:expires-at") {
                anyhow::ensure!(
                    exp.is_u64(),
                    "'std:expires-at' must be a whole number of Unix seconds, not {}; \
                     anything else is read as 'never expires'",
                    json_type_name(exp)
                );
            }
            if let Some(scopes) = members.get("std:scopes") {
                anyhow::ensure!(
                    scopes
                        .as_array()
                        .is_some_and(|a| a.iter().all(|s| s.is_string())),
                    "'std:scopes' must be a list of strings, not {}; anything else \
                     is read as 'no scopes granted'",
                    json_type_name(scopes)
                );
            }
        }
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
    /// False for a field the declaration marked optional. Such a field is
    /// still prompted for — it is skipped by answering nothing, not by being
    /// hidden from the only interactive path there is.
    pub required: bool,
}

impl Prompt {
    /// The line the operator reads.
    ///
    /// `show_key` puts the field's namespaced key beside the label, which is
    /// how a component's own wording is marked as foreign (design §5.5). The
    /// skip hint is the host's own words and is appended last, so a component
    /// cannot author a prompt that looks skippable when it is not — and if it
    /// copies the wording into its label, answering nothing still fails on a
    /// required field.
    pub fn line(&self, show_key: bool) -> String {
        let mut line = if show_key {
            format!("  {} [{}]", self.label, self.field_key)
        } else {
            self.label.clone()
        };
        if !self.required {
            line.push_str(" (optional — Enter to skip)");
        }
        line
    }
}

/// The two types `ACT-CONSTANTS.md` §8.1 registers. A field of any other type
/// MUST be rejected rather than coerced, so this list is the whole of it.
const FIELD_TYPES: [&str; 2] = ["std:string", "std:oauth2"];

/// Parse one `--field` argument into the definition to prompt for and validate
/// against: `NAME`, or `NAME=TYPE` to say what a name alone cannot.
///
/// Names are not registered — whoever stores a credential names its fields
/// (`ACT-CONSTANTS.md` §8.2) — so a name carries no type, and `std:string` is
/// the default because a credential typed at a terminal is a string. `=TYPE` is
/// how the other case is expressed without a declaration to carry it: a bridge
/// storing an OAuth map it obtained by hand writes `--field acme:token=std:oauth2`.
/// A component that declares its fields states the type there and its user
/// never types this.
///
/// The `std:` namespace is the spec's. An operator's own definition file cannot
/// mint into it and neither can a `--field`, for the same reason `act-build`
/// refuses it in a declaration: a `std:` name reads as though this host gave it
/// meaning, and no host may hand that out.
pub(crate) fn field_def_from_arg(arg: &str, registry: &FieldRegistry) -> Result<FieldDef> {
    let (name, explicit) = match arg.split_once('=') {
        Some((n, ty)) => (n, Some(ty)),
        None => (arg, None),
    };
    anyhow::ensure!(!name.is_empty(), "--field needs a name, got '{arg}'");
    anyhow::ensure!(
        !name.starts_with("std:"),
        "--field '{name}' is in the std: namespace, which is the spec's. \
         No field name is registered there — name it in your own, e.g. \
         'acme:{}'.",
        name.trim_start_matches("std:")
    );

    let mut def = registry.resolve(name);
    if let Some(ty) = explicit {
        anyhow::ensure!(
            FIELD_TYPES.contains(&ty),
            "'{ty}' is not a field type; ACT-CONSTANTS §8.1 registers {}",
            FIELD_TYPES.join(" and ")
        );
        // A definition on disk and a type on the command line that disagree is
        // the operator contradicting themselves. Refusing beats picking a
        // winner they cannot see.
        if let Some(defined) = registry.get(name) {
            anyhow::ensure!(
                defined.field_type == ty,
                "--field says '{name}' is {ty}, but its definition says {}. \
                 Fix one of them.",
                defined.field_type
            );
        }
        def.field_type = ty.to_string();
    }
    Ok(def)
}

/// Labels come from the registry, never from a caller or a component — a
/// component that could choose the wording would phish (design §5.5).
///
/// Refuses outright if any required field's type is not `std:string`: an
/// `std:oauth2` field is acquired by a browser flow, not typed at a
/// terminal, and prompting for it would store a string where the SDK
/// expects an object — a mismatch that would surface much later, inside a
/// component, as a failure nothing points back to this command. `Result`
/// rather than `Option` so that refusal carries the reason.
pub fn prompts_for(defs: &[FieldDef]) -> Result<Vec<Prompt>> {
    if let Some(f) = defs.iter().find(|f| f.field_type != "std:string") {
        anyhow::bail!(
            "field {} has type {}, which cannot be typed at a prompt \
             (a {} value is acquired by its flow, not by hand)",
            f.key,
            f.field_type,
            f.field_type
        );
    }
    Ok(defs
        .iter()
        .map(|f| Prompt {
            field_key: f.key.clone(),
            label: f.label.clone(),
            hidden: f.secret,
            required: f.required,
        })
        .collect())
}

/// Reads one field. `None` means an optional field was skipped.
///
/// The empty answer carries both meanings, which is why this is one function
/// and not two call sites deciding for themselves. On a **required** field it
/// is the same failure as EOF one layer up: a credential that stores cleanly
/// and holds nothing, so the operator believes they provisioned something and
/// the component finds nothing. On an **optional** field it is the whole point
/// — that is how the field is left out. Someone whose credential really is the
/// empty string has `--fields-stdin`.
pub(crate) fn prompt_one(p: &Prompt, show_key: bool) -> Result<Option<SecretValue>> {
    let shown = p.line(show_key);
    let value = if p.hidden {
        read_hidden_line(&shown)?
    } else {
        read_visible_line(&shown)?
    };
    if value.is_empty() {
        anyhow::ensure!(
            !p.required,
            "'{}' cannot be empty — nothing was stored",
            p.field_key
        );
        return Ok(None);
    }
    Ok(Some(SecretValue::new(value)))
}

fn prompt_fields_interactively(defs: &[FieldDef]) -> Result<BTreeMap<String, SecretValue>> {
    let prompts = prompts_for(defs)?;
    let mut fields = BTreeMap::new();
    for p in &prompts {
        // `show_key = false`: every label here came from the registry or is a
        // field name the operator typed, so none of it is a component's prose.
        if let Some(value) = prompt_one(p, false)? {
            fields.insert(p.field_key.clone(), value);
        }
    }
    Ok(fields)
}

pub(crate) fn read_visible_line(label: &str) -> Result<String> {
    eprint!("{label}: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    let read = std::io::stdin()
        .read_line(&mut line)
        .context("reading from stdin")?;
    // See `read_hidden_line`: EOF is an aborted prompt, not an empty value.
    anyhow::ensure!(read > 0, "no input for '{label}' — nothing was stored");
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Said before the operator types, never after, in every case where what they
/// type will be visible. Announcing a downgrade once it has happened tells
/// them only that their password is already in the scrollback.
const ECHO_WARNING: &str = "act secret: warning: terminal echo could not be turned off — what you type next \
     WILL be visible on screen and in your scrollback. Ctrl-C and use --fields-stdin \
     or --from-command to avoid it.";

/// Reads one line with terminal echo turned off, so a hidden credential
/// never lands in scrollback or a screen-recording (design §5.3). Shells out
/// to `stty` rather than pulling in a terminal-control crate — `act-cli`
/// carries none today, and this is a single interactive-only code path.
///
/// If `stty` is missing or fails, the read still happens — refusing would
/// strand an operator whose terminal is otherwise fine — but it says so
/// first, so the choice to keep typing is theirs. Silently reading with echo
/// on would defeat the only thing this function exists for.
#[cfg(unix)]
pub(crate) fn read_hidden_line(label: &str) -> Result<String> {
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
            .map(|n| (n, line))
    };
    if echo_disabled {
        let _ = std::process::Command::new("stty").arg("echo").status();
    }
    eprintln!();
    let (read, line) = read_result?;
    // EOF is not an empty credential. `read_line` returns Ok(0) at end of
    // input — a closed pipe, or Ctrl-D at the prompt — and treating that as ""
    // stores an empty value and reports success, which is worse than failing:
    // the operator believes they provisioned something.
    anyhow::ensure!(read > 0, "no input for '{label}' — nothing was stored");
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// No terminal-echo control implemented on this platform yet: the value is
/// visible while typed. A known gap, not a silent downgrade — it says so,
/// with the same warning and at the same point as the unix arm's failure
/// path.
#[cfg(not(unix))]
pub(crate) fn read_hidden_line(label: &str) -> Result<String> {
    eprintln!("{ECHO_WARNING}");
    read_visible_line(label)
}

#[cfg(test)]
mod tests {
    use super::*;
    use act_credentials::field::FieldRegistry;
    use std::path::PathBuf;

    /// The field definitions a caller would get for these `--field` arguments —
    /// the same path `cmd_set` takes, `NAME=TYPE` included.
    fn defs(args: &[&str]) -> Vec<FieldDef> {
        let reg = FieldRegistry::default();
        args.iter()
            .map(|a| field_def_from_arg(a, &reg).expect("a valid --field"))
            .collect()
    }

    #[test]
    fn a_name_with_no_definition_is_a_secret_string_labelled_by_itself() {
        let prompts = prompts_for(&defs(&["acme:token"])).unwrap();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].field_key, "acme:token");
        assert_eq!(
            prompts[0].label, "acme:token",
            "a name is shown verbatim, not dressed in invented words"
        );
        assert!(
            prompts[0].hidden,
            "a field is credential material until someone says otherwise"
        );
    }

    /// No name is well-known, so there is nothing for a caller to select and
    /// nothing for a component to author: a label is the operator's word or the
    /// name itself, never a string that arrived with the request.
    #[test]
    fn a_label_comes_from_the_operators_definition_or_from_the_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("user.toml"),
            "key = \"acme:username\"\nlabel = \"Account\"\n",
        )
        .unwrap();
        let reg = FieldRegistry::load(dir.path()).unwrap();
        let defs: Vec<FieldDef> = ["acme:username", "acme:password"]
            .iter()
            .map(|a| field_def_from_arg(a, &reg).unwrap())
            .collect();
        let prompts = prompts_for(&defs).unwrap();
        assert_eq!(
            prompts.iter().map(|p| p.label.as_str()).collect::<Vec<_>>(),
            vec!["Account", "acme:password"]
        );
        assert!(
            prompts.iter().all(|p| p.hidden),
            "both halves of a password credential are material"
        );
    }

    #[test]
    fn a_field_argument_may_not_mint_a_std_name() {
        let reg = FieldRegistry::default();
        let err = field_def_from_arg("std:password", &reg)
            .unwrap_err()
            .to_string();
        assert!(err.contains("std:"), "{err}");
        assert!(
            err.contains("acme:password"),
            "offer the fix in the caller's own namespace: {err}"
        );
    }

    #[test]
    fn a_field_argument_states_a_type_a_name_cannot_carry() {
        let d = defs(&["acme:token=std:oauth2"]);
        assert_eq!(d[0].key, "acme:token");
        assert_eq!(d[0].field_type, "std:oauth2");
        assert_eq!(
            defs(&["acme:token"])[0].field_type,
            "std:string",
            "a bare name is a string — what a terminal can carry"
        );
    }

    #[test]
    fn an_unknown_field_type_is_refused_with_the_ones_that_exist() {
        let reg = FieldRegistry::default();
        let err = field_def_from_arg("acme:token=std:basic", &reg)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("std:string") && err.contains("std:oauth2"),
            "name the two that exist: {err}"
        );
    }

    #[test]
    fn a_type_that_contradicts_the_operators_definition_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("token.toml"),
            "key = \"acme:token\"\nlabel = \"Token\"\ntype = \"std:oauth2\"\n",
        )
        .unwrap();
        let reg = FieldRegistry::load(dir.path()).unwrap();
        let err = field_def_from_arg("acme:token=std:string", &reg)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("std:string") && err.contains("std:oauth2"),
            "show both sides of the contradiction: {err}"
        );
    }

    /// It is acquired by a flow that does not exist yet. Prompting would
    /// store a string where the SDK expects an object, and the user would
    /// not learn why until the component failed much later.
    #[test]
    fn an_oauth2_field_cannot_be_prompted_for() {
        let err = prompts_for(&defs(&["acme:token=std:oauth2"])).expect_err("must refuse");
        assert!(
            err.to_string().contains("std:oauth2"),
            "name the type: {err}"
        );
    }

    #[test]
    fn field_map_rejects_values_that_are_neither_string_nor_object() {
        let err = parse_fields_json(br#"{"acme:password": 7}"#).unwrap_err();
        assert!(err.to_string().contains("acme:password"));
    }

    #[test]
    fn an_oauth2_object_without_an_access_token_is_rejected() {
        // The regression this migration introduced and the final review caught:
        // an object alone satisfied the shape check, so a credential with no
        // token stored cleanly. `as_oauth2` reads a missing member as ABSENT,
        // never as an error, so the component would see no credential and the
        // operator would see a success.
        let fields = BTreeMap::from([(
            "acme:token".to_string(),
            SecretValue::new(serde_json::json!({"std:scopes": ["repo"]})),
        )]);
        let err = validate_fields(&defs(&["acme:token=std:oauth2"]), &fields)
            .expect_err("must not store a tokenless credential");
        assert!(
            err.to_string().contains("std:access-token"),
            "the error must name what is missing: {err}"
        );
    }

    #[test]
    fn a_mistyped_oauth2_member_is_rejected_with_what_it_would_have_meant() {
        // Both of these degrade silently in the SDK rather than erroring, which
        // is why they are caught at input instead. ACT-CONSTANTS 8.3.
        for (bad, expected) in [
            (
                serde_json::json!({"std:access-token": "at", "std:expires-at": 1.5}),
                "never expires",
            ),
            (
                serde_json::json!({"std:access-token": "at", "std:scopes": "repo"}),
                "no scopes granted",
            ),
        ] {
            let fields =
                BTreeMap::from([("acme:token".to_string(), SecretValue::new(bad.clone()))]);
            let err = validate_fields(&defs(&["acme:token=std:oauth2"]), &fields)
                .expect_err("must reject");
            assert!(
                err.to_string().contains(expected),
                "the error should say what the mistyping would have meant: {err}"
            );
        }
    }

    #[test]
    fn an_optional_field_is_prompted_for_with_a_way_to_skip_it() {
        // `required` is meaningful for a *declared* field — a component may
        // mark one optional — and it must not remove the field from the only
        // interactive path there is. An optional field the operator never sees
        // can only be set by hand-writing JSON for `--fields-stdin`, which is
        // the ceremony `act login` exists to remove.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("needed.toml"),
            "key = \"acme:needed\"\nlabel = \"Needed\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("optional.toml"),
            "key = \"acme:optional\"\nlabel = \"Optional\"\nrequired = false\n",
        )
        .unwrap();
        let reg = FieldRegistry::load(dir.path()).unwrap();
        let defs: Vec<FieldDef> = ["acme:needed", "acme:optional"]
            .iter()
            .map(|n| reg.resolve(n))
            .collect();
        let prompts = prompts_for(&defs).expect("both fields are std:string");
        let keys: Vec<&str> = prompts.iter().map(|p| p.field_key.as_str()).collect();
        assert_eq!(
            keys,
            ["acme:needed", "acme:optional"],
            "an optional field is offered, not hidden"
        );

        let needed = &prompts[0];
        let optional = &prompts[1];
        assert!(needed.required && !optional.required);
        assert!(
            !needed.line(false).contains("Enter to skip"),
            "a required field must not look skippable: {}",
            needed.line(false)
        );
        assert!(
            optional.line(false).contains("Enter to skip"),
            "the way out has to be visible at the prompt: {}",
            optional.line(false)
        );
    }

    /// The skip hint is the host's words, appended after the component's.
    ///
    /// A component that copies "(optional — Enter to skip)" into its own label
    /// gains nothing: the flag decides, not the wording, so answering nothing
    /// on its required field still refuses.
    #[test]
    fn the_skip_hint_cannot_be_forged_by_a_label() {
        let forged = FieldDef {
            key: "acme:token".into(),
            label: "Token (optional — Enter to skip)".into(),
            field_type: "std:string".into(),
            secret: true,
            required: true,
        };
        let prompts = prompts_for(&[forged]).unwrap();
        assert!(prompts[0].required, "the label does not decide this");
        assert!(
            prompts[0].line(true).contains("[acme:token]"),
            "a component's own wording is still marked foreign: {}",
            prompts[0].line(true)
        );
    }

    #[test]
    fn an_operator_file_cannot_mint_a_std_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("password.toml"),
            "key = \"std:password\"\nlabel = \"Not a password\"\nsecret = false\n",
        )
        .unwrap();
        let reg = FieldRegistry::load(dir.path()).unwrap();
        assert!(
            reg.get("std:password").is_none(),
            "the file must be ignored, not loaded under a std: name"
        );
        // And the name stays refused at the argument, so the file cannot be
        // reached by naming it either.
        assert!(field_def_from_arg("std:password", &reg).is_err());
    }

    #[test]
    fn an_object_is_accepted_for_an_oauth2_field() {
        let fields = parse_fields_json(
            br#"{"acme:token": {"std:access-token": "at", "std:scopes": ["repo"]}}"#,
        )
        .expect("an object is valid for a std:oauth2 field");
        assert!(fields["acme:token"].expose().is_object());
    }

    #[test]
    fn validate_fields_rejects_a_string_for_an_oauth2_field() {
        let mut fields = BTreeMap::new();
        fields.insert("acme:token".to_string(), SecretValue::new("not-an-object"));
        let err = validate_fields(&defs(&["acme:token=std:oauth2"]), &fields)
            .unwrap_err()
            .to_string();
        assert!(err.contains("acme:token"), "{err}");
        assert!(err.contains("std:oauth2"), "{err}");
    }

    #[test]
    fn validate_fields_rejects_an_object_for_a_string_field() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "acme:password".to_string(),
            SecretValue::new(serde_json::json!({"nested": true})),
        );
        let err = validate_fields(&defs(&["acme:password"]), &fields)
            .unwrap_err()
            .to_string();
        assert!(err.contains("acme:password"), "{err}");
    }

    #[test]
    fn validate_fields_errors_on_a_missing_required_field() {
        let mut fields = BTreeMap::new();
        fields.insert("acme:username".to_string(), SecretValue::new("alice"));
        // acme:password was asked for and is absent — this must be an error, not
        // a credential silently missing half of what a component expects.
        let err = validate_fields(&defs(&["acme:username", "acme:password"]), &fields)
            .unwrap_err()
            .to_string();
        assert!(err.contains("acme:password"), "{err}");
        assert!(
            err.contains("acme:username"),
            "say what WAS given, so the operator can see the difference: {err}"
        );
    }

    #[test]
    fn validate_fields_refuses_a_key_nobody_asked_for() {
        // Distinctive values, so "the error never carries one" is a claim a
        // single letter cannot accidentally satisfy.
        let mut fields = BTreeMap::new();
        fields.insert(
            "acme:username".to_string(),
            SecretValue::new("user-sentinel"),
        );
        fields.insert(
            "acme:password".to_string(),
            SecretValue::new("password-sentinel"),
        );
        fields.insert(
            "acme:extra".to_string(),
            SecretValue::new("surplus-sentinel"),
        );
        // The operator named two fields; a helper returned three. Storing the
        // third would put material nobody asked for into a plaintext store,
        // announced only by a warning on a stderr that CI does not read.
        let err = validate_fields(&defs(&["acme:username", "acme:password"]), &fields)
            .unwrap_err()
            .to_string();
        assert!(err.contains("acme:extra"), "name the surplus key: {err}");
        assert!(
            err.contains("acme:username") && err.contains("acme:password"),
            "and what was asked for, so the difference is visible: {err}"
        );
        for sentinel in ["user-sentinel", "password-sentinel", "surplus-sentinel"] {
            assert!(
                !err.contains(sentinel),
                "{sentinel} is material and must not be in an error: {err}"
            );
        }
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
                    kind: crate::login_cmd::KIND_FIELDS.to_string(),
                    fields: BTreeMap::from([(
                        "acme:password".to_string(),
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
