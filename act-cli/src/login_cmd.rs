//! `act login` — provisions a credential a component declares it expects, by
//! prompting (design §5.2). The interactive counterpart to `act secret set`;
//! both end at the same `CredentialStore::put`, and neither has a `get`: a
//! value is never printed by anything in either module.
//!
//! Order of operations follows design §5.2, cheapest check first:
//!
//! 1. Does the component declare `act:credentials` at all? This needs only
//!    the `act:component` custom section — no store, no prompt, no network.
//! 2. Which declared credential? (`select_credential`)
//! 3. What fields does it need, and can they be acquired at a prompt?
//!    (`field_set`, which never duplicates `secret_cmd::prompts_for`'s
//!    "a type this host cannot prompt for is refused" rule — it routes every
//!    field list through that one check instead, declared or `--field`.)
//! 4. Does a credential already sit under that key? Never overwritten
//!    without `--force`.
//! 5. Prompt, hidden for secret fields.
//! 6. Write, and report what was stored — never a value.

use std::collections::BTreeMap;

use anyhow::{Context, Result};

use act_credentials::backend;
use act_credentials::field::{FieldDef, FieldRegistry};
use act_credentials::record::{SecretRecord, SecretValue};

use crate::resolve::{self, ComponentRef};
use crate::runtime::credentials::backend_root;
use act_policy::providers::credentials::CAP_CREDENTIALS;

use act_types::types::{StdCredential, StdCredentialField};

/// Flags specific to `act login`. Deliberately no `CommonOpts`/`--config`:
/// this command never instantiates a component, the same reason `act secret`
/// does not carry it either (see the `config_path` match in `main.rs`).
#[derive(clap::Args, Debug)]
pub struct LoginOpts {
    /// Which declared credential to provision — the `key` of one of the
    /// component's `[[std.credentials]]` entries. Omit when the component
    /// declares exactly one; required when it declares several, or none (an
    /// open credential set — a bridge that accepts whatever key an operator
    /// names).
    #[arg(long)]
    pub key: Option<String>,

    /// Name a field to prompt for, repeatable, `NAME` or `NAME=TYPE`. Only
    /// consulted when the selected credential declares no field list of its own
    /// — a component that names its own fields always wins, and its user needs
    /// this only for a bridge, whose credential set is open by nature.
    #[arg(long = "field", value_name = "NAME[=TYPE]")]
    pub field: Vec<String>,

    /// Replace a credential already stored under the same key. Without this,
    /// an existing credential is left untouched and reported, not silently
    /// overwritten.
    #[arg(long)]
    pub force: bool,

    /// Words to record with the credential, shown by `act secret list`.
    ///
    /// The operator's own. A component's `[[std.credentials]]` description is
    /// shown while provisioning, marked as the component's, and is deliberately
    /// not recorded: once in the store nothing distinguishes it from words the
    /// operator chose, and it reaches the agent from there (ACT-AUTH §1.1.5).
    /// Prose a component wrote must stay attributable to it (§5.5).
    #[arg(long)]
    pub description: Option<String>,

    /// Credential store to write to: `file:<path>`. Same flag, parser and
    /// default as `act secret` — a credential `act login` writes is found by
    /// the same run that would read it.
    #[arg(long = "credentials-backend", value_name = "BACKEND")]
    pub credentials_backend: Option<String>,
}

pub async fn cmd_login(component: ComponentRef, opts: LoginOpts) -> Result<()> {
    // 1. Cheapest check first: read the `act:component` custom section
    // without instantiating the component — the same path
    // `act inspect component-manifest` uses (main.rs's
    // `cmd_inspect_component_manifest`) — and ask whether it declares
    // `act:credentials` at all. Everything after this point is more
    // expensive (a store open, a chosen key, a prompt), so a component
    // that was simply the wrong target is told so before any of it runs.
    let component_path = resolve::resolve(&component, false).await?;
    let wasm_bytes = std::fs::read(&component_path).context("reading component file")?;
    let info = crate::runtime::read_component_info(&wasm_bytes)?;

    if !info.std.capabilities.has(CAP_CREDENTIALS) {
        anyhow::bail!("{component} uses no credentials");
    }

    // 2. Which credential?
    let declared = select_credential(&info.std.credentials, opts.key.as_deref(), &component)?;

    // 3. Resolve the field set: the declaration if it names one, else the
    // definitions the registry resolves for --field. Refuses a field type this release
    // cannot acquire (std:oauth2 needs the browser flow, not a prompt) —
    // one implementation of that rule, inside `field_set`.
    let registry = match crate::config::fields_dir() {
        Some(dir) => FieldRegistry::load(&dir).with_context(|| {
            format!(
                "reading credential field definitions from {}",
                dir.display()
            )
        })?,
        None => FieldRegistry::default(),
    };
    let FieldSet {
        prompts,
        oauth,
        labels_are_the_components,
    } = field_set(&declared, &opts.field, &registry)?;

    // Open the store only now: a component that fails the cheapest check or
    // the field-type check never touches it, so a headless run against the
    // wrong target cannot accidentally create or disclose a store.
    let choice = crate::secret_cmd::resolve_backend(opts.credentials_backend.as_deref())?;
    let root = backend_root(&choice).to_path_buf();
    let store = backend::select(choice, &root)
        .with_context(|| format!("opening credential store at {}", root.display()))?;

    let profile = resolve::profile_key(&component);

    // 4. Never overwrite silently.
    let exists = store
        .get(&profile, &declared.key)
        .with_context(|| format!("reading credential '{}' for {profile}", declared.key))?
        .is_some();
    anyhow::ensure!(
        !exists || opts.force,
        "{component} already has a credential under '{}'; pass --force to replace it",
        declared.key
    );

    // 5. Prompt in order, hidden for secret fields, skippable for optional
    // ones.
    //
    // Everything the component wrote is shown below the component reference and
    // marked as its words. Otherwise a component called `innocent-weather`
    // prints "GitHub password:" in the host's voice, which is the attack §5.5
    // names first.
    if labels_are_the_components || declared.description.is_some() {
        eprintln!("Provisioning '{}' for {component}.", declared.key);
    }
    if let Some(described) = &declared.description {
        // `{:?}` quotes and escapes: a description carrying a newline cannot
        // forge a line that looks like the host's own.
        eprintln!("That component describes it as {described:?}");
    }
    if labels_are_the_components {
        eprintln!("The prompts below use wording supplied by that component, not by act:");
    }
    let mut fields = BTreeMap::new();
    for p in &prompts {
        // `prompt_one` owns what an empty answer means — a refusal on a
        // required field, a skip on an optional one — so the rule lives in one
        // place and `act secret set` cannot drift from `act login`.
        if let Some(value) = crate::secret_cmd::prompt_one(p, labels_are_the_components)? {
            fields.insert(p.field_key.clone(), value);
        }
    }

    // 5b. The fields a terminal cannot carry. Each runs its own flow, because
    // `resource` and `scopes` sit on the field: a credential may hold an OAuth
    // token for one upstream beside a plain string for something else, and a
    // refresh later rewrites one field without touching its siblings (§3.2).
    let mut host_only = BTreeMap::new();
    let mut expires_at: Option<i64> = None;
    for f in &oauth {
        let resource = f.resource.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "field '{}' is {OAUTH2} but its declaration names no resource, \
                 and the flow derives every address it contacts from one",
                f.key
            )
        })?;
        eprintln!("Field {} is acquired by an OAuth flow.", f.key);
        let acquired = crate::oauth::run::acquire(
            crate::oauth::run::Request {
                resource,
                scopes: &f.scopes,
                port: None,
                store_root: &root,
                open_with: None,
            },
            now_unix()?,
        )
        .await?;

        let split = split_acquired(&f.key, acquired);
        if let Some(exp) = split.expires_at {
            // The record's own expiry is the soonest of its fields'.
            expires_at = Some(expires_at.map_or(exp, |cur: i64| cur.min(exp)));
        }
        fields.insert(f.key.clone(), split.field);
        host_only.extend(split.host_only);
    }

    // 6. Write, and report what was stored — never a value, and never a field
    // that was skipped.
    let field_names: Vec<&str> = prompts
        .iter()
        .map(|p| p.field_key.as_str())
        .chain(oauth.iter().map(|f| f.key.as_str()))
        .filter(|k| fields.contains_key(*k))
        .collect();
    let record = SecretRecord {
        // Every credential is a set of named fields, whether the component
        // declared them or the user named them, so the stored kind says so.
        kind: KIND_FIELDS.to_string(),
        fields,
        host_only,
        // The operator's words or none. The component's description was shown
        // above, attributed; recording it would launder it — a stored
        // description is indistinguishable from one the operator typed, and
        // goes on to the agent from there.
        description: opts.description.clone(),
        expires_at,
    };
    store
        .put(&profile, &declared.key, &record)
        .with_context(|| format!("writing credential '{}' for {profile}", declared.key))?;

    println!(
        "stored '{}' for {profile}: {}",
        declared.key,
        field_names.join(", ")
    );
    Ok(())
}

/// Picks the one declared credential this run provisions.
///
/// - Exactly one declared entry and no `--key`: that entry, unambiguously.
/// - Several declared entries: `--key` must name one; the error lists what
///   is declared.
/// - No declared entries at all: the set is open by nature (a bridge that
///   accepts whatever key an operator names), so `--key` is mandatory — there
///   is nothing here to default to — and the error hands back a copy-
///   pasteable command that supplies both `--key` and `--field`.
fn select_credential(
    declared: &[StdCredential],
    key: Option<&str>,
    component: &ComponentRef,
) -> Result<StdCredential> {
    if let Some(key) = key {
        if let Some(found) = declared.iter().find(|c| c.key == key) {
            return Ok(found.clone());
        }
        if declared.is_empty() {
            // Open by nature: nothing declared to match against, so the
            // named key stands on its own with no field list of its own —
            // `field_set` falls back to the `--field` names the user gave.
            return Ok(StdCredential {
                key: key.to_string(),
                description: None,
                fields: Vec::new(),
            });
        }
        let known: Vec<&str> = declared.iter().map(|c| c.key.as_str()).collect();
        anyhow::bail!(
            "{component} declares no credential under key '{key}'; declared keys: {}",
            known.join(", ")
        );
    }
    match declared {
        [] => anyhow::bail!(
            "{component} declares an open credential set with no fixed key; pass \
             --key (and --field, e.g. `act login {component} --key default --field acme:token`)"
        ),
        [one] => Ok(one.clone()),
        many => {
            let known: Vec<&str> = many.iter().map(|c| c.key.as_str()).collect();
            anyhow::bail!(
                "{component} declares {} credentials ({}); pass --key to choose one",
                many.len(),
                known.join(", ")
            )
        }
    }
}

/// What every credential this host writes is stored as.
///
/// A credential is a set of named fields and nothing else (design §3.2): there
/// are no registered shapes left to name, so there is no shape id to record.
/// The credential's own key is the wrong thing to put here — it says *which*
/// credential, and an operator reading `"kind": "default"` beside
/// `"key": "default"` learns nothing. The constant says the true thing: a
/// plain set of fields, whose meaning lives in their names.
///
/// It exists at all because `secret-kind` is a required member of the
/// published `act:credentials@0.1.0` `secret` record, which cannot be removed
/// from a published WIT package. See `ACT-CONSTANTS.md` §8.2 and design §14.0.
pub(crate) const KIND_FIELDS: &str = "std:fields";

/// The field type acquired by the flow rather than by typing (ACT-CONSTANTS §8.1).
const OAUTH2: &str = "std:oauth2";

/// How each of a credential's fields is obtained, and whose words the labels are.
#[derive(Debug)]
struct FieldSet {
    /// `std:string` fields — typed at the terminal.
    prompts: Vec<crate::secret_cmd::Prompt>,
    /// `std:oauth2` fields — obtained by running the flow. Kept as the declared
    /// field rather than a `FieldDef` because the flow needs what only a
    /// declaration carries: the resource identifier and the scopes.
    oauth: Vec<StdCredentialField>,
    /// True when the labels came from the component's own declaration rather
    /// than an operator's definition. The host must then mark them as
    /// foreign (§5.5).
    labels_are_the_components: bool,
}

/// Resolves the field list to prompt for.
///
/// A component that names its own fields (the common case, design §4.3) wins
/// outright — `--field` is not consulted when it did. A declaration with no
/// field list of its own is open by nature (a bridge), and the user names the
/// fields instead.
///
/// Fields are split by type: `std:string` is prompted for, `std:oauth2` is run
/// through the flow. Only a declaration can carry an OAuth field, because only
/// a declaration carries the resource identifier the flow derives everything
/// from — a `--field name=std:oauth2` on the command line names a type with no
/// resource to go with it, and is refused rather than half-run.
///
/// The "a type this host cannot prompt for is refused" rule still lives in one
/// place, `secret_cmd::prompts_for`; what changed is that OAuth fields no
/// longer reach it.
fn field_set(
    declared: &StdCredential,
    field: &[String],
    registry: &FieldRegistry,
) -> Result<FieldSet> {
    // A component's own declaration wins: it is the point of `act login` that
    // the user need not know what the component wants.
    if !declared.fields.is_empty() {
        let (oauth, typed): (Vec<_>, Vec<_>) = declared
            .fields
            .iter()
            .cloned()
            .partition(|f| f.field_type == OAUTH2);
        let defs: Vec<FieldDef> = typed.iter().map(field_def_from_declared).collect();
        return Ok(FieldSet {
            prompts: crate::secret_cmd::prompts_for(&defs)?,
            oauth,
            labels_are_the_components: true,
        });
    }

    // Nothing declared — a bridge, whose credential set is open by nature. The
    // user names the fields, and a name the operator defined brings that
    // definition's label, which the host may present as its own.
    anyhow::ensure!(
        !field.is_empty(),
        "no fields are declared for credential '{}', so there is nothing to \
         prompt for. Name them in your own namespace, e.g. --field acme:username \
         --field acme:password, or --field acme:token.",
        declared.key
    );
    let defs: Vec<FieldDef> = field
        .iter()
        .map(|arg| crate::secret_cmd::field_def_from_arg(arg, registry))
        .collect::<Result<_>>()?;
    // An OAuth field named on the command line has no resource identifier, and
    // the host will not take one from an argument: every address the flow
    // contacts is derived from the resource's own metadata (design §5.5). So
    // this is refused here rather than failing inside the flow.
    if let Some(f) = defs.iter().find(|d| d.field_type == OAUTH2) {
        anyhow::bail!(
            "--field {}={OAUTH2} names a type whose flow needs a resource \
             identifier, and only a component's declaration carries one. Either \
             the component declares this field, or store a token you obtained \
             yourself with `act secret set --field {}={OAUTH2} --fields-stdin`.",
            f.key,
            f.key
        );
    }
    Ok(FieldSet {
        prompts: crate::secret_cmd::prompts_for(&defs)?,
        oauth: Vec::new(),
        labels_are_the_components: false,
    })
}

/// What an acquired credential becomes in the record: the revealable field,
/// the host-only half, and the expiry it contributes.
struct Split {
    field: SecretValue,
    host_only: BTreeMap<String, SecretValue>,
    expires_at: Option<i64>,
}

/// Divide an acquired OAuth credential between what a component may see and
/// what it may not.
///
/// Extracted from the flow so the division is testable without a server: it is
/// the line where "a component gets the means to authenticate, never the means
/// to mint a new credential" either holds or does not. `project()` drops
/// `host_only`, so a refresh token that lands on the wrong side of this
/// function reaches the guest and nothing downstream would notice.
fn split_acquired(key: &str, acquired: crate::oauth::run::Acquired) -> Split {
    let mut value = serde_json::Map::new();
    value.insert(
        "std:access-token".into(),
        serde_json::Value::String(acquired.access_token),
    );
    // Members and encodings: ACT-CONSTANTS §8.3. An expiry is written only when
    // the server gave one — absent reads as "no known expiry", so inventing a
    // value here would be inventing a promise.
    if let Some(exp) = acquired.expires_at {
        value.insert("std:expires-at".into(), serde_json::Value::from(exp));
    }
    if !acquired.scopes.is_empty() {
        value.insert(
            "std:scopes".into(),
            serde_json::Value::from(acquired.scopes),
        );
    }

    let mut host_only = BTreeMap::new();
    if let Some(refresh) = acquired.refresh_token {
        // Namespaced by field key: a credential may hold more than one OAuth
        // field, and their refresh tokens must not collide.
        host_only.insert(
            format!("{key}:std:refresh-token"),
            SecretValue::new(refresh),
        );
    }

    Split {
        field: SecretValue::new(serde_json::Value::Object(value)),
        host_only,
        expires_at: acquired
            .expires_at
            .map(|e| i64::try_from(e).unwrap_or(i64::MAX)),
    }
}

/// Unix seconds now. The flow needs it to turn `expires_in` into `expires_at`,
/// and it is read once here so the whole record shares one clock reading.
fn now_unix() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("the system clock is before the Unix epoch")?
        .as_secs())
}

fn field_def_from_declared(f: &StdCredentialField) -> FieldDef {
    FieldDef {
        key: f.key.clone(),
        label: f.label.clone(),
        field_type: f.field_type.clone(),
        secret: f.secret,
        required: f.required,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(key: &str, fields: Vec<StdCredentialField>) -> StdCredential {
        StdCredential {
            key: key.to_string(),
            description: None,
            fields,
        }
    }

    fn string_field(key: &str) -> StdCredentialField {
        StdCredentialField {
            key: key.to_string(),
            label: key.to_string(),
            field_type: "std:string".to_string(),
            secret: true,
            required: true,
            resource: None,
            scopes: Vec::new(),
        }
    }

    fn oauth_field(key: &str) -> StdCredentialField {
        StdCredentialField {
            key: key.to_string(),
            label: key.to_string(),
            field_type: "std:oauth2".to_string(),
            secret: true,
            required: true,
            resource: None,
            scopes: Vec::new(),
        }
    }

    fn comp() -> ComponentRef {
        "example".parse().unwrap()
    }

    #[test]
    fn a_single_declared_entry_needs_no_key() {
        let declared = vec![cred("default", vec![string_field("acme:password")])];
        let picked = select_credential(&declared, None, &comp()).unwrap();
        assert_eq!(picked.key, "default");
    }

    #[test]
    fn several_declared_entries_require_a_key_naming_them() {
        let declared = vec![
            cred("a", vec![string_field("acme:password")]),
            cred("b", vec![string_field("acme:password")]),
        ];
        let err = select_credential(&declared, None, &comp())
            .unwrap_err()
            .to_string();
        assert!(err.contains("--key"), "{err}");
        assert!(err.contains('a') && err.contains('b'), "{err}");
    }

    #[test]
    fn no_declared_entries_is_open_and_requires_a_key() {
        let err = select_credential(&[], None, &comp())
            .unwrap_err()
            .to_string();
        assert!(err.contains("--key"), "{err}");
        assert!(
            err.contains("--field"),
            "hands back a copy-pasteable command: {err}"
        );
    }

    #[test]
    fn no_declared_entries_with_a_key_synthesizes_an_open_credential() {
        let picked = select_credential(&[], Some("mine"), &comp()).unwrap();
        assert_eq!(picked.key, "mine");
        assert!(picked.fields.is_empty());
    }

    #[test]
    fn a_key_not_among_several_declared_entries_lists_what_is_declared() {
        let declared = vec![
            cred("a", vec![string_field("acme:password")]),
            cred("b", vec![string_field("acme:password")]),
        ];
        let err = select_credential(&declared, Some("c"), &comp())
            .unwrap_err()
            .to_string();
        assert!(err.contains('a') && err.contains('b'), "{err}");
    }

    #[test]
    fn declared_fields_are_used_over_named_ones() {
        let declared = cred("default", vec![string_field("acme:password")]);
        let reg = FieldRegistry::default();
        // The user named a different field; the declaration still wins.
        let fs = field_set(&declared, &["acme:token".to_string()], &reg).unwrap();
        assert_eq!(fs.prompts.len(), 1);
        assert_eq!(fs.prompts[0].field_key, "acme:password");
        assert!(
            fs.labels_are_the_components,
            "a declared field list means the labels are the component's words"
        );
    }

    #[test]
    fn labels_the_user_named_are_not_marked_foreign() {
        let declared = cred("default", vec![]);
        let reg = FieldRegistry::default();
        let fs = field_set(
            &declared,
            &["acme:username".to_string(), "acme:password".to_string()],
            &reg,
        )
        .unwrap();
        assert_eq!(fs.prompts.len(), 2);
        assert!(
            !fs.labels_are_the_components,
            "these words came from the operator's command line, not from the component"
        );
    }

    fn acquired() -> crate::oauth::run::Acquired {
        crate::oauth::run::Acquired {
            access_token: "access-sentinel".into(),
            expires_at: Some(1_700_003_600),
            scopes: vec!["read".into()],
            refresh_token: Some("refresh-sentinel".into()),
        }
    }

    /// The division this whole compartment exists for.
    ///
    /// A refresh token in the revealable half reaches the guest — `project()`
    /// drops `host_only` and nothing else does — and a component holding one
    /// can mint credentials for as long as the grant lives, which is exactly
    /// what the store is meant to prevent.
    #[test]
    fn a_refresh_token_never_lands_in_the_revealable_field() {
        let split = split_acquired("acme:token", acquired());

        let rendered = serde_json::to_string(split.field.expose()).unwrap();
        assert!(
            rendered.contains("access-sentinel"),
            "the access token is what a component is meant to get: {rendered}"
        );
        assert!(
            !rendered.contains("refresh-sentinel"),
            "the refresh token must not be in the field a component reads: {rendered}"
        );

        let refresh = split
            .host_only
            .get("acme:token:std:refresh-token")
            .expect("kept, host-side, for refresh");
        assert_eq!(refresh.expose_str(), Some("refresh-sentinel"));
    }

    /// A record that survives `project()` is the real check: the split is only
    /// worth anything if the compartment it feeds is the one that gets dropped.
    #[test]
    fn the_projection_a_component_receives_carries_no_refresh_token() {
        let split = split_acquired("acme:token", acquired());
        let record = SecretRecord {
            kind: KIND_FIELDS.to_string(),
            fields: BTreeMap::from([("acme:token".to_string(), split.field)]),
            host_only: split.host_only,
            description: None,
            expires_at: split.expires_at,
        };
        let projected = serde_json::to_string(
            &record
                .project()
                .fields
                .iter()
                .map(|(k, v)| (k.clone(), v.expose().clone()))
                .collect::<std::collections::BTreeMap<_, _>>(),
        )
        .unwrap();
        assert!(projected.contains("access-sentinel"));
        assert!(
            !projected.contains("refresh-sentinel"),
            "what crosses to the guest still carries it: {projected}"
        );
    }

    #[test]
    fn the_field_carries_the_members_act_constants_8_3_registers() {
        let split = split_acquired("acme:token", acquired());
        let v = split.field.expose().clone();
        assert_eq!(v["std:access-token"], "access-sentinel");
        // A whole number of seconds, not a float: §8.3 has a consumer read
        // anything else as "never expires".
        assert_eq!(v["std:expires-at"], serde_json::json!(1_700_003_600u64));
        assert!(v["std:expires-at"].is_u64());
        assert_eq!(v["std:scopes"], serde_json::json!(["read"]));
        assert_eq!(split.expires_at, Some(1_700_003_600));
    }

    #[test]
    fn absent_members_are_omitted_rather_than_invented() {
        // A server that issued no expiry and no scopes has said nothing about
        // them. Writing a zero, or an empty list, would be this host inventing
        // a promise on its behalf — §8.3 reads a missing expiry as "no known
        // expiry" and missing scopes as "none recorded", which is the truth.
        let split = split_acquired(
            "acme:token",
            crate::oauth::run::Acquired {
                access_token: "at".into(),
                expires_at: None,
                scopes: vec![],
                refresh_token: None,
            },
        );
        let v = split.field.expose().clone();
        assert_eq!(v.as_object().unwrap().len(), 1, "only the token: {v}");
        assert!(
            split.host_only.is_empty(),
            "a public client gets no refresh"
        );
        assert_eq!(split.expires_at, None);
    }

    #[test]
    fn two_oauth_fields_do_not_collide_in_the_host_only_compartment() {
        // A credential may hold an OAuth token per upstream. Keying the
        // compartment by member name alone would have the second overwrite the
        // first, and the loss would only surface at the first refresh.
        let a = split_acquired("acme:one", acquired());
        let b = split_acquired("acme:two", acquired());
        let mut merged = a.host_only;
        merged.extend(b.host_only);
        assert_eq!(merged.len(), 2, "{merged:?}");
    }

    #[test]
    fn a_declared_oauth2_field_goes_to_the_flow_not_to_a_prompt() {
        // It was refused outright until the flow existed. Now it is routed:
        // prompting for it would store a string where the SDK expects a map,
        // and the flow is the only thing that produces the map.
        let mut f = oauth_field("acme:token");
        f.resource = Some("https://api.acme.com".into());
        let declared = cred("default", vec![f, string_field("acme:tenant")]);
        let fs = field_set(&declared, &[], &FieldRegistry::default()).unwrap();

        assert_eq!(
            fs.prompts
                .iter()
                .map(|p| p.field_key.as_str())
                .collect::<Vec<_>>(),
            ["acme:tenant"],
            "only the string field is typed at a terminal"
        );
        assert_eq!(
            fs.oauth.iter().map(|f| f.key.as_str()).collect::<Vec<_>>(),
            ["acme:token"],
            "and the OAuth field is carried whole, because the flow needs its \
             resource and scopes"
        );
        assert_eq!(
            fs.oauth[0].resource.as_deref(),
            Some("https://api.acme.com")
        );
    }

    #[test]
    fn an_oauth2_field_named_on_the_command_line_is_refused() {
        // There is no resource identifier on a command line, and the host will
        // not take one from an argument: every address the flow contacts is
        // derived from the resource's own metadata (design §5.5). Refusing
        // here beats failing inside the flow with the browser already open.
        let declared = cred("default", vec![]);
        let err = field_set(
            &declared,
            &["acme:token=std:oauth2".to_string()],
            &FieldRegistry::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("resource identifier"), "{err}");
        assert!(
            err.contains("act secret set"),
            "point at the way to store a token obtained by hand: {err}"
        );
    }

    #[test]
    fn a_field_name_with_no_definition_is_prompted_for_as_a_secret_string() {
        let declared = cred("default", vec![]);
        let reg = FieldRegistry::default();
        let fs = field_set(&declared, &["acme:token".to_string()], &reg).unwrap();
        assert_eq!(fs.prompts.len(), 1);
        assert_eq!(fs.prompts[0].field_key, "acme:token");
        assert!(
            fs.prompts[0].hidden,
            "a field with no definition is credential material until someone says otherwise"
        );
    }

    #[test]
    fn an_open_declaration_without_named_fields_says_so() {
        let declared = cred("default", vec![]);
        let reg = FieldRegistry::default();
        let err = field_set(&declared, &[], &reg).unwrap_err().to_string();
        assert!(err.contains("--field"), "{err}");
    }
}
