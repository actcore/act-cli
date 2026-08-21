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
use act_credentials::record::SecretRecord;

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

    /// Name a field to prompt for, repeatable. Only consulted when the
    /// selected credential declares no field list of its own — a component
    /// that names its own fields always wins.
    #[arg(long = "field", value_name = "NAME")]
    pub field: Vec<String>,

    /// Replace a credential already stored under the same key. Without this,
    /// an existing credential is left untouched and reported, not silently
    /// overwritten.
    #[arg(long)]
    pub force: bool,

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
        None => FieldRegistry::builtin(),
    };
    let FieldSet {
        prompts,
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
    // When the labels are the component's own words (design §4.3), say so
    // before the first one and show each field's namespaced key beside it.
    // Otherwise a component called `innocent-weather` prints "GitHub password:"
    // in the host's voice, which is the attack §5.5 names first. The component
    // reference goes above the prompts so the reader can see who is asking.
    if labels_are_the_components {
        eprintln!("Provisioning '{}' for {component}.", declared.key);
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

    // 6. Write, and report what was stored — never a value, and never a field
    // that was skipped.
    let field_names: Vec<&str> = prompts
        .iter()
        .map(|p| p.field_key.as_str())
        .filter(|k| fields.contains_key(*k))
        .collect();
    let record = SecretRecord {
        // Every credential is a set of named fields, whether the component
        // declared them or the user named them, so the stored kind says so.
        kind: KIND_FIELDS.to_string(),
        fields,
        host_only: BTreeMap::new(),
        description: declared.description.clone(),
        expires_at: None,
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

/// The prompts for a credential, and whose words the labels are.
#[derive(Debug)]
struct FieldSet {
    prompts: Vec<crate::secret_cmd::Prompt>,
    /// True when the labels came from the component's own declaration rather
    /// than the registry. The host must then mark them as foreign (§5.5).
    labels_are_the_components: bool,
}

/// Resolves the field list to prompt for.
///
/// A component that names its own fields (the common case, design §4.3) wins
/// outright — `--field` is not consulted when it did. A declaration with no
/// field list of its own is open by nature (a bridge), and the user names the
/// fields instead.
///
/// Either way the "a type this host cannot prompt for is refused" rule lives
/// in exactly one place: `secret_cmd::prompts_for`. The declared-fields path
/// does not re-implement that check against `StdCredentialField`; it converts
/// each declared field to a `FieldDef` and calls `prompts_for`, exactly as the
/// `--field` path calls it against definitions the registry resolved.
fn field_set(
    declared: &StdCredential,
    field: &[String],
    registry: &FieldRegistry,
) -> Result<FieldSet> {
    // A component's own declaration wins: it is the point of `act login` that
    // the user need not know what the component wants.
    if !declared.fields.is_empty() {
        let defs: Vec<FieldDef> = declared
            .fields
            .iter()
            .map(field_def_from_declared)
            .collect();
        return Ok(FieldSet {
            prompts: crate::secret_cmd::prompts_for(&defs)?,
            labels_are_the_components: true,
        });
    }

    // Nothing declared — a bridge, whose credential set is open by nature. The
    // user names the fields, and a registered name brings the registry's own
    // label, which the host may present as its own.
    anyhow::ensure!(
        !field.is_empty(),
        "no fields are declared for credential '{}', so there is nothing to \
         prompt for. Name them: --field std:username --field std:password, or \
         --field acme:token.",
        declared.key
    );
    let defs: Vec<FieldDef> = field.iter().map(|n| registry.resolve(n)).collect();
    Ok(FieldSet {
        prompts: crate::secret_cmd::prompts_for(&defs)?,
        labels_are_the_components: false,
    })
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
        let declared = vec![cred("default", vec![string_field("std:password")])];
        let picked = select_credential(&declared, None, &comp()).unwrap();
        assert_eq!(picked.key, "default");
    }

    #[test]
    fn several_declared_entries_require_a_key_naming_them() {
        let declared = vec![
            cred("a", vec![string_field("std:password")]),
            cred("b", vec![string_field("std:password")]),
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
            cred("a", vec![string_field("std:password")]),
            cred("b", vec![string_field("std:password")]),
        ];
        let err = select_credential(&declared, Some("c"), &comp())
            .unwrap_err()
            .to_string();
        assert!(err.contains('a') && err.contains('b'), "{err}");
    }

    #[test]
    fn declared_fields_are_used_over_named_ones() {
        let declared = cred("default", vec![string_field("std:password")]);
        let reg = FieldRegistry::builtin();
        // The user named a different field; the declaration still wins.
        let fs = field_set(&declared, &["acme:token".to_string()], &reg).unwrap();
        assert_eq!(fs.prompts.len(), 1);
        assert_eq!(fs.prompts[0].field_key, "std:password");
        assert!(
            fs.labels_are_the_components,
            "a declared field list means the labels are the component's words"
        );
    }

    #[test]
    fn registry_labels_are_not_marked_foreign() {
        let declared = cred("default", vec![]);
        let reg = FieldRegistry::builtin();
        let fs = field_set(
            &declared,
            &["std:username".to_string(), "std:password".to_string()],
            &reg,
        )
        .unwrap();
        assert_eq!(fs.prompts.len(), 2);
        assert!(
            !fs.labels_are_the_components,
            "registry labels are the host's own and must not be attributed elsewhere"
        );
    }

    #[test]
    fn a_declared_oauth2_field_is_refused_not_prompted_for() {
        let declared = cred("default", vec![oauth_field("std:token")]);
        let reg = FieldRegistry::builtin();
        let err = field_set(&declared, &[], &reg).unwrap_err().to_string();
        assert!(err.contains("std:oauth2"), "{err}");
    }

    #[test]
    fn an_unregistered_field_name_is_prompted_for_as_a_secret_string() {
        let declared = cred("default", vec![]);
        let reg = FieldRegistry::builtin();
        let fs = field_set(&declared, &["acme:token".to_string()], &reg).unwrap();
        assert_eq!(fs.prompts.len(), 1);
        assert_eq!(fs.prompts[0].field_key, "acme:token");
        assert!(
            fs.prompts[0].hidden,
            "an unknown field is credential material until someone says otherwise"
        );
    }

    #[test]
    fn an_open_declaration_without_named_fields_says_so() {
        let declared = cred("default", vec![]);
        let reg = FieldRegistry::builtin();
        let err = field_set(&declared, &[], &reg).unwrap_err().to_string();
        assert!(err.contains("--field"), "{err}");
    }
}
