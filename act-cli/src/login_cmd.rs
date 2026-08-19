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
//!    "not std:string is refused" rule — it routes every field list through
//!    that one check instead, declared or `--kind`.)
//! 4. Does a credential already sit under that key? Never overwritten
//!    without `--force`.
//! 5. Prompt, hidden for secret fields.
//! 6. Write, and report what was stored — never a value.

use std::collections::BTreeMap;

use anyhow::{Context, Result};

use act_credentials::backend;
use act_credentials::kind::{FieldDef, KindDef, KindRegistry};
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

    /// Credential kind (field shape) to prompt for. Only consulted when the
    /// selected credential declares no field list of its own — a component
    /// that names its own fields always wins.
    #[arg(long)]
    pub kind: Option<String>,

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
    // registry entry named by --kind. Refuses a field type this release
    // cannot acquire (std:oauth2 needs the browser flow, not a prompt) —
    // one implementation of that rule, inside `field_set`.
    let registry = match crate::config::kinds_dir() {
        Some(dir) => KindRegistry::load(&dir).with_context(|| {
            format!("reading credential kind definitions from {}", dir.display())
        })?,
        None => KindRegistry::builtin(),
    };
    let FieldSet {
        kind,
        prompts,
        labels_are_the_components,
    } = field_set(&declared, opts.kind.as_deref(), &registry)?;

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

    // 5. Prompt in order, hidden for secret fields.
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
        let shown = if labels_are_the_components {
            format!("  {} [{}]", p.label, p.field_key)
        } else {
            p.label.clone()
        };
        let value = if p.hidden {
            crate::secret_cmd::read_hidden_line(&shown)?
        } else {
            crate::secret_cmd::read_visible_line(&shown)?
        };
        // Enter on an empty prompt is the same failure as EOF one layer up: a
        // credential that stores cleanly and holds nothing, so the operator
        // believes they provisioned something and the component finds nothing.
        // Someone whose credential really is the empty string has
        // `--fields-stdin`.
        anyhow::ensure!(
            !value.is_empty(),
            "'{}' cannot be empty — nothing was stored",
            p.field_key
        );
        fields.insert(p.field_key.clone(), SecretValue::new(value));
    }

    // 6. Write, and report what was stored — never a value.
    let field_names: Vec<&str> = prompts.iter().map(|p| p.field_key.as_str()).collect();
    let record = SecretRecord {
        kind,
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
///   pasteable command that supplies both `--key` and `--kind`.
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
            // `field_set` falls back to `--kind` for its shape.
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
             --key (and --kind, e.g. `act login {component} --key default --kind std:string`)"
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

/// Resolves the field list to prompt for, and the string recorded as the
/// credential's kind.
///
/// A component that names its own fields (the common case, design §4.3)
/// wins outright — `--kind` is not consulted when it did. A declaration with
/// no field list of its own is open by nature, and an operator must say
/// which registry kind shapes it.
///
/// Either way the "not std:string is refused" rule lives in exactly one
/// place: `secret_cmd::prompts_for`. The declared-fields path does not
/// re-implement that check against `StdCredentialField` — it wraps the
/// declaration in a one-off `KindRegistry` (`KindRegistry::single`) keyed by
/// the credential's own key, and calls `prompts_for` against it, exactly as
/// the `--kind` path calls it against the operator-chosen registry entry.
/// What a credential built from a component's own field list is stored as.
///
/// A declaration names a key and fields, never a kind (design §4.3), so there is
/// no kind id to record — and the key is the wrong thing to put here: it says
/// *which* credential, where `kind` says *what shape*, and an operator reading
/// `"kind": "default"` beside `"key": "default"` learns nothing. A constant says
/// the true thing instead: a plain set of fields, whose meaning lives in their
/// names. Registered in `ACT-CONSTANTS.md` §8.2.
pub(crate) const KIND_FIELDS: &str = "std:fields";

/// The prompts for a credential, and whose words the labels are.
#[derive(Debug)]
struct FieldSet {
    kind: String,
    prompts: Vec<crate::secret_cmd::Prompt>,
    /// True when the labels came from the component's own declaration rather
    /// than the registry. The host must then mark them as foreign (§5.5).
    labels_are_the_components: bool,
}

fn field_set(
    declared: &StdCredential,
    kind: Option<&str>,
    registry: &KindRegistry,
) -> Result<FieldSet> {
    if !declared.fields.is_empty() {
        let fields: Vec<FieldDef> = declared
            .fields
            .iter()
            .map(field_def_from_declared)
            .collect();
        let ad_hoc = KindRegistry::single(KindDef {
            id: declared.key.clone(),
            fields,
            description: declared.description.clone(),
        });
        let prompts = crate::secret_cmd::prompts_for(&ad_hoc, &declared.key)?;
        return Ok(FieldSet {
            kind: KIND_FIELDS.to_string(),
            prompts,
            labels_are_the_components: true,
        });
    }

    let kind = kind.ok_or_else(|| {
        anyhow::anyhow!(
            "no field list declared for key '{}'; pass --kind to choose the credential's \
             shape (e.g. --kind std:string)",
            declared.key
        )
    })?;
    let prompts = crate::secret_cmd::prompts_for(registry, kind)?;
    Ok(FieldSet {
        kind: kind.to_string(),
        prompts,
        // A registered kind's labels are the registry's, so the host may
        // present them as its own.
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
        let declared = vec![cred("default", vec![string_field("std:value")])];
        let picked = select_credential(&declared, None, &comp()).unwrap();
        assert_eq!(picked.key, "default");
    }

    #[test]
    fn several_declared_entries_require_a_key_naming_them() {
        let declared = vec![
            cred("a", vec![string_field("std:value")]),
            cred("b", vec![string_field("std:value")]),
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
            err.contains("--kind"),
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
            cred("a", vec![string_field("std:value")]),
            cred("b", vec![string_field("std:value")]),
        ];
        let err = select_credential(&declared, Some("c"), &comp())
            .unwrap_err()
            .to_string();
        assert!(err.contains('a') && err.contains('b'), "{err}");
    }

    #[test]
    fn declared_fields_are_used_over_kind() {
        let declared = cred("default", vec![string_field("std:value")]);
        let reg = KindRegistry::builtin();
        let fs = field_set(&declared, None, &reg).unwrap();
        assert_eq!(fs.prompts.len(), 1);
        assert_eq!(fs.prompts[0].field_key, "std:value");
        // Stored as a plain field set, not under the credential's key: `kind`
        // says what shape, `key` says which credential, and putting the key in
        // both leaves an operator reading `"kind": "default"` none the wiser.
        assert_eq!(fs.kind, KIND_FIELDS);
        assert!(
            fs.labels_are_the_components,
            "a declared field list means the labels are the component's words"
        );
    }

    #[test]
    fn a_registered_kinds_labels_are_not_marked_foreign() {
        let declared = cred("default", vec![]);
        let reg = KindRegistry::builtin();
        let fs = field_set(&declared, Some("std:string"), &reg).unwrap();
        assert!(
            !fs.labels_are_the_components,
            "registry labels are the host's own and must not be attributed elsewhere"
        );
        assert_eq!(fs.kind, "std:string");
    }

    #[test]
    fn a_declared_oauth2_field_is_refused_not_prompted_for() {
        let declared = cred("default", vec![oauth_field("std:token")]);
        let reg = KindRegistry::builtin();
        let err = field_set(&declared, None, &reg).unwrap_err().to_string();
        assert!(err.contains("std:oauth2"), "{err}");
    }

    #[test]
    fn an_open_declaration_falls_back_to_kind() {
        let declared = cred("default", vec![]);
        let reg = KindRegistry::builtin();
        let fs = field_set(&declared, Some("std:basic"), &reg).unwrap();
        let (kind, prompts) = (fs.kind, fs.prompts);
        assert_eq!(kind, "std:basic");
        assert_eq!(prompts.len(), 2);
    }

    #[test]
    fn an_open_declaration_without_kind_says_so() {
        let declared = cred("default", vec![]);
        let reg = KindRegistry::builtin();
        let err = field_set(&declared, None, &reg).unwrap_err().to_string();
        assert!(err.contains("--kind"), "{err}");
    }
}
