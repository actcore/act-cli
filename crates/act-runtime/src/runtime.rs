//! The front door: load a component and hold it running.
//!
//! Everything below this module is reachable on its own — a host that needs to
//! interpose on the linker or own the store still can. What this adds is the
//! order the pieces go in, which is not obvious and not optional: mounts are
//! resolved before instantiation because preopens are, the audit context is
//! built before instantiation because the instantiation header needs it, and
//! the credential namespace is derived from the component reference rather
//! than taken from the caller because that derivation is what keeps one
//! component out of another's secrets.
//!
//! Re-deriving that order in every host is how two hosts come to disagree
//! about what a component is allowed to do.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use wasmtime::Engine;

use crate::audit::Transport;
use crate::consent::CurrentConsentSink;
use crate::info::ComponentInfo;
use crate::resolve::ComponentRef;
use crate::{ComponentHandle, Metadata};

/// Owns the wasmtime [`Engine`], which is reusable across components: one
/// `ComponentRuntime` per host process, many [`RunningComponent`]s.
pub struct ComponentRuntime {
    engine: Engine,
}

/// What the host decided before the component runs.
///
/// Headless by construction — no command-line types, no configuration file
/// format, no notion of where any of this came from. A CLI fills it from flags
/// and TOML; a server from its database; a test from literals.
#[derive(Default)]
pub struct RuntimeConfig {
    /// Capability grants, intersected at load time with what the component
    /// declares. An undeclared class is denied however this reads.
    pub grants: act_policy::grant::GrantPolicy,
    /// Metadata sent with every call this component receives.
    pub metadata: Metadata,
    /// Cap on guest linear memory.
    pub max_memory: Option<usize>,
    pub audit: AuditOptions,
    /// `None` runs the component with no credential store at all. A component
    /// that declared `act:credentials` still reports as declared-but-not-granted.
    pub credentials: Option<CredentialsSource>,
}

#[derive(Default)]
pub struct AuditOptions {
    /// Which transport dispatched the call, as recorded in the audit envelope.
    pub transport: Transport,
    /// Record full tool arguments instead of a digest. Session args are never
    /// recorded either way. Can expose credentials.
    pub record_args: bool,
}

/// Which credential backend serves this run.
///
/// The profile namespace is deliberately not a field here: it is derived from
/// the [`ComponentRef`] through [`crate::resolve::profile_key`], so a caller
/// cannot pass a spelling that disagrees with the one the credential was
/// stored under.
pub struct CredentialsSource {
    /// Backend name, as `act secret --credentials-backend` spells it. Never
    /// inferred: there is no mode that picks one for you.
    pub backend: Option<String>,
    /// How a credential too close to expiry is renewed before it is served.
    /// `None` means no renewal: a near-expiry credential is served as it is,
    /// which is what an embedder with no OAuth upstream wants.
    pub refresher: Option<Arc<dyn crate::credentials::CredentialRefresher>>,
}

/// How an `ask`-mode capability gate reaches a human, and where its answers
/// are remembered for the rest of the run.
pub struct ConsentConfig {
    pub prompter: Arc<dyn act_policy::consent::ConsentPrompter>,
    /// Must agree with `prompter`'s kind — `false` for a denying one. It feeds
    /// the instantiation audit header's warning about capabilities declared
    /// `ask` that no one can actually be asked about.
    pub has_prompt_channel: bool,
    /// Where the actor routes a question raised mid-call. Only transports with
    /// a back-channel install one; everything else prompts locally or denies.
    pub sink: Arc<CurrentConsentSink>,
    pub cache: Arc<act_policy::consent::DecisionCache>,
}

impl ConsentConfig {
    /// Fail-safe: every `ask` capability denies, and nothing is ever asked.
    /// What a headless host wants until it has a channel of its own.
    pub fn deny() -> Self {
        Self {
            prompter: Arc::new(act_policy::consent::DenyPrompter),
            has_prompt_channel: false,
            sink: Arc::new(CurrentConsentSink::new()),
            cache: Arc::new(act_policy::consent::DecisionCache::new()),
        }
    }
}

/// A loaded, instantiated component with its actor running.
pub struct RunningComponent {
    info: ComponentInfo,
    handle: ComponentHandle,
    has_sessions: bool,
    path: PathBuf,
}

impl ComponentRuntime {
    pub fn new() -> Result<Self> {
        Ok(Self {
            engine: crate::create_engine()?,
        })
    }

    /// The engine backing this runtime, for a host that builds its own linker.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Resolve, load and instantiate a component, and start its actor.
    ///
    /// Remote references are pulled through the shared component store on
    /// first use; local paths run in place.
    pub async fn load(
        &self,
        component: &ComponentRef,
        config: &RuntimeConfig,
        consent: ConsentConfig,
    ) -> Result<RunningComponent> {
        let path = crate::resolve::resolve(component, false).await?;
        let wasm_bytes = std::fs::read(&path).context("reading component file")?;
        let info = crate::read_component_info(&wasm_bytes)?;

        // Mounts before instantiation: preopens are decided here, and the
        // provider registry computes the final ceiling from them.
        let fs_mode = config
            .grants
            .resolve(act_types::constants::CAP_FILESYSTEM)
            .mode;
        let mounts = crate::fs_policy::resolve_mounts(&info.std.capabilities, fs_mode);
        crate::fs_policy::create_mount_dirs(&mounts).context("creating mount directories")?;
        let preopens = crate::fs_policy::derive_preopens(&mounts);

        tracing::debug!(
            name = %info.std.name,
            version = %info.std.version,
            path = %path.display(),
            "Loading component"
        );

        let (wasm, digest) = crate::load_component(&self.engine, &path)?;
        let linker = crate::create_linker(&self.engine)?;

        // Built before instantiation so the instantiation audit header can
        // carry it without reconstructing the reference and digest again.
        let audit = crate::AuditContext {
            component_ref: component.to_string(),
            digest,
            transport: config.audit.transport,
            has_prompt_channel: consent.has_prompt_channel,
            record_args: config.audit.record_args,
        };

        let credentials = match &config.credentials {
            Some(source) => credential_host(
                component,
                source.backend.as_deref(),
                source.refresher.clone(),
            )?,
            None => None,
        };

        let (instance, session_provider, store) = crate::instantiate_component(
            &self.engine,
            &wasm,
            &linker,
            &preopens,
            &config.grants,
            &info,
            config.max_memory,
            consent.prompter,
            consent.cache,
            credentials,
            &audit,
        )
        .await?;

        let has_sessions = session_provider.is_some();
        let handle =
            crate::spawn_component_actor(instance, session_provider, store, consent.sink, audit);

        tracing::debug!(name = %info.std.name, version = %info.std.version, "Component ready");

        Ok(RunningComponent {
            info,
            handle,
            has_sessions,
            path,
        })
    }
}

impl RunningComponent {
    pub fn info(&self) -> &ComponentInfo {
        &self.info
    }

    /// Whether the component exports `act:sessions/session-provider`.
    pub fn has_sessions(&self) -> bool {
        self.has_sessions
    }

    /// The local file the component was loaded from — the store's copy for a
    /// remote reference.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// The actor handle, for a host that wants to hold it past this struct
    /// (an MCP bridge keeps one per connection).
    pub fn handle(&self) -> &ComponentHandle {
        &self.handle
    }
}

/// Build the credential host serving one component run, or `None` when no
/// store was named and this platform has no data directory to put one in.
///
/// Takes the [`ComponentRef`] and derives the profile namespace itself. That
/// is the point: the namespace is what makes one component unable to read
/// another's credentials, and it must be `resolve::profile_key(component)`
/// rather than the operator's literal spelling, or a credential stored against
/// `./x.wasm` is invisible to a run of `x.wasm`. Taking a `&str` here left
/// that rule to prose and to whoever wrote the call site.
///
/// The literal spelling is still recorded, separately, as
/// `AuditContext::component_ref`: an audit trail should say what was typed.
fn credential_host(
    component: &ComponentRef,
    backend: Option<&str>,
    refresher: Option<Arc<dyn crate::credentials::CredentialRefresher>>,
) -> Result<Option<Arc<crate::credentials::CredentialHost>>> {
    let component_ref = crate::resolve::profile_key(component);
    let Some(choice) = crate::credentials::resolve_backend(backend)? else {
        return Ok(None);
    };
    let root = crate::credentials::backend_root(&choice).to_path_buf();
    let store = act_credentials::backend::select(choice, &root)
        .with_context(|| format!("opening credential store at {}", root.display()))?;
    let host = crate::credentials::CredentialHost::new(Arc::from(store), component_ref);
    Ok(Some(Arc::new(match refresher {
        Some(r) => host.with_refresher(r),
        None => host,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reader half of the profile-namespace fix. `act secret set` keys
    /// the write on `resolve::profile_key`; if the runtime keyed the read on
    /// the operator's literal spelling instead, `act secret set ./x.wasm`
    /// followed by `act run x.wasm` would miss with a bare not-found. The
    /// writer half is covered end-to-end in `tests/secret_cli.rs`.
    ///
    /// It passes `credential_host` exactly what [`ComponentRuntime::load`]
    /// passes it — the `ComponentRef` itself — so the normalisation under test
    /// is the one the runtime performs, not one the test performed for it.
    #[test]
    fn the_runtime_reads_the_profile_the_writer_wrote() {
        let dir = tempfile::tempdir().unwrap();
        let backend = format!("file:{}", dir.path().display());
        let cwd = std::env::current_dir().unwrap();

        for spelling in ["./x.wasm", "x.wasm"] {
            let component: ComponentRef = spelling.parse().unwrap();
            let host = credential_host(&component, Some(&backend), None)
                .unwrap()
                .expect("an explicitly named backend always yields a host");
            assert_eq!(
                host.component(),
                cwd.join("x.wasm").display().to_string(),
                "{spelling} must reach the same profile as every other spelling"
            );
        }
    }
}
