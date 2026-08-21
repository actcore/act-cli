//! The wasmtime store: host state, the WASI views, and the capability
//! ceilings resolved for one component run.

use anyhow::Result;
use std::sync::Arc;
use wasmtime::component::ResourceTable;
use wasmtime::{Engine, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};
use wasmtime_wasi_http::WasiHttpCtx;
use wasmtime_wasi_http::WasiHttpCtxView;

use crate::info::ComponentInfo;
use crate::{credentials, fs_policy, http_client, http_policy};

/// Host state passed into the wasmtime store.
pub struct HostState {
    pub(crate) wasi: WasiCtx,
    pub(crate) table: ResourceTable,
    pub(crate) http: WasiHttpCtx,
    pub(crate) http_hooks: http_policy::PolicyHttpHooks,
    #[allow(dead_code)] // retained for Task 10 DNS resolver hook access
    pub(crate) http_client: Arc<http_client::ActHttpClient>,
    pub(crate) fs_ceiling: Arc<dyn act_policy::provider::CompiledCeiling>,
    pub(crate) fs_effective_mode: act_policy::grant::PolicyMode,
    pub(crate) fd_paths: fs_policy::FdPathMap,
    /// Interactive-consent prompter + per-session decision cache, shared by
    /// every `ask`-mode decision point (fs / http / sockets).
    pub(crate) consent_prompter: Arc<dyn act_policy::consent::ConsentPrompter>,
    pub(crate) consent_cache: Arc<act_policy::consent::DecisionCache>,
    /// The `act:credentials/store` implementation this run serves, or `None`
    /// when no credential store is configured. Held behind an `Arc` because
    /// the component actor reaches the same object to mark sessions live and
    /// dead — see `spawn_component_actor`.
    pub(crate) credentials: Option<Arc<credentials::CredentialHost>>,
    /// The compiled `act:credentials` ceiling, consulted before any credential
    /// is issued. Present even when `credentials` is `None`: the audit header
    /// must report the class either way.
    pub(crate) credentials_ceiling: Arc<dyn act_policy::provider::CompiledCeiling>,
    /// Caps the component's wasm linear memory growth (via `store.limiter`).
    /// Default `StoreLimits` is unlimited.
    pub(crate) limits: StoreLimits,
}
impl HostState {
    /// Build a policy-aware filesystem view.
    pub(crate) fn policy_fs_view(&mut self) -> fs_policy::PolicyFilesystemCtxView<'_> {
        fs_policy::PolicyFilesystemCtxView {
            ctx: self.wasi.filesystem(),
            table: &mut self.table,
            ceiling: &self.fs_ceiling,
            fd_paths: &mut self.fd_paths,
            mode: self.fs_effective_mode,
            prompter: self.consent_prompter.clone(),
            cache: self.consent_cache.clone(),
        }
    }
}
impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}
impl wasmtime_wasi_http::WasiHttpView for HostState {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView {
            ctx: &mut self.http,
            table: &mut self.table,
            hooks: &mut self.http_hooks,
        }
    }
}
/// Whether this check is the local side of an outbound socket rather than a
/// destination the component asked to reach.
///
/// Since wasmtime 48 an outbound `connect` on an unbound socket — and a
/// `listen` on one — is preceded by a bind check carrying the *wildcard*
/// address, because the OS is about to bind there implicitly. That is
/// documented on `SocketAddrUse::TcpBind`: "the address that is passed to the
/// check is the address provided to `bind` for explicit binds, or the wildcard
/// address for implicit binds".
///
/// `0.0.0.0:0` is not a destination and no allowlist would ever name one, so
/// putting it through the ceiling denies every outbound connection the
/// allowlist was written to permit — which is what the wasmtime 48 upgrade
/// first did.
///
/// Waving it through grants nothing by itself. Reaching a peer still has to
/// pass `TcpConnect` on the real address; accepting one still has to pass
/// `TcpListen`, and then `TcpAccept` per client. An explicit
/// `bind("0.0.0.0:0")` is indistinguishable from the implicit one at this
/// point and takes the same path, to the same effect and for the same reason:
/// binding confers no reach on its own.
pub(crate) fn is_local_implicit_bind(
    addr: std::net::SocketAddr,
    reason: wasmtime_wasi::sockets::SocketAddrUse,
) -> bool {
    use wasmtime_wasi::sockets::SocketAddrUse;
    matches!(reason, SocketAddrUse::TcpBind | SocketAddrUse::UdpBind)
        && addr.ip().is_unspecified()
        && addr.port() == 0
}

/// Declared constraints for one capability class, as `CapabilityProvider::resolve`
/// expects them.
///
/// For `wasi:filesystem`/`wasi:http`/`wasi:sockets`, an empty result legitimately
/// means "declared with an unbounded/absent ceiling": their providers parse every
/// constraint value as a typed rule, so this stays exactly the manifest's
/// constraint list, untouched — the bulk of this function's callers must never
/// see it perturbed.
///
/// `act:credentials` is different: it is a *binary* capability class (see the
/// `declared`-slice contract documented on `act_policy::providers::credentials`)
/// whose bare-table declaration form (`[std.capabilities."act:credentials"]`)
/// always parses to an empty constraint list. Left alone that collapses
/// "declared, no constraints" into "never declared", and
/// `CredentialsProvider::resolve` denies every access permanently while the
/// audit trail reports the component as never having declared the class. So for
/// this one id — and only this one, for now — presence in the manifest decides,
/// not the constraint list, and a one-element sentinel is synthesized when
/// present, matching the contract the provider's module docs require.
pub(crate) fn declared_constraints(info: &ComponentInfo, cap_id: &str) -> Vec<serde_json::Value> {
    if cap_id == act_policy::providers::credentials::CAP_CREDENTIALS {
        return if info.std.capabilities.has(cap_id) {
            vec![serde_json::json!({})]
        } else {
            Vec::new()
        };
    }
    info.std
        .capabilities
        .get(cap_id)
        .map(|req| req.constraints.clone())
        .unwrap_or_default()
}
/// The capability classes over which credentials can leave the machine.
///
/// Deliberately a constant read by `warn_if_credentials_exfil_risk` itself
/// rather than a list its caller assembles: a caller that wired up only
/// `wasi:http` would reopen the identical channel under the id nobody checked,
/// and nothing about that call would look wrong at the call site.
const EXFIL_NETWORK_CAPS: [&str; 2] = [
    act_types::constants::CAP_HTTP,
    act_types::constants::CAP_SOCKETS,
];
/// Warn when a component that declares `act:credentials` also holds an `open`
/// grant on a network class it declared a reachable ceiling for.
///
/// Reading credentials and reaching the network are each unremarkable alone;
/// together they are an exfiltration channel
/// (docs/specs/2026-08-03-act-credentials-design.md §4.1). Both network classes
/// count — raw TCP over `wasi:sockets` exfiltrates exactly as well as HTTP does,
/// so warning about `wasi:http` alone would leave the same channel open under a
/// different id.
///
/// ## Why the grant alone is not the trigger
///
/// The reach is the *ceiling* — grant ∩ declaration — not the grant. Per
/// `act_policy::effective`, a class the component never declared is forced to
/// `Deny` (`effective.rs:100`), a class declared as a bare table with no
/// constraints is likewise forced to `Deny` (`effective.rs:118`), and an `open`
/// grant does not mean "everything": it collapses to `Allowlist` bounded by the
/// declaration (`effective.rs:144`). So `--allow wasi:http` on a component that
/// declared no hosts buys that component nothing at all, and warning about it
/// would be a false positive — the fastest way to teach an operator to ignore
/// every warning this host emits.
///
/// The condition is therefore `open` grant **and** a non-empty declaration:
/// exactly the case where the operator has removed their own bound and the
/// artifact's self-declaration is the only one left standing.
///
/// ## Why not `act::audit`
///
/// Emitted on this module's default target, like every other host advisory
/// (`http_policy`, `fs_policy`). The audit target is not a general-purpose log:
/// `AuditLayer::on_event` reconstructs a typed `CapDecisionRecord` and drops
/// anything without both a `cap_id` and an `act.decision` field, while
/// `crate::fmt_filter` excludes `act::audit` from the `fmt` layer precisely so
/// audit events are rendered once, by `render.rs`. A prose warning addressed to
/// `act::audit` therefore reaches neither layer and is silently swallowed. This
/// is advice about a grant the operator chose, not a decision about a resource
/// access, so the ordinary log is where it belongs.
pub(crate) fn warn_if_credentials_exfil_risk(
    info: &ComponentInfo,
    grant_policy: &act_policy::grant::GrantPolicy,
) {
    if !info
        .std
        .capabilities
        .has(act_policy::providers::credentials::CAP_CREDENTIALS)
    {
        return;
    }

    // Note: a declaration whose constraints are present but malformed is
    // counted as reachable here, while `effective_*` parses it, logs
    // "ignoring malformed ... constraint" and denies. Erring towards the
    // warning on a manifest that is already being complained about is the
    // safe side of that seam, and keeping this check on the raw constraint
    // list avoids duplicating each class's constraint schema here.
    let unbounded: Vec<&str> = EXFIL_NETWORK_CAPS
        .iter()
        .copied()
        .filter(|cap_id| {
            grant_policy.resolve(cap_id).mode == act_policy::grant::PolicyMode::Open
                && !declared_constraints(info, cap_id).is_empty()
        })
        .collect();
    if unbounded.is_empty() {
        return;
    }

    let classes = unbounded.join(" and ");
    tracing::warn!(
        component = %info.std.name,
        open_grants = %classes,
        "component declares act:credentials and is granted {classes} in open \
         mode: an open grant adds no bound of your own, leaving the component's \
         own declaration as the only limit on where it can reach — and it can \
         send your credentials anywhere that declaration permits. Grant an \
         allowlist you chose instead."
    );
}
/// Create a new store with WASI context, preopening directories from resolved mounts.
///
/// `grant_policy` is intersected with the component's declared capabilities via
/// `ProviderRegistry::with_builtins()`. Undeclared capability classes are always
/// denied regardless of the grant.
#[allow(clippy::too_many_arguments)]
pub async fn create_store(
    engine: &Engine,
    preopens: &[fs_policy::Preopen],
    grant_policy: &act_policy::grant::GrantPolicy,
    info: &ComponentInfo,
    max_memory: Option<usize>,
    prompter: Arc<dyn act_policy::consent::ConsentPrompter>,
    cache: Arc<act_policy::consent::DecisionCache>,
    credentials: Option<Arc<credentials::CredentialHost>>,
) -> Result<(
    Store<HostState>,
    Vec<(String, Arc<dyn act_policy::provider::CompiledCeiling>)>,
)> {
    use crate::audit::{CapDecisionRecord, Decision4, emit_cap_decision};
    use act_policy::grant::PolicyMode;
    use act_policy::provider::{CompiledCeiling, ProviderRegistry, ResourceOp};

    let registry = ProviderRegistry::with_builtins();

    // Helper: extract declared constraints for a capability id.
    let get_declared =
        |cap_id: &str| -> Vec<serde_json::Value> { declared_constraints(info, cap_id) };

    let fs_grant = grant_policy.resolve(act_types::constants::CAP_FILESYSTEM);
    let http_grant = grant_policy.resolve(act_types::constants::CAP_HTTP);
    let sockets_grant = grant_policy.resolve(act_types::constants::CAP_SOCKETS);

    // act:credentials plus an unbounded grant on either network class is an
    // exfiltration channel — see `warn_if_credentials_exfil_risk` above. It
    // resolves the classes it cares about itself, from the whole policy.
    warn_if_credentials_exfil_risk(info, grant_policy);

    let fs_ceiling: Arc<dyn CompiledCeiling> = Arc::from(
        registry
            .lookup(act_types::constants::CAP_FILESYSTEM)
            .resolve(
                act_types::constants::CAP_FILESYSTEM,
                &get_declared(act_types::constants::CAP_FILESYSTEM),
                &fs_grant,
            )
            .await
            .map_err(|e| anyhow::anyhow!("fs policy: {e}"))?,
    );
    let fs_effective_mode = fs_ceiling.effective_mode();

    let http_ceiling: Arc<dyn CompiledCeiling> = Arc::from(
        registry
            .lookup(act_types::constants::CAP_HTTP)
            .resolve(
                act_types::constants::CAP_HTTP,
                &get_declared(act_types::constants::CAP_HTTP),
                &http_grant,
            )
            .await
            .map_err(|e| anyhow::anyhow!("http policy: {e}"))?,
    );

    let sockets_ceiling: Arc<dyn CompiledCeiling> = Arc::from(
        registry
            .lookup(act_types::constants::CAP_SOCKETS)
            .resolve(
                act_types::constants::CAP_SOCKETS,
                &get_declared(act_types::constants::CAP_SOCKETS),
                &sockets_grant,
            )
            .await
            .map_err(|e| anyhow::anyhow!("sockets policy: {e}"))?,
    );
    let sockets_effective_mode = sockets_ceiling.effective_mode();

    // `act:credentials` is a semantic class with no resource constraints, so
    // `declared_constraints` hands the provider a synthesized sentinel rather
    // than a rule list — see its doc comment. It is resolved even when this
    // run has no credential store: the ceiling is what the audit header
    // reports, and a component that declared the class but got nothing must
    // still show up as `declared but not granted`.
    let credentials_grant =
        grant_policy.resolve(act_policy::providers::credentials::CAP_CREDENTIALS);
    let credentials_ceiling: Arc<dyn CompiledCeiling> = Arc::from(
        registry
            .lookup(act_policy::providers::credentials::CAP_CREDENTIALS)
            .resolve(
                act_policy::providers::credentials::CAP_CREDENTIALS,
                &get_declared(act_policy::providers::credentials::CAP_CREDENTIALS),
                &credentials_grant,
            )
            .await
            .map_err(|e| anyhow::anyhow!("credentials policy: {e}"))?,
    );

    // Captured for the instantiation audit header (Task 10), before any of
    // them get moved into `HostState` / the hooks / the sockets closure
    // below — an `Arc` clone here is cheap and keeps this function's
    // enforcement wiring below untouched. Every class the host resolves
    // belongs here: the header is assembled from this vec alone, so a class
    // left out of it is one no operator ever sees a mode for.
    let ceilings: Vec<(String, Arc<dyn CompiledCeiling>)> = vec![
        (
            act_types::constants::CAP_FILESYSTEM.to_string(),
            fs_ceiling.clone(),
        ),
        (
            act_types::constants::CAP_HTTP.to_string(),
            http_ceiling.clone(),
        ),
        (
            act_types::constants::CAP_SOCKETS.to_string(),
            sockets_ceiling.clone(),
        ),
        (
            act_policy::providers::credentials::CAP_CREDENTIALS.to_string(),
            credentials_ceiling.clone(),
        ),
    ];

    let mut builder = WasiCtxBuilder::new();
    let mut preopen_pairs = Vec::with_capacity(preopens.len());
    for mount in preopens {
        builder
            .preopened_dir(&mount.host, &mount.guest, wasmtime_wasi::FsPerms::ReadWrite)
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to preopen host dir '{}' as guest '{}': {}",
                    mount.host.display(),
                    mount.guest,
                    e
                )
            })?;
        preopen_pairs.push((mount.guest.clone(), mount.host.clone()));
    }

    // Install sockets enforcement via ceiling.classify.
    {
        let sockets_ceiling_clone = sockets_ceiling.clone();
        let prompter_clone = prompter.clone();
        let cache_clone = cache.clone();
        builder
            .socket_addr_check(move |addr, reason| {
                let sockets_ceiling = sockets_ceiling_clone.clone();
                let prompter = prompter_clone.clone();
                let cache = cache_clone.clone();
                Box::pin(async move {
                    use wasmtime_wasi::sockets::SocketAddrUse;

                    if is_local_implicit_bind(addr, reason) {
                        return true;
                    }

                    // Exhaustive on purpose: a `_` arm silently filed
                    // wasmtime 48's new `TcpListen` and `TcpAccept` under
                    // "udp", in the audit trail and in the attrs a rule
                    // matches on. The next added variant should fail to
                    // compile rather than repeat that.
                    let proto = match reason {
                        SocketAddrUse::TcpBind
                        | SocketAddrUse::TcpListen
                        | SocketAddrUse::TcpAccept
                        | SocketAddrUse::TcpConnect => "tcp",
                        SocketAddrUse::UdpBind
                        | SocketAddrUse::UdpSend
                        | SocketAddrUse::UdpReceive => "udp",
                    };
                    let key = format!("{}:{}", addr.ip(), addr.port());
                    let op = ResourceOp {
                        cap_id: act_types::constants::CAP_SOCKETS.to_string(),
                        key: key.clone(),
                        action: String::new(),
                        attrs: serde_json::json!({"protocol": proto}),
                    };
                    let explained = sockets_ceiling.classify_explained(&op);
                    let mode = sockets_effective_mode.to_string();
                    match explained.decision {
                        act_policy::Decision::Allow => {
                            emit_cap_decision(&CapDecisionRecord::statik(
                                act_types::constants::CAP_SOCKETS,
                                &key,
                                &op.action,
                                Decision4::Allow,
                                &mode,
                                explained.rule,
                            ));
                            true
                        }
                        act_policy::Decision::Deny => {
                            emit_cap_decision(&CapDecisionRecord::statik(
                                act_types::constants::CAP_SOCKETS,
                                &key,
                                &op.action,
                                Decision4::Deny,
                                &mode,
                                explained.rule,
                            ));
                            false
                        }
                        // Deliberately silent: `ask` has not resolved yet. The
                        // record is emitted below once the consent cache /
                        // prompter answers, mirroring `fs_policy::resolve_ask`.
                        act_policy::Decision::Ask => {
                            use act_policy::consent::ConsentAsk;
                            let ask = ConsentAsk {
                                cap_id: act_types::constants::CAP_SOCKETS.to_string(),
                                key: key.clone(),
                                summary: format!("socket {proto} {addr}"),
                            };
                            let allowed =
                                tokio::spawn(
                                    async move { cache.decide_cached(&*prompter, ask).await },
                                )
                                .await
                                .unwrap_or(false);
                            emit_cap_decision(&CapDecisionRecord::answered(
                                act_types::constants::CAP_SOCKETS,
                                &key,
                                allowed,
                            ));
                            allowed
                        }
                    }
                })
            })
            .allow_tcp(true)
            .allow_udp(true)
            .allow_ip_name_lookup(sockets_effective_mode != PolicyMode::Deny);
    }

    let wasi = builder.build();

    // The HTTP client's DNS resolver filters resolved IPs against the allow/deny
    // CIDR rules — which the opaque `CompiledCeiling` does not expose — so build
    // it from the full effective HttpConfig (declaration ∩ grant), not just the
    // mode. (The hook uses the ceiling; this PEP path needs the raw rules.)
    let http_effective = act_policy::effective::effective_http(
        &act_policy::grant::to_http_config(grant_policy)?,
        &info.std.capabilities,
    )
    .config;
    let http_client = Arc::new(http_client::ActHttpClient::new(http_effective)?);

    let state = HostState {
        wasi,
        table: ResourceTable::new(),
        http: WasiHttpCtx::new(),
        http_hooks: http_policy::PolicyHttpHooks::new(
            http_ceiling,
            http_client.clone(),
            prompter.clone(),
            cache.clone(),
        ),
        http_client,
        fs_ceiling,
        fs_effective_mode,
        fd_paths: fs_policy::FdPathMap {
            preopens: preopen_pairs,
            by_rep: Default::default(),
        },
        consent_prompter: prompter,
        consent_cache: cache,
        credentials,
        credentials_ceiling,
        limits: match max_memory {
            Some(bytes) => StoreLimitsBuilder::new().memory_size(bytes).build(),
            None => StoreLimits::default(),
        },
    };
    let mut store = Store::new(engine, state);
    // Enforce the linear-memory cap: when the guest grows memory past the limit,
    // `memory.grow` fails (the guest typically traps OOM) instead of letting the
    // host process balloon. No-op when `max_memory` is None (default limits).
    store.limiter(|state| &mut state.limits);
    Ok((store, ceilings))
}

// ── Component info from custom section ──
