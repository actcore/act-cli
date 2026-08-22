//! The component actor: one task owning the store, fed typed requests
//! over a channel. Also the audit envelope each call is wrapped in.

use anyhow::Result;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::{mpsc, oneshot};
use tracing::Instrument;
use wasmtime::component::{Component, Linker, Source, StreamConsumer, StreamResult};
use wasmtime::{Engine, Store, StoreContextMut};

use crate::consent;
use crate::info::{ComponentError, ComponentInfo};
use crate::store::{HostState, create_store};
use crate::{act, exports};
use crate::{credentials, fs_policy, sessions};

/// Identity of the running artifact, carried into every audit record.
#[derive(Debug, Clone)]
pub struct AuditContext {
    pub component_ref: String,
    pub digest: String,
    pub transport: crate::audit::Transport,
    /// Whether this run has any channel that can answer an interactive
    /// `ask` prompt — a real TTY (`TtyPrompter`) or an MCP client offering
    /// elicitation (`McpElicitationPrompter`). `false` for headless CLI
    /// invocations and ACT-HTTP (`DenyPrompter`), where every `ask`
    /// decision degrades to deny before a human is ever involved. Decided
    /// once, at the same point the concrete prompter is chosen, and carried
    /// here so `instantiate_component` never has to infer it from the
    /// prompter's type.
    pub has_prompt_channel: bool,
    /// `--audit-args`: record full tool-argument values in the envelope
    /// alongside the digest, instead of the digest alone. Never applies to
    /// session args — those are carried only as `session_id` regardless of
    /// this flag; see `args_as_json`, which this only gates.
    pub record_args: bool,
}
/// Pull a well-known `std:` key out of decoded call metadata for the audit
/// envelope. Only ids are ever read this way — session *args* carry auth and
/// are never logged, only the session id they produced.
pub(crate) fn meta_str(metadata: &[(String, String)], key: &str) -> Option<String> {
    metadata
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.clone())
        .filter(|v| !v.is_empty())
}
/// Decode the string-valued entries out of raw WIT call metadata
/// (`list<tuple<string, list<u8>>>`, each value dCBOR-encoded) so `meta_str`
/// can search them. The `std:*` correlation ids the envelope reads are always
/// CBOR text strings; anything that doesn't decode to one is dropped rather
/// than guessed at.
pub(crate) fn decode_meta_strings(metadata: &[(String, Vec<u8>)]) -> Vec<(String, String)> {
    metadata
        .iter()
        .filter_map(|(k, v)| {
            let value = act_types::cbor::cbor_to_json(v).ok()?;
            value.as_str().map(|s| (k.clone(), s.to_string()))
        })
        .collect()
}
/// Render tool-call arguments (dCBOR bytes) as a JSON string for the audit
/// envelope, gated by `--audit-args`. Returns `None` when the flag is unset
/// (the default — `args_sha256` is all that is ever recorded then) or when
/// the arguments fail to decode; either way the call itself proceeds
/// unaffected, since the audit trail must never influence enforcement.
/// Session args never pass through this function — `open_session_for_call`
/// only ever forwards a `session_id` into the envelope, never the args that
/// produced it.
fn args_as_json(arguments: &[u8], record_args: bool) -> Option<String> {
    if !record_args {
        return None;
    }
    let value = act_types::cbor::cbor_to_json(arguments).ok()?;
    serde_json::to_string(&value).ok()
}
/// True if any event in a completed call's result signals a guest tool-level
/// failure. `call-tool` never returns `result<tool-result, error>` — an early
/// failure is encoded as a `tool-event::error` inside an otherwise `Ok`
/// response (ACT-TOOLS §5.2), the same shape `rmcp_bridge`'s
/// `fold_events_to_result` inspects to map a call to an MCP error response.
/// The audit envelope has to look at the same signal, or every guest failure
/// audits as `ok`.
fn events_contain_error(events: &[act::tools::types::ToolEvent]) -> bool {
    events
        .iter()
        .any(|e| matches!(e, act::tools::types::ToolEvent::Error(_)))
}
/// Width of the visible request-id's counter field, in bits. See
/// `pack_visible_request_id` for why this trades off against
/// `SALT_BITS` rather than being widened freely.
const REQUEST_ID_COUNTER_BITS: u32 = 9; // 512 values
/// Width of the visible request-id's salt field, in bits. Together with
/// `COUNTER_BITS` this must sum to 24 (`render_rollup` shows the id's first
/// 6 hex digits = 24 bits — the hard ceiling on how many values can ever be
/// visually distinguishable, no matter how the id is built).
const REQUEST_ID_SALT_BITS: u32 = 24 - REQUEST_ID_COUNTER_BITS; // 15 bits, 32768 values
/// Pack a per-call counter and a per-process salt into the 24-bit value
/// rendered as `new_request_id`'s leading 6 hex digits — the only part
/// `render_rollup`'s 6-byte truncation shows an operator. A prior fix
/// (`format!("act-{:x}", hash_of(pid, counter, time))`) spent 4 of those 6
/// bytes on the literal `act-` and left only 2 hex digits (256 values) of
/// real entropy visible; a standalone repro of that exact algorithm hit a
/// birthday collision at call #23 of 40. This packs the full 24 visible
/// bits productively instead, split so both properties the review asked
/// for hold within that hard ceiling:
///
/// - the high `COUNTER_BITS` bits are the per-process call counter, so two
///   different calls in the SAME process render deterministically distinct
///   visible prefixes — not probabilistically, as long as fewer than
///   `2^COUNTER_BITS` calls have been made in this process. A *fixed-width*
///   bit field is what makes this a guarantee: a variable-width
///   counter-then-salt string (e.g. `format!("{:x}{}", counter, salt)`)
///   can have a short counter's digits absorbed into what looks like a
///   longer counter's leading digits when the salt happens to repeat the
///   right digit — confirmed a real instance by brute-force search rather
///   than asserting it from intuition: `counter=1` and `counter=0x11`
///   both render `"111111"` under that scheme at `salt=0x11111`. Bit
///   packing can't do this — the counter occupies fixed bit positions no
///   salt value can shift into.
/// - the low `SALT_BITS` bits are a per-process random salt, so two
///   different PROCESSES — the dominant real-world case, since most `act
///   call` invocations make exactly one request and so always have
///   counter == 0 — usually render different visible prefixes too.
pub(crate) fn pack_visible_request_id(counter: u64, salt: u32) -> u32 {
    let counter_field = (counter as u32) & ((1 << REQUEST_ID_COUNTER_BITS) - 1);
    let salt_field = salt & ((1 << REQUEST_ID_SALT_BITS) - 1);
    (counter_field << REQUEST_ID_SALT_BITS) | salt_field
}
/// Host-generated correlation id, used when the caller supplied no
/// `std:request-id`. Keeping this non-optional is what makes every audit line
/// joinable to a client log line.
///
/// The visible (6-hex-digit) part comes from `pack_visible_request_id`; see
/// its doc comment for why it's split into a counter field and a salt
/// field. `salt` is drawn once per process, from `RandomState`'s
/// OS-seeded-per-thread hasher (no new dependency); `counter` is the usual
/// per-process monotonic count. The full, un-truncated counter is appended
/// after the visible portion too, so the untruncated id (used verbatim as
/// the `act.request.id` span attribute for OTLP export, never truncated
/// there) stays globally unique for the lifetime of the process regardless
/// of the 6-byte display ceiling.
pub(crate) fn new_request_id() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SALT: OnceLock<u32> = OnceLock::new();
    let salt = *SALT.get_or_init(|| {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u32(std::process::id());
        hasher.finish() as u32
    });

    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);

    format!("{:06x}-{n:x}", pack_visible_request_id(n, salt))
}
pub use act_types::Metadata;
/// Requests that can be sent to the component actor.
pub(crate) enum ComponentRequest {
    ListTools {
        metadata: Metadata,
        reply: oneshot::Sender<Result<act::tools::types::ListToolsResponse, ComponentError>>,
    },
    CallTool {
        name: String,
        arguments: Vec<u8>,
        metadata: Vec<(String, Vec<u8>)>,
        reply: oneshot::Sender<Result<CallToolResult, ComponentError>>,
        /// Where a capability gate firing during this call sends its consent
        /// question. `None` for transports that prompt locally (TTY) or do not
        /// prompt at all. See `runtime::elicit` for why the ask travels back to
        /// the caller instead of the gate reaching for the peer itself.
        consent: Option<consent::ConsentSink>,
    },
    /// Returns a JSON Schema string. A component with no `session-provider`
    /// fails with `Internal`, not a `std:not-found` tool error: nothing ran.
    GetOpenSessionArgsSchema {
        metadata: Vec<(String, Vec<u8>)>,
        reply: oneshot::Sender<Result<String, ComponentError>>,
    },
    /// A component with no `session-provider` fails with `Internal`.
    OpenSession {
        args: Vec<(String, Vec<u8>)>,
        metadata: Vec<(String, Vec<u8>)>,
        reply: oneshot::Sender<Result<sessions::Session, ComponentError>>,
        /// Same routing as `CallTool::consent`. Bridges do their network I/O
        /// while opening a session, so this is where their capability gate
        /// usually fires.
        consent: Option<consent::ConsentSink>,
    },
    /// A component with no `session-provider` fails with `Internal`. The
    /// reply carries `()` so callers can wait for the close to complete.
    CloseSession {
        session_id: String,
        reply: oneshot::Sender<Result<(), ComponentError>>,
    },
}
/// Collected result from call-tool (stream already consumed).
pub struct CallToolResult {
    pub events: Vec<act::tools::types::ToolEvent>,
}
/// Handle to send requests to the component actor.
#[derive(Clone)]
pub struct ComponentHandle(mpsc::Sender<ComponentRequest>);

impl ComponentHandle {
    pub(crate) fn new(tx: mpsc::Sender<ComponentRequest>) -> Self {
        Self(tx)
    }

    /// A handle with no actor behind it: every call answers
    /// `component actor unavailable`.
    ///
    /// For host tests that need to construct whatever holds a handle without
    /// standing up a component. The request enum is private, so a host cannot
    /// build one of these itself.
    pub fn disconnected() -> Self {
        let (tx, _rx) = mpsc::channel(1);
        Self(tx)
    }

    /// Send one request and wait for its reply.
    ///
    /// Both ways the round trip can fail without the component ever running —
    /// the actor gone before the send, the actor gone after it — are host
    /// failures, not tool errors, and neither may be reported as something the
    /// component said.
    async fn round_trip<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<Result<T, ComponentError>>) -> ComponentRequest,
    ) -> Result<T, ComponentError> {
        let (reply, answer) = oneshot::channel();
        self.0.send(build(reply)).await.map_err(|_| {
            ComponentError::Internal(anyhow::anyhow!("component actor unavailable"))
        })?;
        answer.await.map_err(|_| {
            ComponentError::Internal(anyhow::anyhow!("component actor dropped reply"))
        })?
    }

    pub async fn list_tools(
        &self,
        metadata: &Metadata,
    ) -> Result<act::tools::types::ListToolsResponse, ComponentError> {
        self.round_trip(|reply| ComponentRequest::ListTools {
            metadata: metadata.clone(),
            reply,
        })
        .await
    }

    /// `consent` is where a capability gate firing *during this call* sends its
    /// question. `None` for transports that prompt locally or not at all — see
    /// [`crate::consent`] for why the ask travels back to the caller rather
    /// than the gate reaching for a peer itself.
    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Vec<u8>,
        metadata: Vec<(String, Vec<u8>)>,
        consent: Option<consent::ConsentSink>,
    ) -> Result<CallToolResult, ComponentError> {
        self.round_trip(|reply| ComponentRequest::CallTool {
            name: name.to_string(),
            arguments,
            metadata,
            reply,
            consent,
        })
        .await
    }

    /// A component that exports no session-provider fails with
    /// [`ComponentError::Internal`] — the host could not make the call, as
    /// opposed to the component declining it.
    pub async fn open_session(
        &self,
        args: Vec<(String, Vec<u8>)>,
        metadata: Vec<(String, Vec<u8>)>,
        consent: Option<consent::ConsentSink>,
    ) -> Result<sessions::Session, ComponentError> {
        self.round_trip(|reply| ComponentRequest::OpenSession {
            args,
            metadata,
            reply,
            consent,
        })
        .await
    }

    pub async fn close_session(&self, session_id: String) -> Result<(), ComponentError> {
        self.round_trip(|reply| ComponentRequest::CloseSession { session_id, reply })
            .await
    }

    /// Send one request and wait for its reply, answering any consent question
    /// the gate raises *while the call is running* through `answer`.
    ///
    /// The select loop lives here rather than in the host because the ordering
    /// it encodes is a property of the runtime: the guest is blocked until the
    /// answer lands, so a pending ask must be serviced before the reply is
    /// polled — `biased` is load-bearing, not a preference. What a host
    /// supplies is only how to put the question to a human.
    async fn round_trip_servicing_consent<T, F, Fut>(
        &self,
        build: impl FnOnce(
            oneshot::Sender<Result<T, ComponentError>>,
            consent::ConsentSink,
        ) -> ComponentRequest,
        mut answer: F,
    ) -> Result<T, ComponentError>
    where
        F: FnMut(String) -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let (reply, mut answer_rx) = oneshot::channel();
        // Depth 1: the actor runs one call at a time and blocks on each answer.
        let (consent_tx, mut consent_rx) = mpsc::channel::<consent::ConsentRequest>(1);

        self.0.send(build(reply, consent_tx)).await.map_err(|_| {
            ComponentError::Internal(anyhow::anyhow!("component actor unavailable"))
        })?;

        let reply = loop {
            tokio::select! {
                biased;
                Some(ask) = consent_rx.recv() => {
                    let decision = answer(ask.message).await;
                    let _ = ask.reply.send(decision);
                }
                reply = &mut answer_rx => break reply,
            }
        };
        reply.map_err(|_| {
            ComponentError::Internal(anyhow::anyhow!("component actor dropped reply"))
        })?
    }

    /// [`Self::call_tool`], with consent questions routed back to `answer`
    /// instead of denied. Transports with a back-channel to a human use this.
    pub async fn call_tool_servicing_consent<F, Fut>(
        &self,
        name: &str,
        arguments: Vec<u8>,
        metadata: Vec<(String, Vec<u8>)>,
        answer: F,
    ) -> Result<CallToolResult, ComponentError>
    where
        F: FnMut(String) -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        self.round_trip_servicing_consent(
            |reply, consent| ComponentRequest::CallTool {
                name: name.to_string(),
                arguments,
                metadata,
                reply,
                consent: Some(consent),
            },
            answer,
        )
        .await
    }

    /// [`Self::open_session`], with consent questions routed back to `answer`.
    /// A bridge does its network I/O while opening a session, so this is where
    /// its capability gate usually fires.
    pub async fn open_session_servicing_consent<F, Fut>(
        &self,
        args: Vec<(String, Vec<u8>)>,
        metadata: Vec<(String, Vec<u8>)>,
        answer: F,
    ) -> Result<sessions::Session, ComponentError>
    where
        F: FnMut(String) -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        self.round_trip_servicing_consent(
            |reply, consent| ComponentRequest::OpenSession {
                args,
                metadata,
                reply,
                consent: Some(consent),
            },
            answer,
        )
        .await
    }

    /// Returns a JSON Schema string. A component that exports no
    /// session-provider fails with [`ComponentError::Internal`].
    pub async fn open_session_args_schema(
        &self,
        metadata: Vec<(String, Vec<u8>)>,
    ) -> Result<String, ComponentError> {
        self.round_trip(|reply| ComponentRequest::GetOpenSessionArgsSchema { metadata, reply })
            .await
    }
}
/// The generated tool-provider guest — the always-present surface of every
/// ACT component.
pub use exports::act::tools::tool_provider::Guest as ToolProvider;
/// Instantiate the component. Returns the tool-provider guest, an optional
/// SessionProvider (present iff the component exports
/// `act:sessions/session-provider`), and the store.
///
/// `act-world` declares both `tool-provider` and `session-provider` as
/// exports, but the latter is opt-in. Rather than `ActWorldIndices::new`
/// (which requires *every* declared export and would reject stateless
/// components), each interface is bound through its own per-interface
/// `GuestIndices`: tool-provider is mandatory, session-provider is looked up
/// with `.ok()` so its absence yields `None`.
///
/// Component info is read from custom sections (no instantiation needed
/// for that).
#[allow(clippy::too_many_arguments)]
pub async fn instantiate_component(
    engine: &Engine,
    component: &Component,
    linker: &Linker<HostState>,
    preopens: &[fs_policy::Preopen],
    grant_policy: &act_policy::grant::GrantPolicy,
    info: &ComponentInfo,
    max_memory: Option<usize>,
    prompter: Arc<dyn act_policy::consent::ConsentPrompter>,
    cache: Arc<act_policy::consent::DecisionCache>,
    credentials: Option<Arc<credentials::CredentialHost>>,
    audit: &AuditContext,
) -> Result<(
    ToolProvider,
    Option<sessions::SessionProvider>,
    Store<HostState>,
)> {
    use exports::act::sessions::session_provider::GuestIndices as SessionGuestIndices;
    use exports::act::tools::tool_provider::GuestIndices as ToolGuestIndices;

    let (mut store, ceilings) = create_store(
        engine,
        preopens,
        grant_policy,
        info,
        max_memory,
        prompter,
        cache,
        credentials,
        &audit.component_ref,
    )
    .await?;

    let pre = linker
        .instantiate_pre(component)
        .map_err(|e| anyhow::anyhow!("failed to pre-instantiate component: {e}"))?;
    // Resolve export indices before instantiation. tool-provider is required;
    // session-provider is optional — a missing export makes `new` error, which
    // we map to `None` (the component is simply stateless).
    let tool_indices =
        ToolGuestIndices::new(&pre).map_err(|e| anyhow::anyhow!("tool-provider indices: {e}"))?;
    let session_indices = SessionGuestIndices::new(&pre).ok();

    let instance = pre
        .instantiate_async(&mut store)
        .await
        .map_err(|e| anyhow::anyhow!("failed to instantiate component: {e}"))?;

    let tool_provider = tool_indices
        .load(&mut store, &instance)
        .map_err(|e| anyhow::anyhow!("failed to load tool-provider: {e}"))?;

    let session_provider = match session_indices {
        Some(idx) => {
            let guest = idx
                .load(&mut store, &instance)
                .map_err(|e| anyhow::anyhow!("failed to load session-provider: {e}"))?;
            Some(sessions::SessionProvider::from_guest(&guest))
        }
        None => None,
    };

    // Audit at instantiation: what is running, and under what modes. Modelled
    // exactly like a tool call — a span with one event per capability class —
    // so the same layer machinery renders it and OTLP gets queryable per-class
    // attributes rather than a sentence.
    let inst_span = crate::audit::instantiation_span(&audit.component_ref, &audit.digest);
    {
        let _g = inst_span.enter();
        for (id, c) in &ceilings {
            crate::audit::emit_ceiling_class(&crate::audit::CeilingClassRecord {
                cap_id: id.clone(),
                mode: c.effective_mode().to_string(),
                declared: c.declared(),
                has_prompt_channel: audit.has_prompt_channel,
            });
        }
    }
    // Dropping the span closes it; the layer renders the header line and, when
    // a declared class resolved to deny, the declared-but-ungranted warning.
    drop(inst_span);

    Ok((tool_provider, session_provider, store))
}
/// Spawn the component actor task. Owns the Store, the tool-provider guest,
/// and the optional SessionProvider (present iff the component supports
/// `act:sessions/session-provider`).
///
/// Returns a handle for sending requests.
pub fn spawn_component_actor(
    tool_provider: ToolProvider,
    session_provider: Option<sessions::SessionProvider>,
    mut store: Store<HostState>,
    current_consent: Arc<consent::CurrentConsentSink>,
    audit: AuditContext,
) -> ComponentHandle {
    let (tx, mut rx) = mpsc::channel::<ComponentRequest>(32);

    // Session-ids opened through this actor. Closed on actor shutdown
    // per ACT-SESSIONS §2.5 ("host MUST call close-session for every
    // still-open session before deinit").
    let mut tracked_sessions: Vec<String> = Vec::new();

    // The credential host, if this run has one. Taken from the store rather
    // than passed in: it is already there, and reading it here keeps the two
    // views of "which sessions are live" — this actor's `tracked_sessions`
    // and the credential host's set — updated from the same three places.
    // Every transport (MCP stdio, MCP over HTTP, `--session-args`) opens and
    // closes sessions through these requests, so wiring it here covers all
    // of them at once.
    let credentials = store.data().credentials.clone();

    tokio::spawn(async move {
        while let Some(request) = rx.recv().await {
            match request {
                ComponentRequest::ListTools { metadata, reply } => {
                    let provider = tool_provider.clone();
                    let result = store
                        .run_concurrent(async |accessor| {
                            provider
                                .call_list_tools(accessor, metadata.clone().into())
                                .await
                        })
                        .await;
                    let response = match result {
                        Ok(Ok(Ok(list_response))) => Ok(list_response),
                        Ok(Ok(Err(tool_error))) => Err(ComponentError::Tool(tool_error)),
                        Ok(Err(e)) => Err(ComponentError::Internal(anyhow::anyhow!(
                            "list-tools failed: {e}"
                        ))),
                        Err(e) => Err(ComponentError::Internal(anyhow::anyhow!(
                            "run_concurrent failed: {e}"
                        ))),
                    };
                    let _ = reply.send(response);
                }
                ComponentRequest::CallTool {
                    name,
                    arguments,
                    metadata,
                    reply,
                    consent,
                } => {
                    // Point the consent slot at this call for the duration of
                    // the guest execution. The actor serves one request at a
                    // time, so a capability gate firing below always resolves
                    // to the caller that is waiting for this reply.
                    current_consent.set(consent);
                    let provider = tool_provider.clone();

                    let started = std::time::Instant::now();
                    let meta_strings = decode_meta_strings(&metadata);
                    let audit_span = crate::audit::tool_call_span(&crate::audit::ToolCallStart {
                        component_ref: audit.component_ref.clone(),
                        digest: audit.digest.clone(),
                        tool: name.clone(),
                        args_sha256: crate::audit::sha256_hex(&arguments),
                        args_json: args_as_json(&arguments, audit.record_args),
                        session_id: meta_str(&meta_strings, act_types::constants::META_SESSION_ID),
                        agent_id: meta_str(&meta_strings, act_types::constants::META_AGENT_ID),
                        request_id: meta_str(&meta_strings, act_types::constants::META_REQUEST_ID)
                            .unwrap_or_else(new_request_id),
                        traceparent: meta_str(
                            &meta_strings,
                            act_types::constants::META_TRACEPARENT,
                        ),
                        tracestate: meta_str(&meta_strings, act_types::constants::META_TRACESTATE),
                        transport: audit.transport,
                    });

                    let collected: Arc<std::sync::Mutex<Vec<act::tools::types::ToolEvent>>> =
                        Arc::new(std::sync::Mutex::new(Vec::new()));
                    let collected2 = collected.clone();
                    let (done_tx, done_rx) = oneshot::channel::<()>();

                    let result = store
                        .run_concurrent(async |accessor| {
                            let tool_result = provider
                                .call_call_tool(
                                    accessor,
                                    name.clone(),
                                    arguments.clone(),
                                    metadata.clone(),
                                )
                                .await?;

                            accessor.with(|access| match tool_result {
                                exports::act::tools::tool_provider::ToolResult::Streaming(
                                    stream,
                                ) => {
                                    let consumer = CollectingConsumer {
                                        collected,
                                        done_tx: Some(done_tx),
                                    };
                                    let _ = stream.pipe(access, consumer);
                                }
                                exports::act::tools::tool_provider::ToolResult::Immediate(
                                    events,
                                ) => {
                                    collected
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .extend(events);
                                    let _ = done_tx.send(());
                                }
                            });

                            let _ = done_rx.await;

                            Ok::<_, wasmtime::Error>(())
                        })
                        .instrument(audit_span.clone())
                        .await;

                    let response = match result {
                        Ok(Ok(())) => {
                            let events = collected2
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .drain(..)
                                .collect();
                            Ok(CallToolResult { events })
                        }
                        Ok(Err(e)) => Err(ComponentError::Internal(anyhow::anyhow!(
                            "call-tool failed: {e}"
                        ))),
                        Err(e) => Err(ComponentError::Internal(anyhow::anyhow!(
                            "run_concurrent failed: {e}"
                        ))),
                    };
                    // Nothing is executing any more: drop the sink so a later
                    // gate outside a call cannot answer through a stale caller.
                    current_consent.set(None);
                    let outcome = match &response {
                        // `call-tool` reports a guest failure inside the event
                        // list, not via the outer Result — see
                        // `events_contain_error`.
                        Ok(r) if events_contain_error(&r.events) => {
                            crate::audit::Outcome::ToolError
                        }
                        Ok(_) => crate::audit::Outcome::Ok,
                        Err(ComponentError::Tool(_)) => crate::audit::Outcome::ToolError,
                        Err(_) => crate::audit::Outcome::HostError,
                    };
                    crate::audit::finish_tool_call(&audit_span, outcome, started.elapsed());
                    let _ = reply.send(response);
                }
                ComponentRequest::GetOpenSessionArgsSchema { metadata, reply } => {
                    let response = match &session_provider {
                        Some(sp) => {
                            let sp = sp.clone();
                            let result = store
                                .run_concurrent(async |accessor| {
                                    sp.get_open_session_args_schema
                                        .call_concurrent(&accessor, (metadata,))
                                        .await
                                })
                                .await;
                            session_call_to_response(result, |(r,)| r)
                        }
                        None => Err(ComponentError::Internal(anyhow::anyhow!(
                            "component does not export act:sessions/session-provider"
                        ))),
                    };
                    let _ = reply.send(response);
                }

                ComponentRequest::OpenSession {
                    args,
                    metadata,
                    reply,
                    consent,
                } => {
                    current_consent.set(consent);
                    let response = match &session_provider {
                        Some(sp) => {
                            let sp = sp.clone();
                            let result = store
                                .run_concurrent(async |accessor| {
                                    sp.open_session
                                        .call_concurrent(&accessor, (args, metadata))
                                        .await
                                })
                                .await;
                            let inner = session_call_to_response(result, |(r,)| r);
                            // Track open id so we can close on deinit.
                            if let Ok(s) = &inner {
                                tracked_sessions.push(s.id.clone());
                                if let Some(c) = &credentials {
                                    c.note_session_opened(&s.id);
                                }
                            }
                            inner
                        }
                        None => Err(ComponentError::Internal(anyhow::anyhow!(
                            "component does not export act:sessions/session-provider"
                        ))),
                    };
                    current_consent.set(None);
                    let _ = reply.send(response);
                }

                ComponentRequest::CloseSession { session_id, reply } => {
                    let response: Result<(), ComponentError> = match &session_provider {
                        Some(sp) => {
                            let sp = sp.clone();
                            let id = session_id.clone();
                            let result = store
                                .run_concurrent(async |accessor| {
                                    sp.close_session.call_concurrent(&accessor, (id,)).await
                                })
                                .await;
                            // Untrack regardless of error. Credentials stop
                            // being served for this id at the same moment
                            // (design §3.3: "after close-session the host stops
                            // serving that id") — a close that the component
                            // reported as failed still ends the session from
                            // the host's side, so the two must agree.
                            tracked_sessions.retain(|sid| sid != &session_id);
                            if let Some(c) = &credentials {
                                c.note_session_closed(&session_id);
                            }
                            match result {
                                Ok(Ok(())) => Ok(()),
                                Ok(Err(e)) => Err(ComponentError::Internal(anyhow::anyhow!(
                                    "close-session failed: {e}"
                                ))),
                                Err(e) => Err(ComponentError::Internal(anyhow::anyhow!(
                                    "run_concurrent failed: {e}"
                                ))),
                            }
                        }
                        None => Err(ComponentError::Internal(anyhow::anyhow!(
                            "component does not export act:sessions/session-provider"
                        ))),
                    };
                    let _ = reply.send(response);
                }
            }
        }

        // Actor channel closed → component is shutting down. Close any
        // sessions we still track, best-effort. ACT-SESSIONS §2.5.
        if let Some(sp) = &session_provider {
            for id in std::mem::take(&mut tracked_sessions) {
                if let Some(c) = &credentials {
                    c.note_session_closed(&id);
                }
                let sp = sp.clone();
                let _ = store
                    .run_concurrent(async |accessor| {
                        sp.close_session.call_concurrent(&accessor, (id,)).await
                    })
                    .await;
            }
        }
    });

    ComponentHandle::new(tx)
}
/// Helper for unwrapping `result<R, error>` returns from session-provider
/// typed-func calls.
fn session_call_to_response<R, F>(
    raw: wasmtime::Result<wasmtime::Result<(Result<R, act::core::types::Error>,)>>,
    extract: F,
) -> Result<R, ComponentError>
where
    F: FnOnce((Result<R, act::core::types::Error>,)) -> Result<R, act::core::types::Error>,
{
    match raw {
        Ok(Ok(tuple)) => match extract(tuple) {
            Ok(r) => Ok(r),
            Err(e) => Err(ComponentError::Tool(e)),
        },
        Ok(Err(e)) => Err(ComponentError::Internal(anyhow::anyhow!(
            "session-provider call failed: {e}"
        ))),
        Err(e) => Err(ComponentError::Internal(anyhow::anyhow!(
            "run_concurrent failed: {e}"
        ))),
    }
}
/// A StreamConsumer that collects all items into a Vec and signals completion.
struct CollectingConsumer {
    collected: Arc<std::sync::Mutex<Vec<act::tools::types::ToolEvent>>>,
    done_tx: Option<oneshot::Sender<()>>,
}
impl StreamConsumer<HostState> for CollectingConsumer {
    type Item = act::tools::types::ToolEvent;

    fn poll_consume(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        store: StoreContextMut<HostState>,
        mut source: Source<'_, Self::Item>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        let mut buffer = Vec::with_capacity(64);
        source.read(store, &mut buffer)?;

        if !buffer.is_empty() {
            self.collected
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend(buffer);
        }

        if finish {
            if let Some(tx) = self.done_tx.take() {
                let _ = tx.send(());
            }
            Poll::Ready(Ok(StreamResult::Dropped))
        } else {
            Poll::Ready(Ok(StreamResult::Completed))
        }
    }
}
