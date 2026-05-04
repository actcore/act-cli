//! Host-side wrappers for the `act:sessions/session-provider` interface.
//!
//! The host's `bindgen!` only covers `act:tools/tool-provider`, so we
//! look up the session-provider exports manually via raw component-model
//! APIs. Components without session-provider exports are loaded fine —
//! `lookup` simply returns `None` for them.
//!
//! `Error` and `LocalizedString` types are reused from the tool-provider
//! bindings (they are the same `act:core/types` records via structural
//! typing in wasmtime).

use anyhow::Result;
use wasmtime::component::{ComponentNamedList, ComponentType, Instance, Lift, Lower, TypedFunc};
use wasmtime::{AsContext, AsContextMut, StoreContextMut};

use super::HostState;
use super::exports::act::tools::tool_provider::{Error, LocalizedString};

/// `act:sessions/session-provider.session` — the WIT record returned by
/// `open-session`.
#[derive(Debug, Clone, ComponentType, Lift, Lower)]
#[component(record)]
pub struct Session {
    pub id: String,
    pub metadata: Vec<(String, Vec<u8>)>,
}

// ── Typed function aliases (matching the WIT signatures) ───────────────────

/// `get-open-session-args-schema(metadata: metadata) -> result<string, error>`
type GetOpenSessionArgsSchemaFn = TypedFunc<(Vec<(String, Vec<u8>)>,), (Result<String, Error>,)>;

/// `open-session(args: metadata, metadata: metadata) -> result<session, error>`
type OpenSessionFn =
    TypedFunc<(Vec<(String, Vec<u8>)>, Vec<(String, Vec<u8>)>), (Result<Session, Error>,)>;

/// `close-session(session-id: string)`
type CloseSessionFn = TypedFunc<(String,), ()>;

const INTERFACE_NAME: &str = "act:sessions/session-provider@0.1.0";

/// Typed handles to the three session-provider functions of one component
/// instance.
#[derive(Clone)]
pub struct SessionProvider {
    pub get_open_session_args_schema: GetOpenSessionArgsSchemaFn,
    pub open_session: OpenSessionFn,
    pub close_session: CloseSessionFn,
}

impl SessionProvider {
    /// Look up the session-provider exports of a component instance.
    /// Returns `None` if the component doesn't export session-provider.
    pub fn lookup(
        instance: &Instance,
        mut store: StoreContextMut<'_, HostState>,
    ) -> Result<Option<Self>> {
        let Some((_, iface)) = instance.get_export(&mut store, None, INTERFACE_NAME) else {
            return Ok(None);
        };

        let get_schema = lookup_typed(
            instance,
            store.as_context_mut(),
            Some(&iface),
            "get-open-session-args-schema",
        )?;
        let open = lookup_typed(
            instance,
            store.as_context_mut(),
            Some(&iface),
            "open-session",
        )?;
        let close = lookup_typed(
            instance,
            store.as_context_mut(),
            Some(&iface),
            "close-session",
        )?;

        Ok(Some(Self {
            get_open_session_args_schema: get_schema,
            open_session: open,
            close_session: close,
        }))
    }
}

fn lookup_typed<Params, Return>(
    instance: &Instance,
    mut store: StoreContextMut<'_, HostState>,
    iface: Option<&wasmtime::component::ComponentExportIndex>,
    name: &str,
) -> Result<TypedFunc<Params, Return>>
where
    Params: ComponentNamedList + Lower + Send + Sync + 'static,
    Return: ComponentNamedList + Lift + Send + Sync + 'static,
{
    let (_, idx) = instance
        .get_export(&mut store, iface, name)
        .ok_or_else(|| anyhow::anyhow!("session-provider missing export `{name}`"))?;
    let func = instance
        .get_func(&mut store, idx)
        .ok_or_else(|| anyhow::anyhow!("session-provider export `{name}` is not a function"))?;
    func.typed::<Params, Return>(store.as_context())
        .map_err(|e| anyhow::anyhow!("session-provider `{name}` typed lookup failed: {e}"))
}

// LocalizedString is currently only referenced indirectly through Error;
// keep the import alive for callers that grow handling here.
#[allow(dead_code)]
fn _localized_string_in_scope(_: LocalizedString) {}
