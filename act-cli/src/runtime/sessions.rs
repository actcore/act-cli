//! Host-side typed handles for the generated `act:sessions/session-provider`
//! bindings.
//!
//! `act-world` declares `session-provider` as an export, but it is opt-in:
//! stateless components do not export it. The host therefore binds it through
//! a per-interface `GuestIndices::new` lookup that is allowed to fail —
//! `instantiate_component` turns that failure into `None`, so components
//! without session-provider instantiate fine.
//!
//! `Session`, `Error` and `Metadata` come straight from the generated
//! bindings (the same `act:core/types` records the tool-provider uses, shared
//! via the single `act-world` bindgen invocation).

use wasmtime::component::TypedFunc;

use super::exports::act::sessions::session_provider::Guest;
// `act:sessions@0.2.0` moved the `session` record into `act:sessions/types`;
// `error` / `metadata` resolve through `act:core/types`. Only the `Guest`
// (and its typed-func accessors) still live in `session_provider`.
use super::act::core::types::{Error, Metadata};

/// `act:sessions/types.session` — re-exported from the generated bindings so
/// callers keep referring to `sessions::Session`.
pub use super::act::sessions::types::Session;

// ── Typed function aliases (matching the WIT signatures) ───────────────────

/// `get-open-session-args-schema(metadata) -> result<string, error>`
type GetOpenSessionArgsSchemaFn = TypedFunc<(Metadata,), (Result<String, Error>,)>;

/// `open-session(args: metadata, metadata: metadata) -> result<session, error>`
type OpenSessionFn = TypedFunc<(Metadata, Metadata), (Result<Session, Error>,)>;

/// `close-session(session-id: string)`
type CloseSessionFn = TypedFunc<(String,), ()>;

/// Typed handles to the three session-provider functions of one component
/// instance, derived from the generated session `Guest`.
#[derive(Clone)]
pub struct SessionProvider {
    pub get_open_session_args_schema: GetOpenSessionArgsSchemaFn,
    pub open_session: OpenSessionFn,
    pub close_session: CloseSessionFn,
}

impl SessionProvider {
    /// Build typed handles from the generated session-provider `Guest`.
    pub fn from_guest(guest: &Guest) -> Self {
        Self {
            get_open_session_args_schema: guest.func_get_open_session_args_schema(),
            open_session: guest.func_open_session(),
            // `close-session` is a sync WIT func, so bindgen types its accessor
            // `TypedFunc<(&str,), ()>`. `call_concurrent` (used to drive it
            // through the async store, like the other two) rejects that because
            // its params must be `'static`. Re-type the same underlying `Func`
            // to owned `(String,)`; the lowering is identical (both lower a
            // `string`), which is what makes the `new_unchecked` sound.
            close_session: unsafe { TypedFunc::new_unchecked(*guest.func_close_session().func()) },
        }
    }
}
