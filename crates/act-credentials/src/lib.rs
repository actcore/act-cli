//! Credential profiles, field definitions and storage for the ACT host.
pub mod backend;
pub mod expiry;
pub mod field;
// The file backend's own bookkeeping — the non-secret listing beside the store.
// The `Index` type is not API: nothing outside reaches for it, and publishing it
// would freeze a layout that exists to serve one backend. Its private-write
// helper is, because "create at 0600, replace atomically, never through a file
// we did not make" is the property every host-side secret file needs and it is
// written and tested exactly once.
pub(crate) mod index;

pub use index::write_private;
pub mod record;
pub mod store;
