//! The common policy decision returned by every capability provider.

/// The verdict for one capability operation, shared across all classes
/// (filesystem, http, sockets, and generic/semantic providers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Permitted.
    Allow,
    /// Refused.
    Deny,
    /// In-ceiling but `ask` mode: defer to interactive consent. The sync
    /// classifier never prompts; the async caller (e.g. `fs_policy::check_path`)
    /// resolves this through the `DecisionCache` / `ConsentPrompter`.
    Ask,
}
