//! The pluggable capability-decision framework: providers (factories) produce
//! compiled ceilings; a registry maps capability ids to providers.

use std::sync::Arc;

use crate::Decision;
use crate::grant::{CapabilityGrant, PolicyError};

/// One operation to classify. Erased so any provider can interpret it, from an
/// intercepted WASI op or a reported `consent.request`.
#[derive(Debug, Clone)]
pub struct ResourceOp {
    pub cap_id: String,
    /// Primary subject: path / "host:port" / socket addr / semantic key.
    pub key: String,
    /// Attempted sub-operation: "read"/"write" (fs), HTTP method, etc. "" if N/A.
    pub action: String,
    /// Extra structured attributes (scheme, protocol, semantic args). Null if none.
    pub attrs: serde_json::Value,
}

/// A capability class's decision logic. Object-safe; held as `dyn` in the registry.
pub trait CapabilityProvider: Send + Sync {
    fn resolve(
        &self,
        cap_id: &str,
        declared: &[serde_json::Value],
        grant: &CapabilityGrant,
    ) -> Result<Box<dyn CompiledCeiling>, PolicyError>;
}

/// The compiled ceiling for one class in one run. Pure, sync, wasm-clean.
pub trait CompiledCeiling: Send + Sync {
    fn classify(&self, op: &ResourceOp) -> Decision;
    fn declared(&self) -> bool;
    /// Test/diagnostic tag; production impls keep the default.
    fn tag(&self) -> &str {
        ""
    }
}

/// Maps capability ids (incl. `*`-suffix globs) to providers, with a generic fallback.
pub struct ProviderRegistry {
    entries: Vec<(String, Arc<dyn CapabilityProvider>)>,
    generic: Arc<dyn CapabilityProvider>,
}

impl ProviderRegistry {
    pub fn new(generic: Arc<dyn CapabilityProvider>) -> Self {
        Self {
            entries: Vec::new(),
            generic,
        }
    }

    pub fn register(&mut self, pattern: &str, provider: Arc<dyn CapabilityProvider>) {
        self.entries.push((pattern.to_string(), provider));
    }

    /// Priority: exact id > longest matching `*`-prefix > generic fallback.
    pub fn lookup(&self, cap_id: &str) -> &Arc<dyn CapabilityProvider> {
        if let Some((_, p)) = self.entries.iter().find(|(k, _)| k == cap_id) {
            return p;
        }
        let mut best: Option<(&str, &Arc<dyn CapabilityProvider>)> = None;
        for (k, p) in &self.entries {
            if let Some(prefix) = k.strip_suffix('*')
                && cap_id.starts_with(prefix)
                && best.is_none_or(|(bk, _)| prefix.len() > bk.len() - 1)
            {
                best = Some((k, p));
            }
        }
        best.map(|(_, p)| p).unwrap_or(&self.generic)
    }

    /// Build a registry pre-loaded with the built-in fs/http/sockets providers
    /// and the generic fallback.
    pub fn with_builtins() -> Self {
        let mut r = Self::new(Arc::new(crate::providers::generic::GenericProvider));
        r.register(
            "wasi:filesystem",
            Arc::new(crate::providers::fs::FsProvider),
        );
        r.register("wasi:http", Arc::new(crate::providers::http::HttpProvider));
        r.register(
            "wasi:sockets",
            Arc::new(crate::providers::sockets::SocketsProvider),
        );
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct Tagged(&'static str);
    impl CapabilityProvider for Tagged {
        fn resolve(
            &self,
            _id: &str,
            _declared: &[serde_json::Value],
            _grant: &crate::grant::CapabilityGrant,
        ) -> Result<Box<dyn CompiledCeiling>, crate::grant::PolicyError> {
            Ok(Box::new(TagCeiling(self.0)))
        }
    }
    struct TagCeiling(&'static str);
    impl CompiledCeiling for TagCeiling {
        fn classify(&self, _op: &ResourceOp) -> crate::Decision {
            crate::Decision::Deny
        }
        fn declared(&self) -> bool {
            true
        }
        fn tag(&self) -> &str {
            self.0
        }
    }

    #[test]
    fn lookup_prefers_exact_then_longest_prefix_then_generic() {
        let mut r = ProviderRegistry::new(Arc::new(Tagged("generic")));
        r.register("wasi:http", Arc::new(Tagged("http")));
        r.register("db:*", Arc::new(Tagged("db-wild")));
        r.register("db:drop-*", Arc::new(Tagged("db-drop")));
        let ceil = |id: &str| r.lookup(id).resolve(id, &[], &Default::default()).unwrap();
        assert_eq!(ceil("wasi:http").tag(), "http"); // exact
        assert_eq!(ceil("db:truncate").tag(), "db-wild"); // *-prefix
        assert_eq!(ceil("db:drop-database").tag(), "db-drop"); // longest *-prefix
        assert_eq!(ceil("email:send").tag(), "generic"); // fallback
    }
}
