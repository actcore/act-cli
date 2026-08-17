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

/// A capability class's decision logic. Object-safe; held as `dyn` in the
/// registry. `resolve` is async so a provider can do startup work that needs
/// I/O (e.g. the sockets provider resolves hostname rules via DNS, pinning the
/// IPs once). `classify` stays sync — it runs on the hot path.
#[async_trait::async_trait]
pub trait CapabilityProvider: Send + Sync {
    async fn resolve(
        &self,
        cap_id: &str,
        declared: &[serde_json::Value],
        grant: &CapabilityGrant,
    ) -> Result<Box<dyn CompiledCeiling>, PolicyError>;
}

/// A decision plus, when the provider can attribute one, the ceiling rule
/// that produced it. Used by the host's audit rollup to group permitted
/// operations under the grant that allowed them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explained {
    pub decision: Decision,
    pub rule: Option<String>,
}

/// The compiled ceiling for one class in one run. Pure, sync, wasm-clean.
pub trait CompiledCeiling: Send + Sync {
    fn classify(&self, op: &ResourceOp) -> Decision;
    /// `classify`, plus the rule that matched. Defaulted so providers that
    /// cannot attribute a rule (or have not been updated) keep working; the
    /// audit rollup degrades to grouping by capability and action.
    fn classify_explained(&self, op: &ResourceOp) -> Explained {
        Explained {
            decision: self.classify(op),
            rule: None,
        }
    }
    fn declared(&self) -> bool;
    /// Effective policy mode for this ceiling. Used by hosts that need to
    /// know the mode for non-classify decisions (e.g. p3 preopens kill-switch).
    fn effective_mode(&self) -> crate::grant::PolicyMode {
        crate::grant::PolicyMode::Deny
    }
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
        r.register(
            "act:credentials",
            Arc::new(crate::providers::credentials::CredentialsProvider),
        );
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct Tagged(&'static str);
    #[async_trait::async_trait]
    impl CapabilityProvider for Tagged {
        async fn resolve(
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

    #[tokio::test]
    async fn lookup_prefers_exact_then_longest_prefix_then_generic() {
        let mut r = ProviderRegistry::new(Arc::new(Tagged("generic")));
        r.register("wasi:http", Arc::new(Tagged("http")));
        r.register("db:*", Arc::new(Tagged("db-wild")));
        r.register("db:drop-*", Arc::new(Tagged("db-drop")));
        async fn tag(r: &ProviderRegistry, id: &str) -> String {
            r.lookup(id)
                .resolve(id, &[], &Default::default())
                .await
                .unwrap()
                .tag()
                .to_string()
        }
        assert_eq!(tag(&r, "wasi:http").await, "http"); // exact
        assert_eq!(tag(&r, "db:truncate").await, "db-wild"); // *-prefix
        assert_eq!(tag(&r, "db:drop-database").await, "db-drop"); // longest *-prefix
        assert_eq!(tag(&r, "email:send").await, "generic"); // fallback
    }

    #[tokio::test]
    async fn credentials_provider_is_registered_not_generic_fallback() {
        let r = ProviderRegistry::with_builtins();
        let provider = r.lookup("act:credentials");
        // If credentials provider is not registered, lookup would return the
        // generic fallback. We verify by checking that resolving with an empty
        // declared set in Ask mode yields Deny (credentials provider behavior),
        // not Ask (generic provider behavior which treats undeclared as unbounded).
        let ask_grant = crate::grant::CapabilityGrant {
            mode: crate::grant::PolicyMode::Ask,
            allow: vec![],
            deny: vec![],
        };
        let ceiling = provider
            .resolve("act:credentials", &[], &ask_grant)
            .await
            .unwrap();
        let cred_op = ResourceOp {
            cap_id: "act:credentials".into(),
            key: "test-cred".into(),
            action: "get".into(),
            attrs: serde_json::Value::Null,
        };
        assert_eq!(
            ceiling.classify(&cred_op),
            crate::Decision::Deny,
            "act:credentials provider must deny undeclared access in Ask mode, not defer to generic fallback which would return Ask"
        );
    }
}
