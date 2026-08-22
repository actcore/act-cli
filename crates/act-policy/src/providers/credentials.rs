//! `act:credentials` decisions.
//!
//! Deliberately **not** the generic provider — although since the
//! manifest-is-the-ceiling rule the two now agree on undeclared access, this
//! provider keeps its own typed ceiling and declaredness reporting.
//!
//! A credential is a resource that carries reach into someone else's system,
//! so undeclared means denied, as it does for filesystem, http and sockets.
//! `declared.is_some()` is the whole test: the caller passes `Some(&[])` for
//! the prescribed bare-table form and `None` when the class is absent.

use crate::Decision;
use crate::grant::{CapabilityGrant, PolicyError, PolicyMode};
use crate::provider::{CapabilityProvider, CompiledCeiling, Explained, ResourceOp};

/// The `act:credentials` capability id. Mirrors `act_types::constants::CAP_CREDENTIALS`
/// (act-sdk-rs) — that is the ecosystem-wide canonical constant, but act-cli's
/// `act-types` dependency predates it, so this crate-local copy is what the
/// registration site (`provider.rs::with_builtins`) and callers within this
/// workspace (e.g. `act-cli::runtime::create_store`) actually use today.
/// Replace both with the `act_types` constant once the workspace dependency
/// is bumped past the release that carries it.
pub const CAP_CREDENTIALS: &str = "act:credentials";

pub struct CredentialsProvider;

pub struct CredentialsCeiling {
    declared: bool,
    mode: PolicyMode,
}

#[async_trait::async_trait]
impl CapabilityProvider for CredentialsProvider {
    async fn resolve(
        &self,
        _cap_id: &str,
        declared: Option<&[serde_json::Value]>,
        grant: &CapabilityGrant,
    ) -> Result<Box<dyn CompiledCeiling>, PolicyError> {
        let declared = declared.is_some();
        Ok(Box::new(CredentialsCeiling {
            declared,
            mode: grant.mode,
        }))
    }
}

impl CompiledCeiling for CredentialsCeiling {
    fn classify(&self, _op: &ResourceOp) -> Decision {
        if !self.declared {
            return Decision::Deny;
        }
        match self.mode {
            PolicyMode::Deny => Decision::Deny,
            PolicyMode::Ask => Decision::Ask,
            PolicyMode::Open | PolicyMode::Allowlist => Decision::Allow,
        }
    }

    fn classify_explained(&self, _op: &ResourceOp) -> Explained {
        if !self.declared {
            return Explained {
                decision: Decision::Deny,
                rule: Some("act:credentials not declared in act:component".into()),
            };
        }
        let decision = match self.mode {
            PolicyMode::Deny => Decision::Deny,
            PolicyMode::Ask => Decision::Ask,
            PolicyMode::Open | PolicyMode::Allowlist => Decision::Allow,
        };
        Explained {
            decision,
            rule: Some(CAP_CREDENTIALS.into()),
        }
    }

    fn declared(&self) -> bool {
        self.declared
    }

    fn effective_mode(&self) -> PolicyMode {
        if self.declared {
            self.mode
        } else {
            PolicyMode::Deny
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::PolicyMode;

    fn grant(mode: PolicyMode) -> CapabilityGrant {
        CapabilityGrant {
            mode,
            allow: vec![],
            deny: vec![],
        }
    }

    fn op() -> ResourceOp {
        ResourceOp {
            cap_id: CAP_CREDENTIALS.into(),
            key: "notion-work".into(),
            action: "get".into(),
            attrs: serde_json::Value::Null,
        }
    }

    #[tokio::test]
    async fn undeclared_is_denied_even_in_ask_mode() {
        let ceiling = CredentialsProvider
            .resolve(CAP_CREDENTIALS, None, &grant(PolicyMode::Ask))
            .await
            .unwrap();
        assert_eq!(
            ceiling.classify(&op()),
            Decision::Deny,
            "a credential is a resource to misuse; undeclared must not become Ask"
        );
    }

    #[tokio::test]
    async fn declared_and_asked_yields_ask() {
        // `act:credentials` has no constraint schema of its own, so
        // `vec![json!({})]` is just a non-empty placeholder standing in for
        // "declared" — the class's only real signal, per the module docs, is
        // `declared.is_some()`, not anything inside the slice.
        let declared = vec![serde_json::json!({})];
        let ceiling = CredentialsProvider
            .resolve(CAP_CREDENTIALS, Some(&declared), &grant(PolicyMode::Ask))
            .await
            .unwrap();
        assert_eq!(ceiling.classify(&op()), Decision::Ask);
    }

    #[tokio::test]
    async fn declared_and_denied_yields_deny() {
        // Placeholder constraint, see comment above.
        let declared = vec![serde_json::json!({})];
        let ceiling = CredentialsProvider
            .resolve(CAP_CREDENTIALS, Some(&declared), &grant(PolicyMode::Deny))
            .await
            .unwrap();
        assert_eq!(ceiling.classify(&op()), Decision::Deny);
    }

    #[tokio::test]
    async fn effective_mode_reports_ask_when_declared() {
        // Placeholder constraint, see comment on `declared_and_asked_yields_ask` above.
        let declared = vec![serde_json::json!({})];
        let ceiling = CredentialsProvider
            .resolve(CAP_CREDENTIALS, Some(&declared), &grant(PolicyMode::Ask))
            .await
            .unwrap();
        assert_eq!(ceiling.effective_mode(), PolicyMode::Ask);
    }

    #[tokio::test]
    async fn effective_mode_reports_deny_when_undeclared() {
        // Even though the grant itself is in Ask mode, an undeclared
        // capability's effective mode must still read as Deny — otherwise
        // the audit trail renders a mode the component was never actually
        // granted.
        let ceiling = CredentialsProvider
            .resolve(CAP_CREDENTIALS, None, &grant(PolicyMode::Ask))
            .await
            .unwrap();
        assert_eq!(ceiling.effective_mode(), PolicyMode::Deny);
    }

    #[tokio::test]
    async fn bare_declaration_is_declared_and_absent_is_not() {
        // The prescribed manifest form is a bare table with no constraints:
        //   [std.capabilities."act:credentials"]
        // which must be distinguishable from never mentioning the class at all.
        let bare = CredentialsProvider
            .resolve(CAP_CREDENTIALS, Some(&[]), &grant(PolicyMode::Ask))
            .await
            .unwrap();
        assert!(
            bare.declared(),
            "a bare declaration is a declaration, not an absence"
        );

        let absent = CredentialsProvider
            .resolve(CAP_CREDENTIALS, None, &grant(PolicyMode::Ask))
            .await
            .unwrap();
        assert!(!absent.declared(), "an absent class is undeclared");
    }
}
