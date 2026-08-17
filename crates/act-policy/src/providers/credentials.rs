//! `act:credentials` decisions.
//!
//! Deliberately **not** the generic provider. That one treats an empty
//! `declared` as an unbounded ceiling, reasoning that a semantic class has no
//! physical resource to misuse. A credential is precisely such a resource: it
//! carries reach into someone else's system. So undeclared means denied, as it
//! does for filesystem, http and sockets.

use crate::Decision;
use crate::grant::{CapabilityGrant, PolicyError, PolicyMode};
use crate::provider::{CapabilityProvider, CompiledCeiling, Explained, ResourceOp};

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
        declared: &[serde_json::Value],
        grant: &CapabilityGrant,
    ) -> Result<Box<dyn CompiledCeiling>, PolicyError> {
        Ok(Box::new(CredentialsCeiling {
            declared: !declared.is_empty(),
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
            rule: Some("act:credentials".into()),
        }
    }

    fn declared(&self) -> bool {
        self.declared
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
            cap_id: "act:credentials".into(),
            key: "notion-work".into(),
            action: "get".into(),
            attrs: serde_json::Value::Null,
        }
    }

    #[tokio::test]
    async fn undeclared_is_denied_even_in_ask_mode() {
        let ceiling = CredentialsProvider
            .resolve("act:credentials", &[], &grant(PolicyMode::Ask))
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
        let declared = vec![serde_json::json!({})];
        let ceiling = CredentialsProvider
            .resolve("act:credentials", &declared, &grant(PolicyMode::Ask))
            .await
            .unwrap();
        assert_eq!(ceiling.classify(&op()), Decision::Ask);
    }

    #[tokio::test]
    async fn declared_and_denied_yields_deny() {
        let declared = vec![serde_json::json!({})];
        let ceiling = CredentialsProvider
            .resolve("act:credentials", &declared, &grant(PolicyMode::Deny))
            .await
            .unwrap();
        assert_eq!(ceiling.classify(&op()), Decision::Deny);
    }
}
