//! `act:credentials` decisions.
//!
//! Deliberately **not** the generic provider. That one treats an empty
//! `declared` as an unbounded ceiling, reasoning that a semantic class has no
//! physical resource to misuse. A credential is precisely such a resource: it
//! carries reach into someone else's system. So undeclared means denied, as it
//! does for filesystem, http and sockets.
//!
//! ## The `declared` contract
//!
//! [`CapabilityProvider::resolve`] only ever sees a capability's **constraint
//! list** (`declared: &[serde_json::Value]`), never a separate presence flag.
//! This provider derives declared-ness from that list with `!declared.is_empty()`
//! — so the contract callers MUST honor is: **`declared` is non-empty if and
//! only if `act:credentials` is present in the component's `act:component`
//! manifest.**
//!
//! That is awkward because the manifest's prescribed way to declare this
//! capability, per spec §4, is a bare table with no constraints at all:
//!
//! ```toml
//! [std.capabilities."act:credentials"]
//! ```
//!
//! which parses to `constraints: vec![]` — indistinguishable, from inside this
//! module, from "the capability was never mentioned". This provider has no way
//! to tell the two apart; it cannot see the manifest, only the slice it was
//! handed. **The caller that reads the manifest and invokes `resolve` MUST
//! pass a one-element sentinel (e.g. `vec![serde_json::json!({})]`) when the
//! bare-table form is present**, so that "declared with no constraints" and
//! "not declared" produce different slices. Fixing that call site is tracked
//! as separate follow-up work and is **not** done in this module.
//!
//! Get this wrong — pass an empty slice for a component that *did* declare
//! the capability — and every access silently downgrades to `Deny` regardless
//! of grant mode, and the audit summary reports the component as not having
//! declared a class it declared correctly. There is no error, no warning:
//! just a capability that never works and an audit trail that mis-attributes
//! why.

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
        // `vec![json!({})]` here is the sentinel described in the module docs
        // above, not a shape any real manifest produces: the bare-table form
        // `[std.capabilities."act:credentials"]` parses to an empty
        // constraint list, so a non-empty placeholder is what a caller must
        // synthesize to signal "declared". This test does not exercise that
        // caller-side wiring — see the module docs for why it can't yet.
        let declared = vec![serde_json::json!({})];
        let ceiling = CredentialsProvider
            .resolve("act:credentials", &declared, &grant(PolicyMode::Ask))
            .await
            .unwrap();
        assert_eq!(ceiling.classify(&op()), Decision::Ask);
    }

    #[tokio::test]
    async fn declared_and_denied_yields_deny() {
        // Sentinel, see comment above.
        let declared = vec![serde_json::json!({})];
        let ceiling = CredentialsProvider
            .resolve("act:credentials", &declared, &grant(PolicyMode::Deny))
            .await
            .unwrap();
        assert_eq!(ceiling.classify(&op()), Decision::Deny);
    }

    #[tokio::test]
    async fn effective_mode_reports_ask_when_declared() {
        // Sentinel, see comment on `declared_and_asked_yields_ask` above.
        let declared = vec![serde_json::json!({})];
        let ceiling = CredentialsProvider
            .resolve("act:credentials", &declared, &grant(PolicyMode::Ask))
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
            .resolve("act:credentials", &[], &grant(PolicyMode::Ask))
            .await
            .unwrap();
        assert_eq!(ceiling.effective_mode(), PolicyMode::Deny);
    }
}
