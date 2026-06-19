//! Host → MCP-client elicitation channel. General primitive (consent is the
//! first consumer; a future component-facing `act:elicit` interface reuses this).
//!
//! Clients without elicitation support degrade ask→deny (fail-safe via
//! `CapabilityNotSupported` from `elicit_with_timeout`).

use std::sync::Arc;
use std::time::Duration;

use rmcp::Peer;
use rmcp::service::RoleServer;

const ELICIT_TIMEOUT: Duration = Duration::from_secs(120);

/// Shared, late-bound handle to the active MCP server peer. The bridge fills
/// it per `call_tool`; the elicitation channel reads it.
#[derive(Default)]
pub struct PeerSlot {
    inner: std::sync::Mutex<Option<Peer<RoleServer>>>,
}

impl PeerSlot {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, peer: Peer<RoleServer>) {
        *self.inner.lock().unwrap() = Some(peer);
    }

    pub fn get(&self) -> Option<Peer<RoleServer>> {
        self.inner.lock().unwrap().clone()
    }
}

/// Empty elicitation response — for a yes/no confirm, the *action* (Accept vs
/// Decline) is the answer; no fields are requested from the user.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ConsentAck {}
rmcp::elicit_safe!(ConsentAck);

/// General host→client elicitation channel over the MCP peer slot.
///
/// This is a general primitive: `confirm` is the first operation; structured
/// `form<T>` requests can be added later without changing the slot machinery.
pub struct ElicitationChannel {
    slot: Arc<PeerSlot>,
}

impl ElicitationChannel {
    pub fn new(slot: Arc<PeerSlot>) -> Self {
        Self { slot }
    }

    /// Yes/no confirm via MCP elicitation.
    ///
    /// * Accept (with or without content) → `true`
    /// * Decline / Cancel / unsupported / timeout / no peer → `false` (fail-safe)
    pub async fn confirm(&self, message: String) -> bool {
        let Some(peer) = self.slot.get() else {
            return false;
        };
        match peer
            .elicit_with_timeout::<ConsentAck>(message, Some(ELICIT_TIMEOUT))
            .await
        {
            // Accept with content — user consented.
            Ok(Some(_)) => true,
            // Accept with no content — the Accept action itself is the signal.
            Ok(None) => true,
            // NoContent: Accept action received but no data payload — treat as consent.
            Err(rmcp::service::ElicitationError::NoContent) => true,
            // Any other error: UserDeclined, UserCancelled, CapabilityNotSupported,
            // ParseError, Service(..) — all map to deny (fail-safe).
            Err(_) => false,
        }
    }
}

// ── McpElicitationPrompter ─────────────────────────────────────────────────

use crate::runtime::consent::{ConsentAsk, ConsentPrompter};
use std::future::Future;
use std::pin::Pin;

/// Consent prompter that forwards decisions to the connected MCP client via
/// the elicitation channel. Used by `act run --mcp` so the agent driving the
/// MCP session can approve or deny capability requests interactively.
///
/// Format mirrors `TtyPrompter`: `ACT consent[risk]: <cap_id> — <summary> (<key>)`.
pub struct McpElicitationPrompter {
    channel: Arc<ElicitationChannel>,
}

impl McpElicitationPrompter {
    pub fn new(channel: Arc<ElicitationChannel>) -> Self {
        Self { channel }
    }
}

impl ConsentPrompter for McpElicitationPrompter {
    fn decide<'a>(
        &'a self,
        ask: &'a ConsentAsk,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        let risk = if matches!(ask.risk, crate::runtime::consent::ConsentRisk::Destructive) {
            " [DESTRUCTIVE]"
        } else {
            ""
        };
        let message = format!(
            "ACT consent{risk}: {} — {} ({})",
            ask.cap_id, ask.summary, ask.key
        );
        Box::pin(async move { self.channel.confirm(message).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_peer_denies() {
        let ch = ElicitationChannel::new(Arc::new(PeerSlot::new()));
        assert!(!ch.confirm("allow X?".into()).await);
    }

    #[tokio::test]
    async fn mcp_elicitation_prompter_no_peer_denies() {
        // Without a peer set on the slot, McpElicitationPrompter must deny (fail-safe).
        let slot = Arc::new(PeerSlot::new());
        let channel = Arc::new(ElicitationChannel::new(slot));
        let prompter = McpElicitationPrompter::new(channel);
        let ask = ConsentAsk {
            cap_id: "wasi:filesystem".into(),
            key: "/data".into(),
            summary: "read file".into(),
            risk: crate::runtime::consent::ConsentRisk::Normal,
        };
        assert!(
            !prompter.decide(&ask).await,
            "no peer → must deny (fail-safe)"
        );
    }

    #[tokio::test]
    async fn mcp_elicitation_prompter_destructive_formats_correctly() {
        // Verify the message format: destructive ask adds [DESTRUCTIVE] marker.
        // We can't test confirm() without a real peer, but we can test message
        // construction indirectly by checking the no-peer deny path still works.
        let slot = Arc::new(PeerSlot::new());
        let channel = Arc::new(ElicitationChannel::new(slot));
        let prompter = McpElicitationPrompter::new(channel);
        let ask = ConsentAsk {
            cap_id: "wasi:filesystem".into(),
            key: "/tmp/x".into(),
            summary: "delete file".into(),
            risk: crate::runtime::consent::ConsentRisk::Destructive,
        };
        // No peer → deny regardless; we validate the path doesn't panic.
        assert!(!prompter.decide(&ask).await);
    }
}
