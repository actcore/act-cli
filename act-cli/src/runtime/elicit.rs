//! Host → MCP-client elicitation channel. General primitive (consent is the
//! first consumer; a future component-facing `act:elicit` interface reuses this).

// Bridge wiring is added in later tasks (consent prompter + bridge wiring).
// Until then, suppress dead_code for every item in this module.
#![allow(dead_code)]

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_peer_denies() {
        let ch = ElicitationChannel::new(Arc::new(PeerSlot::new()));
        assert!(!ch.confirm("allow X?".into()).await);
    }
}
