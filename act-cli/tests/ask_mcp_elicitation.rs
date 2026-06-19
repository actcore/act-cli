//! MCP elicitation consent — automated unit guards + design note.
//!
//! ## Full roundtrip smoke test (manual)
//!
//! The fully-wired path (McpElicitationPrompter + bridge PeerSlot + real MCP
//! client responding Accept/Decline) cannot be exercised deterministically in
//! automated tests because:
//!
//!   1. Constructing a `Peer<RoleServer>` requires a live MCP transport (rmcp
//!      does not expose a mock constructor).
//!   2. Triggering an `ask`-mode capability access requires a component that
//!      declares an `ask` cap and a runtime that reaches the consent gate —
//!      none of the fixture components (time.wasm) do this.
//!
//! The no-peer→deny path is already verified by unit tests in
//! `src/runtime/elicit.rs` (`no_peer_denies`, `mcp_elicitation_prompter_no_peer_denies`).
//!
//! ## Manual smoke procedure
//!
//! 1. Build a component that declares a filesystem cap in `ask` mode and reads
//!    a file in a tool call.
//! 2. Run: `act run <component.wasm> --mcp`
//! 3. Connect an MCP client that implements `ClientHandler::create_elicitation`
//!    returning `ElicitResult::Accept(None)`.
//! 4. Call the tool — expect success (access granted).
//! 5. Reconnect with a client returning `ElicitResult::Decline`.
//! 6. Call the tool — expect `ERR_CAPABILITY_DENIED`.
//!
//! ## Capability note (no server capability needed)
//!
//! MCP elicitation is a *client* capability: the server sends elicitation
//! requests; clients advertise support in their `ClientCapabilities`. The
//! `ActRmcpBridge::get_info` does NOT need to declare a server elicitation
//! capability. When a client omits elicitation support, `elicit_with_timeout`
//! returns `CapabilityNotSupported` which our mapping converts to deny
//! (fail-safe). This is the same behaviour as the no-peer path.

// No runnable test code here — the automated guard lives in elicit.rs unit
// tests. This file documents the design contract and manual procedure for
// future reference and CI auditors.

#[test]
fn no_peer_deny_is_unit_tested_in_elicit_rs() {
    // Sentinel: this test exists so `cargo test` counts this module and CI
    // reviewers can confirm the design decision is intentional, not an oversight.
    // The actual assertion is `no_peer_denies` in src/runtime/elicit.rs.
}
