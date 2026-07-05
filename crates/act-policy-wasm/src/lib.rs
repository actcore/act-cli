//! Browser-facing wrapper over the `act-policy` PDP. All decision logic lives
//! in `core`; this file only bridges JSON strings to/from JS.

mod core;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct PolicyKernel(core::Kernel);

#[wasm_bindgen]
impl PolicyKernel {
    /// `declared_caps_json`: the decoded `act:component` `std.capabilities` map.
    /// `policy_json`: the operator PolicyConfig.
    #[wasm_bindgen(constructor)]
    pub fn new(declared_caps_json: &str, policy_json: &str) -> Result<PolicyKernel, JsError> {
        core::Kernel::build(declared_caps_json, policy_json)
            .map(PolicyKernel)
            .map_err(|e| JsError::new(&e))
    }

    /// `op_json`: a ResourceOp `{ capId, key, action, attrs }`. Returns
    /// `"allow" | "deny" | "ask"`.
    pub fn classify(&self, op_json: &str) -> Result<String, JsError> {
        self.0
            .classify_json(op_json)
            .map(|s| s.to_string())
            .map_err(|e| JsError::new(&e))
    }

    /// Per-class `{ declared, mode }` summary for the audit-at-instantiation log.
    #[wasm_bindgen(js_name = ceilingSummary)]
    pub fn ceiling_summary(&self) -> String {
        self.0.ceiling_summary_json()
    }
}
