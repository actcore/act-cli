//! Built-in sockets provider — wraps the Stage 1 net matcher and effective_sockets.

use std::collections::BTreeMap;

use act_types::{Capabilities, CapabilityRequest, SocketProtocol};

use crate::Decision;
use crate::effective::effective_sockets;
use crate::grant::{CapabilityGrant, PolicyError, SocketsConfig, SocketsRule};
use crate::net::{NetworkCheck, rule_matches};
use crate::provider::{CapabilityProvider, CompiledCeiling, ResourceOp};

pub struct SocketsProvider;

impl CapabilityProvider for SocketsProvider {
    fn resolve(
        &self,
        cap_id: &str,
        declared: &[serde_json::Value],
        grant: &CapabilityGrant,
    ) -> Result<Box<dyn CompiledCeiling>, PolicyError> {
        let user = sockets_config_from_grant(grant)?;
        // Build declaration rules for protocol ceiling enforcement.
        let decl_rules = parse_sockets_rules(declared)?;
        // Empty declared → don't insert key → effective_sockets treats as undeclared.
        let caps = caps_from_declared(cap_id, declared);
        let eff = effective_sockets(&user, &caps);
        Ok(Box::new(SocketsCeiling {
            config: eff.config,
            decl_rules,
            is_declared: eff.declared,
        }))
    }
}

struct SocketsCeiling {
    /// Effective config (grant ∩ declaration host/port filtering via effective_sockets).
    config: SocketsConfig,
    /// Raw declaration rules — used for protocol ceiling enforcement.
    decl_rules: Vec<SocketsRule>,
    is_declared: bool,
}

impl CompiledCeiling for SocketsCeiling {
    fn classify(&self, op: &ResourceOp) -> Decision {
        let (host, port) = parse_host_port(&op.key);
        let check = NetworkCheck::new(host, port);
        let protocol = op
            .attrs
            .get("protocol")
            .and_then(|v| v.as_str())
            .and_then(|s| match s {
                "tcp" => Some(SocketProtocol::Tcp),
                "udp" => Some(SocketProtocol::Udp),
                _ => None,
            });

        match self.config.mode {
            crate::grant::PolicyMode::Deny => Decision::Deny,
            crate::grant::PolicyMode::Open => Decision::Allow,
            crate::grant::PolicyMode::Ask => {
                // Deny wins first.
                if self
                    .config
                    .deny
                    .iter()
                    .any(|r| rule_matches(&r.net, &check))
                {
                    return Decision::Deny;
                }
                // In-ceiling: effective allow rule matches host/port AND declaration allows protocol.
                let in_ceiling = self.config.allow.iter().any(|eff_rule| {
                    rule_matches(&eff_rule.net, &check)
                        && decl_allows_protocol(&self.decl_rules, &check, protocol.as_ref())
                });
                if in_ceiling {
                    Decision::Ask
                } else {
                    Decision::Deny
                }
            }
            crate::grant::PolicyMode::Allowlist => {
                // Deny wins first.
                if self
                    .config
                    .deny
                    .iter()
                    .any(|r| rule_matches(&r.net, &check))
                {
                    return Decision::Deny;
                }
                // Allow if effective rule matches AND declaration allows protocol.
                if self.config.allow.iter().any(|eff_rule| {
                    rule_matches(&eff_rule.net, &check)
                        && decl_allows_protocol(&self.decl_rules, &check, protocol.as_ref())
                }) {
                    Decision::Allow
                } else {
                    Decision::Deny
                }
            }
        }
    }

    fn declared(&self) -> bool {
        self.is_declared
    }
}

/// Check if any declaration rule allows the protocol for this target.
/// When `decl_rules` is empty, defaults to allowing any protocol.
fn decl_allows_protocol(
    decl_rules: &[SocketsRule],
    check: &NetworkCheck,
    protocol: Option<&SocketProtocol>,
) -> bool {
    if decl_rules.is_empty() {
        return true;
    }
    decl_rules.iter().any(|r| {
        if !rule_matches(&r.net, check) {
            return false;
        }
        if let Some(allowed_protocols) = &r.protocols
            && let Some(req_protocol) = protocol
            && !allowed_protocols.contains(req_protocol)
        {
            return false;
        }
        true
    })
}

/// Parse "host" or "host:port" into (host, port). Defaults to port 0 for sockets.
fn parse_host_port(key: &str) -> (&str, u16) {
    // Handle IPv6 bracketed addresses like [::1]:8080
    if key.starts_with('[')
        && let Some(bracket_end) = key.find(']')
    {
        let host = &key[..=bracket_end];
        if let Some(port_str) = key.get(bracket_end + 2..)
            && let Ok(port) = port_str.parse::<u16>()
        {
            return (host, port);
        }
        return (host, 0);
    }
    // Regular "host:port"
    if let Some(colon_pos) = key.rfind(':') {
        let port_str = &key[colon_pos + 1..];
        if let Ok(port) = port_str.parse::<u16>() {
            return (&key[..colon_pos], port);
        }
    }
    (key, 0)
}

/// Convert a `CapabilityGrant` into a `SocketsConfig`.
fn sockets_config_from_grant(grant: &CapabilityGrant) -> Result<SocketsConfig, PolicyError> {
    let allow = parse_sockets_rules(&grant.allow)?;
    let deny = parse_sockets_rules(&grant.deny)?;
    Ok(SocketsConfig {
        mode: grant.mode,
        allow,
        deny,
    })
}

fn parse_sockets_rules(cs: &[serde_json::Value]) -> Result<Vec<SocketsRule>, PolicyError> {
    cs.iter()
        .map(|c| {
            serde_json::from_value::<SocketsRule>(c.clone()).map_err(|e| PolicyError::Constraint {
                cap: "wasi:sockets",
                source: e,
            })
        })
        .collect()
}

/// Build a `Capabilities` struct containing only `cap_id`'s declared constraints.
/// Empty declared → empty Capabilities → effective_sockets treats as undeclared.
fn caps_from_declared(cap_id: &str, declared: &[serde_json::Value]) -> Capabilities {
    if declared.is_empty() {
        return Capabilities::default();
    }
    let req = CapabilityRequest {
        constraints: declared.to_vec(),
        ..Default::default()
    };
    Capabilities(BTreeMap::from([(cap_id.to_string(), req)]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decision;
    use crate::grant::{CapabilityGrant, PolicyMode};
    use crate::provider::{CapabilityProvider, ResourceOp};
    use serde_json::json;

    #[test]
    fn sockets_provider_matches_host_port_protocol() {
        let p = SocketsProvider;
        let declared = vec![json!({
            "host": "vnc.example.com",
            "ports": [5900],
            "protocols": ["tcp"]
        })];
        let grant = CapabilityGrant {
            mode: PolicyMode::Allowlist,
            allow: vec![json!({"host": "vnc.example.com", "ports": [5900]})],
            deny: vec![],
        };
        let c = p.resolve("wasi:sockets", &declared, &grant).unwrap();
        // Allowed: correct host, port, TCP protocol.
        let ok_op = ResourceOp {
            cap_id: "wasi:sockets".into(),
            key: "vnc.example.com:5900".into(),
            action: "".into(),
            attrs: json!({"protocol": "tcp"}),
        };
        assert_eq!(c.classify(&ok_op), Decision::Allow);
        // Denied: wrong protocol.
        let bad_proto_op = ResourceOp {
            cap_id: "wasi:sockets".into(),
            key: "vnc.example.com:5900".into(),
            action: "".into(),
            attrs: json!({"protocol": "udp"}),
        };
        assert_eq!(c.classify(&bad_proto_op), Decision::Deny);
    }

    #[test]
    fn sockets_provider_undeclared_denies_all() {
        let p = SocketsProvider;
        let grant = CapabilityGrant {
            mode: PolicyMode::Open,
            allow: vec![],
            deny: vec![],
        };
        let c = p.resolve("wasi:sockets", &[], &grant).unwrap();
        let op = ResourceOp {
            cap_id: "wasi:sockets".into(),
            key: "host.example.com:5900".into(),
            action: "".into(),
            attrs: json!({"protocol": "tcp"}),
        };
        assert_eq!(c.classify(&op), Decision::Deny);
        assert!(!c.declared());
    }
}
