//! Built-in sockets provider — wraps the Stage 1 net matcher and effective_sockets.

use std::collections::BTreeMap;

use act_types::{Capabilities, CapabilityRequest, SocketProtocol};

use crate::Decision;
use crate::effective::effective_sockets;
use crate::grant::{CapabilityGrant, PolicyError, SocketsConfig, SocketsRule};
use crate::net::{NetworkCheck, rule_matches};
use crate::provider::{CapabilityProvider, CompiledCeiling, ResourceOp};

pub struct SocketsProvider;

#[async_trait::async_trait]
impl CapabilityProvider for SocketsProvider {
    async fn resolve(
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
        let is_declared = eff.declared;

        // `classify` sees the *resolved* connecting IP (wasi resolves the
        // hostname before `socket_addr_check`), so a rule naming a hostname must
        // be pinned to its IP(s) here, once, at startup. Host-only: there is no
        // DNS on wasm, and browsers have no raw sockets. Both the effective
        // allow/deny rules and the declaration rules (used for the protocol
        // ceiling check) are pinned.
        #[cfg(feature = "host")]
        let (config, decl_rules) = {
            let mut config = eff.config;
            config.allow = pin_hostnames(config.allow).await;
            config.deny = pin_hostnames(config.deny).await;
            (config, pin_hostnames(decl_rules).await)
        };
        #[cfg(not(feature = "host"))]
        let (config, decl_rules) = (eff.config, decl_rules);

        Ok(Box::new(SocketsCeiling {
            config,
            decl_rules,
            is_declared,
        }))
    }
}

/// Resolve any hostname-bearing rule to its IP(s) at startup, emitting a
/// synthetic `/32` (or `/128`) CIDR rule per resolved address (carrying the
/// original ports/protocols) so the sync `classify` can match the connecting
/// IP. The original rule is kept too (covers IP-literal and CIDR rules, and the
/// `*` wildcard). Pinning once also closes the DNS-rebinding window.
#[cfg(feature = "host")]
async fn pin_hostnames(rules: Vec<SocketsRule>) -> Vec<SocketsRule> {
    use std::net::IpAddr;
    let mut out = Vec::new();
    for rule in rules {
        if let Some(host) = rule.net.host.as_deref()
            && host != "*"
            && host.parse::<IpAddr>().is_err()
        {
            match tokio::net::lookup_host((host, 0u16)).await {
                Ok(addrs) => {
                    for addr in addrs {
                        let mut synth = rule.clone();
                        synth.net.host = None;
                        synth.net.cidr = Some(match addr.ip() {
                            IpAddr::V4(v4) => format!("{v4}/32"),
                            IpAddr::V6(v6) => format!("{v6}/128"),
                        });
                        out.push(synth);
                    }
                }
                Err(_) => tracing::warn!(
                    host = %host,
                    "wasi:sockets rule host did not resolve; rule has no effect"
                ),
            }
        }
        out.push(rule);
    }
    out
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

    fn effective_mode(&self) -> crate::grant::PolicyMode {
        self.config.mode
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

    // IP-literal rule (no DNS) → exercises host/port/protocol matching.
    #[tokio::test]
    async fn sockets_provider_matches_host_port_protocol() {
        let p = SocketsProvider;
        let declared = vec![json!({
            "host": "198.51.100.7",
            "ports": [5900],
            "protocols": ["tcp"]
        })];
        let grant = CapabilityGrant {
            mode: PolicyMode::Allowlist,
            allow: vec![json!({"host": "198.51.100.7", "ports": [5900]})],
            deny: vec![],
        };
        let c = p.resolve("wasi:sockets", &declared, &grant).await.unwrap();
        // Allowed: correct host, port, TCP protocol.
        let ok_op = ResourceOp {
            cap_id: "wasi:sockets".into(),
            key: "198.51.100.7:5900".into(),
            action: "".into(),
            attrs: json!({"protocol": "tcp"}),
        };
        assert_eq!(c.classify(&ok_op), Decision::Allow);
        // Denied: wrong protocol.
        let bad_proto_op = ResourceOp {
            cap_id: "wasi:sockets".into(),
            key: "198.51.100.7:5900".into(),
            action: "".into(),
            attrs: json!({"protocol": "udp"}),
        };
        assert_eq!(c.classify(&bad_proto_op), Decision::Deny);
    }

    // A rule names a hostname; the guest connects to the RESOLVED ip (wasi
    // resolves before `socket_addr_check`). The provider must pin the hostname
    // at resolve so `classify` (which sees the ip) still matches. `localhost`
    // resolves hermetically via the hosts file.
    #[cfg(feature = "host")]
    #[tokio::test]
    async fn sockets_provider_pins_hostname_to_resolved_ip() {
        let p = SocketsProvider;
        let declared = vec![json!({"host":"localhost","ports":[5900],"protocols":["tcp"]})];
        let grant = CapabilityGrant {
            mode: PolicyMode::Allowlist,
            allow: vec![json!({"host":"localhost","ports":[5900]})],
            deny: vec![],
        };
        let c = p.resolve("wasi:sockets", &declared, &grant).await.unwrap();
        let op = ResourceOp {
            cap_id: "wasi:sockets".into(),
            key: "127.0.0.1:5900".into(),
            action: "".into(),
            attrs: json!({"protocol": "tcp"}),
        };
        assert_eq!(c.classify(&op), Decision::Allow);
    }

    #[tokio::test]
    async fn sockets_provider_undeclared_denies_all() {
        let p = SocketsProvider;
        let grant = CapabilityGrant {
            mode: PolicyMode::Open,
            allow: vec![],
            deny: vec![],
        };
        let c = p.resolve("wasi:sockets", &[], &grant).await.unwrap();
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
