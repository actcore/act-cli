//! Built-in HTTP provider — wraps the Stage 1 HTTP net matcher and effective_http.

use std::collections::BTreeMap;

use act_types::{Capabilities, CapabilityRequest, HttpAllow};

use crate::Decision;
use crate::effective::effective_http;
use crate::grant::{CapabilityGrant, HttpConfig, HttpRule, PolicyError};
use crate::net::{NetworkCheck, rule_matches};
use crate::provider::{CapabilityProvider, CompiledCeiling, ResourceOp};

pub struct HttpProvider;

#[async_trait::async_trait]
impl CapabilityProvider for HttpProvider {
    async fn resolve(
        &self,
        cap_id: &str,
        declared: &[serde_json::Value],
        grant: &CapabilityGrant,
    ) -> Result<Box<dyn CompiledCeiling>, PolicyError> {
        let user = http_config_from_grant(grant)?;
        // Build declaration rules for method/scheme ceiling enforcement.
        let decl_rules = parse_http_rules_from_httpallow(declared)?;
        // Empty declared → don't insert key → effective_http treats as undeclared.
        let caps = caps_from_declared(cap_id, declared);
        let eff = effective_http(&user, &caps);
        Ok(Box::new(HttpCeiling {
            config: eff.config,
            decl_rules,
            is_declared: eff.declared,
        }))
    }
}

struct HttpCeiling {
    /// Effective config (grant ∩ declaration host/port filtering via effective_http).
    config: HttpConfig,
    /// Raw declaration rules — used for method/scheme ceiling enforcement.
    decl_rules: Vec<HttpRule>,
    is_declared: bool,
}

impl CompiledCeiling for HttpCeiling {
    fn classify(&self, op: &ResourceOp) -> Decision {
        let (host, port) = parse_host_port(&op.key);
        let check = NetworkCheck::new(host, port);
        let scheme = op.attrs.get("scheme").and_then(|v| v.as_str());
        let method = if op.action.is_empty() {
            None
        } else {
            Some(op.action.as_str())
        };

        match self.config.mode {
            crate::grant::PolicyMode::Deny => Decision::Deny,
            crate::grant::PolicyMode::Open => Decision::Allow,
            crate::grant::PolicyMode::Ask => {
                // Deny wins first.
                if self
                    .config
                    .deny
                    .iter()
                    .any(|r| http_rule_matches_net(r, &check, scheme))
                {
                    return Decision::Deny;
                }
                // In-ceiling: effective allow rule matches host AND declaration allows method.
                let in_ceiling = self.config.allow.iter().any(|eff_rule| {
                    http_rule_matches_net(eff_rule, &check, scheme)
                        && decl_allows_method(&self.decl_rules, &check, scheme, method)
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
                    .any(|r| http_rule_matches_net(r, &check, scheme))
                {
                    return Decision::Deny;
                }
                // Allow if effective rule matches AND declaration allows method.
                if self.config.allow.iter().any(|eff_rule| {
                    http_rule_matches_net(eff_rule, &check, scheme)
                        && decl_allows_method(&self.decl_rules, &check, scheme, method)
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

/// Check if any declaration rule allows the method for this target.
/// When `decl_rules` is empty, defaults to allowing any method.
fn decl_allows_method(
    decl_rules: &[HttpRule],
    check: &NetworkCheck,
    scheme: Option<&str>,
    method: Option<&str>,
) -> bool {
    if decl_rules.is_empty() {
        return true;
    }
    decl_rules.iter().any(|r| {
        if !rule_matches(&r.net, check) {
            return false;
        }
        if let (Some(rule_scheme), Some(req_scheme)) = (&r.scheme, scheme)
            && !rule_scheme.eq_ignore_ascii_case(req_scheme)
        {
            return false;
        }
        if let Some(allowed_methods) = &r.methods
            && let Some(req_method) = method
            && !allowed_methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(req_method))
        {
            return false;
        }
        true
    })
}

/// Network-level + scheme match for an HttpRule (no method check).
fn http_rule_matches_net(rule: &HttpRule, check: &NetworkCheck, scheme: Option<&str>) -> bool {
    if !rule_matches(&rule.net, check) {
        return false;
    }
    if let (Some(rule_scheme), Some(req_scheme)) = (&rule.scheme, scheme)
        && !rule_scheme.eq_ignore_ascii_case(req_scheme)
    {
        return false;
    }
    true
}

/// Parse "host" or "host:port" into (host, port). Defaults to port 443.
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
        return (host, 443);
    }
    // Regular "host:port"
    if let Some(colon_pos) = key.rfind(':') {
        let port_str = &key[colon_pos + 1..];
        if let Ok(port) = port_str.parse::<u16>() {
            return (&key[..colon_pos], port);
        }
    }
    (key, 443)
}

/// Convert a `CapabilityGrant` into an `HttpConfig`.
fn http_config_from_grant(grant: &CapabilityGrant) -> Result<HttpConfig, PolicyError> {
    let allow = parse_http_rules(&grant.allow)?;
    let deny = parse_http_rules(&grant.deny)?;
    Ok(HttpConfig {
        mode: grant.mode,
        allow,
        deny,
    })
}

fn parse_http_rules(cs: &[serde_json::Value]) -> Result<Vec<HttpRule>, PolicyError> {
    cs.iter()
        .map(|c| {
            serde_json::from_value::<HttpRule>(c.clone()).map_err(|e| PolicyError::Constraint {
                cap: "wasi:http",
                source: e,
            })
        })
        .collect()
}

/// Parse declared constraints as HttpAllow then map to HttpRule for method/scheme ceiling.
fn parse_http_rules_from_httpallow(
    declared: &[serde_json::Value],
) -> Result<Vec<HttpRule>, PolicyError> {
    declared
        .iter()
        .map(|c| {
            let a: HttpAllow =
                serde_json::from_value(c.clone()).map_err(|e| PolicyError::Constraint {
                    cap: "wasi:http",
                    source: e,
                })?;
            Ok(HttpRule {
                net: crate::net::NetworkRule {
                    host: Some(a.host),
                    ports: a.ports,
                    cidr: None,
                    except_ports: None,
                },
                scheme: a.scheme,
                methods: a.methods,
            })
        })
        .collect()
}

/// Build a `Capabilities` struct containing only `cap_id`'s declared constraints.
/// Empty declared → empty Capabilities → effective_http treats as undeclared.
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

    #[tokio::test]
    async fn http_provider_matches_host_and_method() {
        let p = HttpProvider;
        let declared = vec![json!({"host":"api.example.com","methods":["GET"]})];
        let grant = CapabilityGrant {
            mode: PolicyMode::Allowlist,
            allow: vec![json!({"host":"api.example.com"})],
            deny: vec![],
        };
        let c = p.resolve("wasi:http", &declared, &grant).await.unwrap();
        let op = |m: &str| ResourceOp {
            cap_id: "wasi:http".into(),
            key: "api.example.com:443".into(),
            action: m.into(),
            attrs: json!({"scheme":"https"}),
        };
        assert_eq!(c.classify(&op("GET")), Decision::Allow);
        assert_eq!(c.classify(&op("POST")), Decision::Deny); // method not declared
    }

    #[tokio::test]
    async fn http_provider_undeclared_denies_all() {
        let p = HttpProvider;
        let grant = CapabilityGrant {
            mode: PolicyMode::Open,
            allow: vec![],
            deny: vec![],
        };
        let c = p.resolve("wasi:http", &[], &grant).await.unwrap();
        let op = ResourceOp {
            cap_id: "wasi:http".into(),
            key: "api.example.com:443".into(),
            action: "GET".into(),
            attrs: json!({"scheme":"https"}),
        };
        assert_eq!(c.classify(&op), Decision::Deny);
        assert!(!c.declared());
    }

    #[tokio::test]
    async fn http_provider_ask_mode_in_ceiling() {
        let p = HttpProvider;
        let declared = vec![json!({"host":"api.example.com"})];
        let grant = CapabilityGrant {
            mode: PolicyMode::Ask,
            allow: vec![],
            deny: vec![],
        };
        let c = p.resolve("wasi:http", &declared, &grant).await.unwrap();
        // In-ceiling with Ask mode → Ask
        let in_op = ResourceOp {
            cap_id: "wasi:http".into(),
            key: "api.example.com:443".into(),
            action: "GET".into(),
            attrs: json!({"scheme":"https"}),
        };
        assert_eq!(c.classify(&in_op), Decision::Ask);
        // Out-of-ceiling with Ask mode → Deny
        let out_op = ResourceOp {
            cap_id: "wasi:http".into(),
            key: "evil.com:443".into(),
            action: "GET".into(),
            attrs: json!({"scheme":"https"}),
        };
        assert_eq!(c.classify(&out_op), Decision::Deny);
    }
}
