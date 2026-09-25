//! Built-in HTTP provider — wraps the Stage 1 HTTP net matcher and `effective_http`.

use std::collections::BTreeMap;

use act_types::{Capabilities, CapabilityRequest, HttpAllow};

use crate::Decision;
use crate::effective::effective_http;
use crate::grant::{CapabilityGrant, HttpConfig, HttpRule, PolicyError};
use crate::net::{NetworkCheck, rule_matches};
use crate::provider::{CapabilityProvider, CompiledCeiling, Explained, ResourceOp};

pub struct HttpProvider;

#[async_trait::async_trait]
impl CapabilityProvider for HttpProvider {
    fn shorthand_help(&self) -> Option<crate::shorthand::ShorthandHelp> {
        Some(crate::shorthand::ShorthandHelp {
            alias: Some("http"),
            syntax: "[scheme://]host[:port]",
            examples: &["http=api.example.com", "http=https://*.github.com"],
            placeholder: "<host>",
        })
    }

    /// An http allow rule without a host never survives the intersection
    /// with the component's ceiling (declared http rules are hosts), so a
    /// CIDR there would grant nothing. As a deny it works — the resolver
    /// filter and IP literals honour it — so only the allow side refuses it.
    fn parse_shorthand_rule(
        &self,
        cap_id: &str,
        s: &str,
        side: crate::shorthand::RuleSide,
    ) -> Result<serde_json::Value, PolicyError> {
        let rule = self.parse_shorthand(cap_id, s)?;
        if side == crate::shorthand::RuleSide::Allow && rule.get("host").is_none() {
            return Err(PolicyError::Shorthand(
                "an http allow rule is matched against hosts; a CIDR range would grant nothing — name a host (a range can be denied)".into(),
            ));
        }
        Ok(rule)
    }

    fn parse_shorthand(&self, _cap_id: &str, s: &str) -> Result<serde_json::Value, PolicyError> {
        let (scheme, rest) = match s.split_once("://") {
            Some((sc, r)) if sc == "http" || sc == "https" => (Some(sc), r),
            Some((sc, _)) => {
                return Err(PolicyError::Shorthand(format!(
                    "unknown scheme `{sc}` (expected `http` or `https`)"
                )));
            }
            None => (None, s),
        };
        // A path after the authority makes this a URL, not a grant. A CIDR
        // also contains `/`, so only a non-CIDR tail counts as a path.
        let search_from = if rest.starts_with('[') {
            rest.find(']').unwrap_or(0)
        } else {
            0
        };
        if let Some(i) = rest[search_from..].find('/').map(|i| i + search_from)
            && rest.parse::<cidr::IpCidr>().is_err()
        {
            return Err(PolicyError::Shorthand(format!(
                "a path is not part of an http grant; drop `{}`",
                &rest[i..]
            )));
        }
        let target = crate::shorthand::parse_net_target(rest).map_err(PolicyError::Shorthand)?;
        // `Uri::host()` keeps IPv6 brackets, and hosts are compared as
        // strings, so a bracketed address stays a bracketed host.
        let mut m = if rest.starts_with('[') {
            let bracketed = &rest[..=rest.find(']').unwrap_or(0)];
            let mut m = serde_json::Map::new();
            m.insert("host".into(), bracketed.into());
            if let Some(p) = target.port {
                m.insert("ports".into(), serde_json::json!([p]));
            }
            m
        } else {
            target.into_json()
        };
        if let Some(sc) = scheme {
            m.insert("scheme".into(), sc.into());
        }
        Ok(serde_json::Value::Object(m))
    }

    async fn resolve(
        &self,
        cap_id: &str,
        declared: Option<&[serde_json::Value]>,
        grant: &CapabilityGrant,
    ) -> Result<Box<dyn CompiledCeiling>, PolicyError> {
        let declared = declared.unwrap_or(&[]);
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
    /// Effective config (grant ∩ declaration host/port filtering via `effective_http`).
    config: HttpConfig,
    /// Raw declaration rules — used for method/scheme ceiling enforcement.
    decl_rules: Vec<HttpRule>,
    is_declared: bool,
}

impl HttpCeiling {
    /// The same mode-dispatch `classify` used to run, but returning the
    /// matching effective allow rule (rendered as a string) alongside the
    /// decision. Both trait methods are expressed in terms of this so the
    /// decision output cannot drift between them.
    fn matched(&self, op: &ResourceOp) -> (Decision, Option<String>) {
        let (host, port) = parse_host_port(&op.key);
        let check = NetworkCheck::new(host, port);
        let scheme = op.attrs.get("scheme").and_then(|v| v.as_str());
        let method = if op.action.is_empty() {
            None
        } else {
            Some(op.action.as_str())
        };

        match self.config.mode {
            crate::grant::PolicyMode::Deny => (Decision::Deny, None),
            crate::grant::PolicyMode::Open => (Decision::Allow, None),
            crate::grant::PolicyMode::Ask => {
                // Deny wins first.
                if self
                    .config
                    .deny
                    .iter()
                    .any(|r| http_rule_matches_net(r, &check, scheme))
                {
                    return (Decision::Deny, None);
                }
                // In-ceiling: effective allow rule matches host AND declaration allows method.
                match self.config.allow.iter().find(|eff_rule| {
                    http_rule_matches_net(eff_rule, &check, scheme)
                        && decl_allows_method(&self.decl_rules, &check, scheme, method)
                }) {
                    Some(rule) => (Decision::Ask, Some(render_http_rule(rule))),
                    None => (Decision::Deny, None),
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
                    return (Decision::Deny, None);
                }
                // Allow if effective rule matches AND declaration allows method.
                match self.config.allow.iter().find(|eff_rule| {
                    http_rule_matches_net(eff_rule, &check, scheme)
                        && decl_allows_method(&self.decl_rules, &check, scheme, method)
                }) {
                    Some(rule) => (Decision::Allow, Some(render_http_rule(rule))),
                    None => (Decision::Deny, None),
                }
            }
        }
    }
}

impl CompiledCeiling for HttpCeiling {
    fn classify(&self, op: &ResourceOp) -> Decision {
        self.matched(op).0
    }

    fn classify_explained(&self, op: &ResourceOp) -> Explained {
        let (decision, rule) = self.matched(op);
        Explained { decision, rule }
    }

    fn declared(&self) -> bool {
        self.is_declared
    }

    fn effective_mode(&self) -> crate::grant::PolicyMode {
        self.config.mode
    }
}

/// Render an `HttpRule` as a human-readable rule label for the audit
/// rollup: the host pattern it anchors on, or the CIDR if host-less.
fn render_http_rule(rule: &HttpRule) -> String {
    rule.net
        .host
        .clone()
        .or_else(|| rule.net.cidr.clone())
        .unwrap_or_else(|| "*".to_string())
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

/// Network-level + scheme match for an `HttpRule` (no method check).
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

/// Parse declared constraints as `HttpAllow` then map to `HttpRule` for method/scheme ceiling.
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
/// Empty declared → empty Capabilities → `effective_http` treats as undeclared.
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
    use crate::shorthand::RuleSide;
    use serde_json::json;

    fn http_sh(s: &str) -> Result<serde_json::Value, String> {
        HttpProvider
            .parse_shorthand("wasi:http", s)
            .map_err(|e| e.to_string())
    }

    #[test]
    fn http_shorthand_forms_and_errors() {
        assert_eq!(
            http_sh("api.example.com").unwrap(),
            json!({"host":"api.example.com"})
        );
        assert_eq!(
            http_sh("https://api.example.com").unwrap(),
            json!({"host":"api.example.com","scheme":"https"})
        );
        // IPv6 stays bracketed: `Uri::host()` yields `[::1]`, and the host
        // matcher compares that string.
        assert_eq!(
            http_sh("http://[::1]:8080").unwrap(),
            json!({"host":"[::1]","ports":[8080],"scheme":"http"})
        );
        assert_eq!(
            http_sh("127.0.0.1:8080").unwrap(),
            json!({"host":"127.0.0.1","ports":[8080]})
        );
        // An http allow rule without a host is dropped by the ceiling
        // intersection, so a CIDR here would grant nothing: refuse it.
        assert_eq!(
            HttpProvider
                .parse_shorthand_rule("wasi:http", "10.0.0.0/8", RuleSide::Allow)
                .unwrap_err()
                .to_string(),
            "an http allow rule is matched against hosts; a CIDR range would grant nothing — name a host (a range can be denied)"
        );
        // A CIDR deny does work (the resolver filter and IP literals), and is
        // the spelling-proof way to block e.g. the metadata service.
        assert_eq!(
            HttpProvider
                .parse_shorthand_rule("wasi:http", "169.254.0.0/16", RuleSide::Deny)
                .unwrap(),
            json!({"cidr":"169.254.0.0/16"})
        );
        assert_eq!(
            http_sh("ftp://x.com").unwrap_err(),
            "unknown scheme `ftp` (expected `http` or `https`)"
        );
        assert_eq!(
            http_sh("https://api.example.com/v1").unwrap_err(),
            "a path is not part of an http grant; drop `/v1`"
        );
    }

    #[test]
    fn http_shorthand_help() {
        let h = HttpProvider.shorthand_help().unwrap();
        assert_eq!((h.alias, h.placeholder), (Some("http"), "<host>"));
    }

    #[tokio::test]
    async fn http_shorthand_is_equivalent_to_json() {
        // Declared ceilings take hosts only (`HttpAllow`); CIDRs appear in grants.
        let declared = vec![
            json!({"host":"api.example.com"}),
            json!({"host":"[::1]"}),
            json!({"host":"[::2]"}),
        ];
        let op = |host: &str, port: u16, scheme: &str| ResourceOp {
            cap_id: "wasi:http".into(),
            key: format!("{host}:{port}"),
            action: "GET".into(),
            attrs: json!({"scheme": scheme}),
        };
        let ops = [
            op("api.example.com", 443, "https"),
            op("api.example.com", 80, "http"),
            op("evil.example.net", 443, "https"),
            op("[::1]", 8080, "http"),
            op("[::2]", 8080, "http"),
        ];
        for (short, json_rule) in [
            ("api.example.com", json!({"host":"api.example.com"})),
            (
                "https://api.example.com:443",
                json!({"host":"api.example.com","ports":[443],"scheme":"https"}),
            ),
            ("[::1]:8080", json!({"host":"[::1]","ports":[8080]})),
        ] {
            crate::shorthand::assert_equivalent(
                &HttpProvider,
                "wasi:http",
                &declared,
                short,
                json_rule,
                &ops,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn http_provider_matches_host_and_method() {
        let p = HttpProvider;
        let declared = vec![json!({"host":"api.example.com","methods":["GET"]})];
        let grant = CapabilityGrant {
            mode: PolicyMode::Allowlist,
            allow: vec![json!({"host":"api.example.com"})],
            deny: vec![],
        };
        let c = p
            .resolve("wasi:http", Some(&declared), &grant)
            .await
            .unwrap();
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
        let c = p.resolve("wasi:http", None, &grant).await.unwrap();
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
        let c = p
            .resolve("wasi:http", Some(&declared), &grant)
            .await
            .unwrap();
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
