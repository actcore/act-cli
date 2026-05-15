//! Per-call `wasi:sockets` enforcement, installed on
//! `WasiCtxBuilder::socket_addr_check`. Hostnames are resolved at startup; the
//! resulting IPs plus CIDR rules and IP literals form the allow-set used by
//! the per-op closure.

#![allow(dead_code)] // SocketsPolicy::install wired by Task 5

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::sockets::SocketAddrUse;

use crate::config::{PolicyMode, SocketsConfig, SocketsRule};
use crate::runtime::network::cidr_contains;
use act_types::SocketProtocol;

/// Resolved policy ready to install on `WasiCtxBuilder::socket_addr_check`.
#[derive(Debug, Clone)]
pub struct SocketsPolicy {
    pub mode: PolicyMode,
    allow: Vec<CompiledRule>,
    deny: Vec<CompiledRule>,
    /// True if any rule names a host (not just CIDR / IP literal). The host
    /// wires this into `allow_ip_name_lookup`.
    any_host_rule: bool,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    /// IPs resolved from `host` at startup. Empty for CIDR-only or
    /// unresolvable rules.
    resolved_ips: Vec<IpAddr>,
    /// Set if `host` was a parseable `IpAddr`.
    ip_literal: Option<IpAddr>,
    cidr: Option<String>,
    /// Empty = "any port" (deny rules only — declarations / user-allow
    /// rules always carry ports).
    ports: Vec<u16>,
    except_ports: Vec<u16>,
    protocols: Vec<SocketProtocol>,
}

impl SocketsPolicy {
    /// Build a policy: resolve hostnames, freeze the rule set.
    pub async fn build(cfg: SocketsConfig) -> Result<Self> {
        let mut any_host_rule = false;
        let allow = Self::compile_rules(&cfg.allow, &mut any_host_rule).await?;
        let deny = Self::compile_rules(&cfg.deny, &mut any_host_rule).await?;
        Ok(Self {
            mode: cfg.mode,
            allow,
            deny,
            any_host_rule,
        })
    }

    async fn compile_rules(
        rules: &[SocketsRule],
        any_host_rule: &mut bool,
    ) -> Result<Vec<CompiledRule>> {
        let mut out = Vec::with_capacity(rules.len());
        for rule in rules {
            let mut resolved_ips: Vec<IpAddr> = Vec::new();
            let mut ip_literal: Option<IpAddr> = None;
            let mut cidr = rule.net.cidr.clone();

            if let Some(host) = &rule.net.host {
                if host == "*" {
                    // Wildcard host: encode as two match-everything CIDRs.
                    // Push the v4 form on the rule and let a clone carry v6.
                    *any_host_rule = true;
                    cidr = Some("0.0.0.0/0".to_string());
                } else if let Ok(ip) = host.parse::<IpAddr>() {
                    ip_literal = Some(ip);
                } else {
                    *any_host_rule = true;
                    if let Ok(addrs) = tokio::net::lookup_host((host.as_str(), 0u16)).await {
                        for addr in addrs {
                            resolved_ips.push(addr.ip());
                        }
                    } else {
                        tracing::warn!(
                            host = %host,
                            "wasi:sockets rule host did not resolve; rule has no effect"
                        );
                    }
                }
            }

            let compiled = CompiledRule {
                resolved_ips,
                ip_literal,
                cidr,
                ports: rule.net.ports.clone().unwrap_or_default(),
                except_ports: rule.net.except_ports.clone().unwrap_or_default(),
                protocols: rule
                    .protocols
                    .clone()
                    .unwrap_or_else(|| vec![SocketProtocol::Tcp, SocketProtocol::Udp]),
            };

            // For "*" host, also emit a v6 match-all so IPv6 connects pass.
            if rule.net.host.as_deref() == Some("*") {
                let mut v6 = compiled.clone();
                v6.cidr = Some("::/0".to_string());
                out.push(v6);
            }
            out.push(compiled);
        }
        Ok(out)
    }

    pub fn any_host_rule(&self) -> bool {
        self.any_host_rule
    }

    /// Install on a `WasiCtxBuilder` — also configures `allow_tcp(true)`,
    /// `allow_udp(true)`, and `allow_ip_name_lookup(any_host_rule)`.
    pub fn install(self, builder: &mut WasiCtxBuilder) {
        let any_host = self.any_host_rule;
        let me = Arc::new(self);
        builder
            .socket_addr_check(move |addr, reason| {
                let me = me.clone();
                Box::pin(async move { me.decide(addr, reason) })
            })
            .allow_tcp(true)
            .allow_udp(true)
            .allow_ip_name_lookup(any_host);
    }

    fn decide(&self, addr: SocketAddr, reason: SocketAddrUse) -> bool {
        let proto = proto_of(reason);

        match self.mode {
            PolicyMode::Deny => return false,
            PolicyMode::Open => return true,
            PolicyMode::Allowlist => {}
        }

        if self.deny.iter().any(|r| matches_rule(r, addr, proto)) {
            tracing::warn!(
                addr = %addr,
                ?reason,
                "blocked by ACT sockets policy (deny rule)"
            );
            return false;
        }
        if self.allow.iter().any(|r| matches_rule(r, addr, proto)) {
            tracing::debug!(addr = %addr, ?reason, "sockets policy allow");
            return true;
        }
        tracing::warn!(
            addr = %addr,
            ?reason,
            "blocked by ACT sockets policy (no allow rule matched)"
        );
        false
    }
}

fn proto_of(reason: SocketAddrUse) -> SocketProtocol {
    match reason {
        SocketAddrUse::TcpBind | SocketAddrUse::TcpConnect => SocketProtocol::Tcp,
        SocketAddrUse::UdpBind | SocketAddrUse::UdpConnect | SocketAddrUse::UdpOutgoingDatagram => {
            SocketProtocol::Udp
        }
    }
}

fn matches_rule(rule: &CompiledRule, addr: SocketAddr, proto: SocketProtocol) -> bool {
    if !rule.protocols.contains(&proto) {
        return false;
    }

    let ip = addr.ip();
    let host_or_cidr_match = rule.ip_literal == Some(ip)
        || rule.resolved_ips.contains(&ip)
        || rule
            .cidr
            .as_deref()
            .map(|c| cidr_contains(c, ip))
            .unwrap_or(false);
    if !host_or_cidr_match {
        return false;
    }

    let port = addr.port();
    if rule.except_ports.contains(&port) {
        return false;
    }
    if !rule.ports.is_empty() && !rule.ports.contains(&port) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PolicyMode, SocketsConfig, SocketsRule};
    use crate::runtime::network::NetworkRule;

    fn rule(
        host: Option<&str>,
        cidr: Option<&str>,
        ports: Option<Vec<u16>>,
        protos: Option<Vec<SocketProtocol>>,
    ) -> SocketsRule {
        SocketsRule {
            net: NetworkRule {
                host: host.map(String::from),
                cidr: cidr.map(String::from),
                ports,
                except_ports: None,
            },
            protocols: protos,
        }
    }

    #[tokio::test]
    async fn deny_mode_blocks_everything() {
        let p = SocketsPolicy::build(SocketsConfig {
            mode: PolicyMode::Deny,
            allow: vec![rule(Some("127.0.0.1"), None, Some(vec![5900]), None)],
            ..Default::default()
        })
        .await
        .unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], 5900));
        assert!(!p.decide(addr, SocketAddrUse::TcpConnect));
    }

    #[tokio::test]
    async fn open_mode_allows_everything() {
        let p = SocketsPolicy::build(SocketsConfig {
            mode: PolicyMode::Open,
            ..Default::default()
        })
        .await
        .unwrap();
        let addr = SocketAddr::from(([1, 1, 1, 1], 53));
        assert!(p.decide(addr, SocketAddrUse::UdpConnect));
    }

    #[tokio::test]
    async fn ip_literal_match() {
        let p = SocketsPolicy::build(SocketsConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![rule(
                Some("127.0.0.1"),
                None,
                Some(vec![5900]),
                Some(vec![SocketProtocol::Tcp]),
            )],
            ..Default::default()
        })
        .await
        .unwrap();
        let ok = SocketAddr::from(([127, 0, 0, 1], 5900));
        let bad_port = SocketAddr::from(([127, 0, 0, 1], 5901));
        let bad_ip = SocketAddr::from(([127, 0, 0, 2], 5900));
        assert!(p.decide(ok, SocketAddrUse::TcpConnect));
        assert!(!p.decide(bad_port, SocketAddrUse::TcpConnect));
        assert!(!p.decide(bad_ip, SocketAddrUse::TcpConnect));
    }

    #[tokio::test]
    async fn cidr_match_with_except_ports() {
        let p = SocketsPolicy::build(SocketsConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![rule(
                None,
                Some("10.0.0.0/8"),
                Some(vec![80, 443]),
                Some(vec![SocketProtocol::Tcp]),
            )],
            deny: vec![SocketsRule {
                net: NetworkRule {
                    cidr: Some("10.0.0.0/8".into()),
                    except_ports: Some(vec![443]),
                    ..Default::default()
                },
                protocols: None,
            }],
        })
        .await
        .unwrap();
        let p443 = SocketAddr::from(([10, 1, 2, 3], 443));
        let p80 = SocketAddr::from(([10, 1, 2, 3], 80));
        // 443 is excepted from the deny, so the allow can fire.
        assert!(p.decide(p443, SocketAddrUse::TcpConnect));
        // 80 matches the deny (cidr, port not excepted) → blocked.
        assert!(!p.decide(p80, SocketAddrUse::TcpConnect));
    }

    #[tokio::test]
    async fn protocol_mismatch_denied() {
        let p = SocketsPolicy::build(SocketsConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![rule(
                Some("127.0.0.1"),
                None,
                Some(vec![5900]),
                Some(vec![SocketProtocol::Tcp]),
            )],
            ..Default::default()
        })
        .await
        .unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], 5900));
        assert!(p.decide(addr, SocketAddrUse::TcpConnect));
        assert!(!p.decide(addr, SocketAddrUse::UdpConnect));
    }

    #[tokio::test]
    async fn star_host_matches_any_ip() {
        let p = SocketsPolicy::build(SocketsConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![rule(
                Some("*"),
                None,
                Some(vec![80]),
                Some(vec![SocketProtocol::Tcp]),
            )],
            ..Default::default()
        })
        .await
        .unwrap();
        assert!(p.decide(
            SocketAddr::from(([8, 8, 8, 8], 80)),
            SocketAddrUse::TcpConnect
        ));
        assert!(p.decide(
            SocketAddr::from(([192, 168, 1, 1], 80)),
            SocketAddrUse::TcpConnect
        ));
        // Wrong port — blocked even with wildcard host.
        assert!(!p.decide(
            SocketAddr::from(([8, 8, 8, 8], 81)),
            SocketAddrUse::TcpConnect
        ));
    }
}
