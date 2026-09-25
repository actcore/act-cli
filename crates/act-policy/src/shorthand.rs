//! Shorthand constraints for `--allow` / `--deny`: what a provider tells the
//! CLI about its short form. The parsing itself lives with each provider.

/// What a provider tells `--help` (and the audit hint) about its shorthand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShorthandHelp {
    /// Short name accepted wherever the class id is (`fs` for `wasi:filesystem`).
    pub alias: Option<&'static str>,
    /// Grammar of the part after `=`, e.g. `<glob>[:ro|:rw]`. Empty when the
    /// class takes no constraint.
    pub syntax: &'static str,
    /// Complete example flag values, e.g. `fs=/data/**`.
    pub examples: &'static [&'static str],
    /// Placeholder used in the audit hint, e.g. `<path>`. Empty when the class
    /// takes no constraint.
    pub placeholder: &'static str,
}

/// Host part of a network shorthand, before the class adds scheme/protocol.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetTarget {
    pub host: Option<String>,
    pub cidr: Option<String>,
    pub port: Option<u16>,
}

impl NetTarget {
    /// The `host` / `cidr` / `ports` members of a network constraint object.
    pub fn into_json(self) -> serde_json::Map<String, serde_json::Value> {
        let mut m = serde_json::Map::new();
        if let Some(h) = self.host {
            m.insert("host".into(), h.into());
        }
        if let Some(c) = self.cidr {
            m.insert("cidr".into(), c.into());
        }
        if let Some(p) = self.port {
            m.insert("ports".into(), serde_json::json!([p]));
        }
        m
    }
}

fn parse_port(p: &str) -> Result<u16, String> {
    match p.parse::<u16>() {
        Ok(n) if n > 0 => Ok(n),
        _ => Err(format!("port `{p}` is not in 1–65535")),
    }
}

/// `host`, `host:port`, `*.suffix[:port]`, `[v6]`, `[v6]:port`, or a CIDR.
///
/// IPv6 only in brackets: `fe80::1:8080` is itself a valid address, so an
/// unbracketed form cannot be read one way only. A bracketed address becomes
/// a `/128` CIDR, which the network matcher applies to IP literals.
pub fn parse_net_target(s: &str) -> Result<NetTarget, String> {
    if s.is_empty() {
        return Err("empty constraint".into());
    }
    if let Some(rest) = s.strip_prefix('[') {
        let (addr, after) = rest
            .split_once(']')
            .ok_or_else(|| "unclosed `[` in an IPv6 address".to_string())?;
        addr.parse::<std::net::Ipv6Addr>()
            .map_err(|_| format!("`{addr}` is not an IPv6 address"))?;
        let port = match after {
            "" => None,
            a => Some(parse_port(
                a.strip_prefix(':')
                    .ok_or_else(|| format!("unexpected `{a}` after `]`"))?,
            )?),
        };
        return Ok(NetTarget {
            cidr: Some(format!("{addr}/128")),
            port,
            ..Default::default()
        });
    }
    if s.contains('/') {
        if let Some((range, port)) = s.rsplit_once(':')
            && range.contains('/')
            && !port.is_empty()
            && port.bytes().all(|b| b.is_ascii_digit())
        {
            return Err("a CIDR takes no port; use --grant for ports on a range".into());
        }
        s.parse::<cidr::IpCidr>()
            .map_err(|_| format!("`{s}` is not a valid CIDR"))?;
        return Ok(NetTarget {
            cidr: Some(s.to_string()),
            ..Default::default()
        });
    }
    if s.matches(':').count() > 1 {
        let hint = match s.rsplit_once(':') {
            Some((head, tail))
                if !tail.is_empty()
                    && tail.len() <= 5
                    && tail.bytes().all(|b| b.is_ascii_digit())
                    && !head.ends_with(':') =>
            {
                format!("[{head}]:{tail}")
            }
            _ => format!("[{s}]"),
        };
        return Err(format!("put IPv6 addresses in brackets: {hint}"));
    }
    let (host, port) = match s.split_once(':') {
        Some((h, p)) => (h, Some(parse_port(p)?)),
        None => (s, None),
    };
    if host == "*" {
        return Err("a lone `*` is not a host; to allow every host, omit `=…`".into());
    }
    if host.is_empty() {
        return Err("empty host".into());
    }
    if host.strip_prefix("*.").unwrap_or(host).contains('*') {
        return Err("`*` is only allowed as a leading `*.` in a host".into());
    }
    Ok(NetTarget {
        host: Some(host.to_string()),
        port,
        ..Default::default()
    })
}

#[cfg(test)]
pub(crate) async fn assert_equivalent(
    p: &dyn crate::provider::CapabilityProvider,
    cap_id: &str,
    declared: &[serde_json::Value],
    short: &str,
    json_rule: serde_json::Value,
    ops: &[crate::provider::ResourceOp],
) {
    use crate::Decision;
    use crate::grant::{CapabilityGrant, PolicyMode};
    let grant = |rule| CapabilityGrant {
        mode: PolicyMode::Allowlist,
        allow: vec![rule],
        deny: vec![],
    };
    let parsed = p.parse_shorthand(cap_id, short).unwrap();
    let a = p
        .resolve(cap_id, Some(declared), &grant(parsed))
        .await
        .unwrap();
    let b = p
        .resolve(cap_id, Some(declared), &grant(json_rule))
        .await
        .unwrap();
    let da: Vec<_> = ops.iter().map(|o| a.classify(o)).collect();
    let db: Vec<_> = ops.iter().map(|o| b.classify(o)).collect();
    assert_eq!(da, db, "shorthand {short} diverges from its JSON");
    assert!(
        da.contains(&Decision::Allow) && da.contains(&Decision::Deny),
        "op set must exercise both outcomes for {short}: {da:?}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(host, cidr, port)` of a parsed target.
    type Parts = (Option<String>, Option<String>, Option<u16>);

    fn t(s: &str) -> Result<Parts, String> {
        parse_net_target(s).map(|n| (n.host, n.cidr, n.port))
    }

    #[test]
    fn net_target_forms() {
        assert_eq!(
            t("api.example.com").unwrap(),
            (Some("api.example.com".into()), None, None)
        );
        assert_eq!(
            t("api.example.com:443").unwrap(),
            (Some("api.example.com".into()), None, Some(443))
        );
        assert_eq!(
            t("*.github.com").unwrap(),
            (Some("*.github.com".into()), None, None)
        );
        assert_eq!(
            t("127.0.0.1:8080").unwrap(),
            (Some("127.0.0.1".into()), None, Some(8080))
        );
        assert_eq!(t("[::1]").unwrap(), (None, Some("::1/128".into()), None));
        assert_eq!(
            t("[::1]:8080").unwrap(),
            (None, Some("::1/128".into()), Some(8080))
        );
        assert_eq!(
            t("10.0.0.0/8").unwrap(),
            (None, Some("10.0.0.0/8".into()), None)
        );
        assert_eq!(
            t("fc00::/7").unwrap(),
            (None, Some("fc00::/7".into()), None)
        );
    }

    #[test]
    fn net_target_errors() {
        let e = |s| t(s).unwrap_err();
        assert_eq!(e(""), "empty constraint");
        assert_eq!(
            e("*"),
            "a lone `*` is not a host; to allow every host, omit `=…`"
        );
        assert_eq!(
            e("a.*.com"),
            "`*` is only allowed as a leading `*.` in a host"
        );
        assert_eq!(
            e("fe80::1:8080"),
            "put IPv6 addresses in brackets: [fe80::1]:8080"
        );
        assert_eq!(e("::1"), "put IPv6 addresses in brackets: [::1]");
        assert_eq!(e("[::1"), "unclosed `[` in an IPv6 address");
        assert_eq!(e("[nope]"), "`nope` is not an IPv6 address");
        assert_eq!(e("host:0"), "port `0` is not in 1–65535");
        assert_eq!(e("host:http"), "port `http` is not in 1–65535");
        assert_eq!(e("10.0.0.0/99"), "`10.0.0.0/99` is not a valid CIDR");
        assert_eq!(
            e("10.0.0.0/8:22"),
            "a CIDR takes no port; use --grant for ports on a range"
        );
    }
}
