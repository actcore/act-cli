//! Validate `[std.capabilities.*]` declarations at pack time so broken
//! globs / hostnames fail the build instead of silently breaking
//! enforcement at runtime.

use act_types::constants::{CAP_CREDENTIALS, CAP_FILESYSTEM, CAP_HTTP};
use act_types::types::StdCredential;
use act_types::{Capabilities, FilesystemAllow, HttpAllow};
use anyhow::{Result, bail};

pub fn validate(caps: &Capabilities, credentials: &[StdCredential]) -> Result<()> {
    if let Some(fs_req) = caps.get(CAP_FILESYSTEM) {
        let entries = fs_req
            .constraints_as::<FilesystemAllow>()
            .map_err(|e| anyhow::anyhow!("malformed wasi:filesystem constraints: {e}"))?;
        validate_fs(&entries)?;
        let mounts = caps
            .fs_mounts()
            .map_err(|e| anyhow::anyhow!("malformed wasi:filesystem params.mounts: {e}"))?;
        act_types::validate_mounts(&mounts).map_err(anyhow::Error::msg)?;
        warn_mount_issues(&mounts, &entries, caps);
    }
    if let Some(http_req) = caps.get(CAP_HTTP) {
        let rules = http_req
            .constraints_as::<HttpAllow>()
            .map_err(|e| anyhow::anyhow!("malformed wasi:http constraints: {e}"))?;
        validate_http(&rules)?;
    }
    if !credentials.is_empty() && !caps.has(CAP_CREDENTIALS) {
        bail!(
            "act.toml declares [[std.credentials]] but no act:credentials capability.\n\
             The declaration is descriptive; the capability is the gate, and an\n\
             undeclared class is always denied — so this component would be refused\n\
             its own credentials at runtime. Add:\n\n    \
             [std.capabilities.\"act:credentials\"]"
        );
    }

    // Design §4.3 rule 1: the `std:` namespace is registry-governed. A user's
    // own config file already cannot redefine a `std:` kind
    // (`KindRegistry::load`); a component is less trusted than that config and
    // must not be able to either. Without this, a component declares
    // `std:username` / `std:password`, and the prompt it produces is
    // indistinguishable from one the host wrote for a registered kind — which
    // is the phishing case §5.5 names first.
    for c in credentials {
        if c.key.starts_with("std:") {
            bail!(
                "[[std.credentials]] key '{}' is in the std: namespace, which is \
                 reserved for kinds registered in ACT-CONSTANTS. Use your own \
                 namespace, e.g. 'acme:{}'.",
                c.key,
                c.key.trim_start_matches("std:")
            );
        }
        for f in &c.fields {
            if f.key.starts_with("std:") {
                bail!(
                    "[[std.credentials.fields]] key '{}' (under '{}') is in the std: \
                     namespace, which is reserved for registered field names. A \
                     declared field must carry your own prefix so a human can see \
                     the label is yours and not the host's.",
                    f.key,
                    c.key
                );
            }
        }
    }
    Ok(())
}

fn validate_fs(entries: &[FilesystemAllow]) -> Result<()> {
    for (i, entry) in entries.iter().enumerate() {
        if entry.path.is_empty() {
            bail!("[std.capabilities.\"wasi:filesystem\"].allow[{i}].path is empty");
        }
        globset::Glob::new(&entry.path).map_err(|e| {
            anyhow::anyhow!(
                "[std.capabilities.\"wasi:filesystem\"].allow[{i}].path \
                 '{}' is not a valid glob: {e}",
                entry.path
            )
        })?;
    }
    Ok(())
}

fn validate_http(rules: &[HttpAllow]) -> Result<()> {
    for (i, rule) in rules.iter().enumerate() {
        if rule.host.is_empty() {
            bail!("[std.capabilities.\"wasi:http\"].allow[{i}].host is empty");
        }
        if let Some(scheme) = rule.scheme.as_deref()
            && !matches!(scheme, "http" | "https")
        {
            bail!(
                "[std.capabilities.\"wasi:http\"].allow[{i}].scheme \
                 '{scheme}' must be 'http' or 'https'"
            );
        }
    }
    Ok(())
}

/// Non-fatal lints: bind mounts with no covering constraint, and mount-root
/// declared alongside an explicit root mount.
fn warn_mount_issues(
    mounts: &[act_types::FilesystemMount],
    constraints: &[act_types::FilesystemAllow],
    caps: &act_types::Capabilities,
) {
    for m in mounts {
        if m.kind == act_types::MountType::Bind
            && let Some(h) = m.host.as_deref()
        {
            // Best-effort substring check (raw, unexpanded act.toml strings), not a
            // full glob-containment test — it only drives a non-fatal lint.
            let covered = constraints
                .iter()
                .any(|c| c.path.starts_with(h) || h.starts_with(trim_glob(&c.path)));
            if !covered {
                tracing::warn!(
                    host = h,
                    "bind mount host is not covered by any wasi:filesystem constraint; \
                     it will be preopened but access-denied"
                );
            }
        }
    }
    if caps.fs_mount_root().is_some() && mounts.iter().any(|m| m.kind == act_types::MountType::Root)
    {
        tracing::warn!(
            "both `mount-root` and an explicit `root` mount declared; `mount-root` is ignored"
        );
    }
}

/// Strip a trailing glob segment so a prefix comparison is meaningful
/// (`~/.ows/**` → `~/.ows`).
fn trim_glob(pattern: &str) -> &str {
    let cut = pattern.find(['*', '?', '[', '{']).unwrap_or(pattern.len());
    pattern[..cut].trim_end_matches('/')
}

#[cfg(test)]
mod mount_validate_tests {
    use super::validate;
    use act_types::{Capabilities, CapabilityRequest};
    use std::collections::BTreeMap;

    fn caps(fs_params: serde_json::Value, allow: serde_json::Value) -> Capabilities {
        let mut c = Capabilities::default();
        let mut params = BTreeMap::new();
        params.insert("mounts".to_string(), fs_params);
        c.0.insert(
            "wasi:filesystem".into(),
            CapabilityRequest {
                params,
                constraints: allow.as_array().unwrap().clone(),
                ..Default::default()
            },
        );
        c
    }

    #[test]
    fn valid_bind_with_constraint_passes() {
        let c = caps(
            serde_json::json!([{ "guest": "/ows", "host": "~/.ows" }]),
            serde_json::json!([{ "path": "~/.ows/**", "mode": "rw" }]),
        );
        assert!(validate(&c, &[]).is_ok());
    }

    #[test]
    fn bind_without_host_is_rejected() {
        let c = caps(
            serde_json::json!([{ "guest": "/ows" }]),
            serde_json::json!([{ "path": "~/.ows/**", "mode": "rw" }]),
        );
        let e = format!("{}", validate(&c, &[]).unwrap_err());
        assert!(e.contains("host"), "got: {e}");
    }

    #[test]
    fn root_with_host_is_rejected() {
        let c = caps(
            serde_json::json!([{ "type": "root", "guest": "/", "host": "/x" }]),
            serde_json::json!([{ "path": "**", "mode": "rw" }]),
        );
        assert!(validate(&c, &[]).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use act_types::{FilesystemAllow, FsMode, HttpAllow};

    #[test]
    fn valid_fs_paths_pass() {
        let entries = vec![
            FilesystemAllow {
                path: "/tmp/**".into(),
                mode: FsMode::Rw,
            },
            FilesystemAllow {
                path: "/etc/foo".into(),
                mode: FsMode::Ro,
            },
        ];
        validate_fs(&entries).expect("valid globs");
    }

    #[test]
    fn invalid_fs_glob_fails() {
        let entries = vec![FilesystemAllow {
            path: "[unclosed".into(),
            mode: FsMode::Rw,
        }];
        assert!(validate_fs(&entries).is_err());
    }

    #[test]
    fn empty_fs_path_fails() {
        let entries = vec![FilesystemAllow {
            path: String::new(),
            mode: FsMode::Rw,
        }];
        assert!(validate_fs(&entries).is_err());
    }

    #[test]
    fn valid_http_rules_pass() {
        let rules = vec![
            HttpAllow {
                host: "api.example.com".into(),
                scheme: Some("https".into()),
                methods: None,
                ports: None,
            },
            HttpAllow {
                host: "*".into(),
                scheme: None,
                methods: None,
                ports: None,
            },
        ];
        validate_http(&rules).expect("valid rules");
    }

    #[test]
    fn empty_http_host_fails() {
        let rules = vec![HttpAllow {
            host: String::new(),
            scheme: None,
            methods: None,
            ports: None,
        }];
        assert!(validate_http(&rules).is_err());
    }

    #[test]
    fn bad_scheme_fails() {
        let rules = vec![HttpAllow {
            host: "example.com".into(),
            scheme: Some("ftp".into()),
            methods: None,
            ports: None,
        }];
        assert!(validate_http(&rules).is_err());
    }

    #[test]
    fn malformed_fs_constraint_fails_validate() {
        use act_types::{Capabilities, CapabilityRequest};
        use std::collections::BTreeMap;
        // A wasi:filesystem constraint missing the required `mode` cannot parse
        // as FilesystemAllow, so the public validate() must reject it.
        let caps = Capabilities(BTreeMap::from([(
            "wasi:filesystem".to_string(),
            CapabilityRequest {
                constraints: vec![serde_json::json!({ "path": "/x/**" })],
                ..Default::default()
            },
        )]));
        assert!(validate(&caps, &[]).is_err());
    }

    #[test]
    fn credentials_without_capability_are_rejected() {
        let credentials = vec![StdCredential {
            key: "default".into(),
            ..Default::default()
        }];
        let err = validate(&Capabilities::default(), &credentials).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("act:credentials") && msg.contains("capabilit"),
            "the error must name what to add: {msg}"
        );
    }

    /// The phishing case, refused where the author can see it.
    ///
    /// A component declaring `std:username` / `std:password` produces a prompt a
    /// human cannot tell from one the host wrote for a registered kind — design
    /// §5.5 names that attack first. Note the asymmetry this closes: an
    /// operator's own config file already cannot redefine a `std:` id
    /// (`KindRegistry::load`), and a component is less trusted than that config.
    #[test]
    fn a_declared_credential_may_not_take_a_std_name() {
        use act_types::CapabilityRequest;
        let mut caps = Capabilities::default();
        caps.0
            .insert(CAP_CREDENTIALS.to_string(), CapabilityRequest::default());

        let by_key = vec![StdCredential {
            key: "std:basic".into(),
            ..Default::default()
        }];
        let msg = validate(&caps, &by_key).unwrap_err().to_string();
        assert!(
            msg.contains("std:basic") && msg.contains("namespace"),
            "{msg}"
        );

        let by_field = vec![StdCredential {
            key: "acme:login".into(),
            fields: vec![act_types::types::StdCredentialField {
                key: "std:password".into(),
                label: "GitHub password".into(),
                field_type: "std:string".into(),
                secret: true,
                required: true,
                resource: None,
                scopes: vec![],
            }],
            ..Default::default()
        }];
        let msg = validate(&caps, &by_field).unwrap_err().to_string();
        assert!(
            msg.contains("std:password") && msg.contains("namespace"),
            "a std: FIELD key must be refused too, not just a std: credential key: {msg}"
        );
    }

    #[test]
    fn credentials_with_capability_pass() {
        use act_types::CapabilityRequest;
        let mut caps = Capabilities::default();
        caps.0
            .insert(CAP_CREDENTIALS.to_string(), CapabilityRequest::default());
        let credentials = vec![StdCredential {
            key: "default".into(),
            ..Default::default()
        }];
        assert!(validate(&caps, &credentials).is_ok());
    }

    #[test]
    fn no_credentials_needs_no_capability() {
        assert!(validate(&Capabilities::default(), &[]).is_ok());
    }
}
