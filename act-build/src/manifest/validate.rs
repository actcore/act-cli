//! Validate `[std.capabilities.*]` declarations at pack time so broken
//! globs / hostnames fail the build instead of silently breaking
//! enforcement at runtime.

use act_types::constants::{CAP_FILESYSTEM, CAP_HTTP};
use act_types::{Capabilities, FilesystemAllow, HttpAllow};
use anyhow::{Result, bail};

pub fn validate(caps: &Capabilities) -> Result<()> {
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
        assert!(validate(&c).is_ok());
    }

    #[test]
    fn bind_without_host_is_rejected() {
        let c = caps(
            serde_json::json!([{ "guest": "/ows" }]),
            serde_json::json!([{ "path": "~/.ows/**", "mode": "rw" }]),
        );
        let e = format!("{}", validate(&c).unwrap_err());
        assert!(e.contains("host"), "got: {e}");
    }

    #[test]
    fn root_with_host_is_rejected() {
        let c = caps(
            serde_json::json!([{ "type": "root", "guest": "/", "host": "/x" }]),
            serde_json::json!([{ "path": "**", "mode": "rw" }]),
        );
        assert!(validate(&c).is_err());
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
        assert!(validate(&caps).is_err());
    }
}
