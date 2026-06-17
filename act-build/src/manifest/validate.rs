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
}
