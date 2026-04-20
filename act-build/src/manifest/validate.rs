//! Validate `[std.capabilities.*]` declarations at pack time so broken
//! globs / hostnames fail the build instead of silently breaking
//! enforcement at runtime.

use act_types::{Capabilities, FilesystemCap, HttpCap};
use anyhow::{Result, bail};

pub fn validate(caps: &Capabilities) -> Result<()> {
    if let Some(fs) = caps.filesystem.as_ref() {
        validate_fs(fs)?;
    }
    if let Some(http) = caps.http.as_ref() {
        validate_http(http)?;
    }
    Ok(())
}

fn validate_fs(cap: &FilesystemCap) -> Result<()> {
    for (i, entry) in cap.allow.iter().enumerate() {
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

fn validate_http(cap: &HttpCap) -> Result<()> {
    for (i, rule) in cap.allow.iter().enumerate() {
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
        let cap = FilesystemCap {
            allow: vec![
                FilesystemAllow {
                    path: "/tmp/**".into(),
                    mode: FsMode::Rw,
                },
                FilesystemAllow {
                    path: "/etc/foo".into(),
                    mode: FsMode::Ro,
                },
            ],
            ..Default::default()
        };
        validate_fs(&cap).expect("valid globs");
    }

    #[test]
    fn invalid_fs_glob_fails() {
        let cap = FilesystemCap {
            allow: vec![FilesystemAllow {
                path: "[unclosed".into(),
                mode: FsMode::Rw,
            }],
            ..Default::default()
        };
        assert!(validate_fs(&cap).is_err());
    }

    #[test]
    fn empty_fs_path_fails() {
        let cap = FilesystemCap {
            allow: vec![FilesystemAllow {
                path: String::new(),
                mode: FsMode::Rw,
            }],
            ..Default::default()
        };
        assert!(validate_fs(&cap).is_err());
    }

    #[test]
    fn valid_http_rules_pass() {
        let cap = HttpCap {
            allow: vec![
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
            ],
        };
        validate_http(&cap).expect("valid rules");
    }

    #[test]
    fn empty_http_host_fails() {
        let cap = HttpCap {
            allow: vec![HttpAllow {
                host: String::new(),
                scheme: None,
                methods: None,
                ports: None,
            }],
        };
        assert!(validate_http(&cap).is_err());
    }

    #[test]
    fn bad_scheme_fails() {
        let cap = HttpCap {
            allow: vec![HttpAllow {
                host: "example.com".into(),
                scheme: Some("ftp".into()),
                methods: None,
                ports: None,
            }],
        };
        assert!(validate_http(&cap).is_err());
    }
}
