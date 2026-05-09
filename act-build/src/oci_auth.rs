//! Resolve `RegistryAuth` for a given OCI registry host.
//!
//! Lookup order:
//! 1. `OCI_USERNAME` + `OCI_PASSWORD` env vars (registry-agnostic)
//! 2. `~/.docker/config.json` (or `$DOCKER_CONFIG/config.json`) — `auths.<registry>.auth`
//!    is a base64'd `username:password`
//! 3. `Anonymous`
//!
//! GHCR special case: if `OCI_USERNAME` is unset but `GITHUB_TOKEN` is set,
//! treat it as a Bearer-equivalent basic auth (`username = $GITHUB_ACTOR`,
//! `password = $GITHUB_TOKEN`) — matches what `oras login ghcr.io` does
//! in CI.

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use oci_client::secrets::RegistryAuth;
use serde::Deserialize;
use std::path::PathBuf;

/// Resolve auth for the given registry host (e.g. `"ghcr.io"`).
pub fn resolve(registry: &str) -> Result<RegistryAuth> {
    if let (Ok(user), Ok(pass)) = (std::env::var("OCI_USERNAME"), std::env::var("OCI_PASSWORD")) {
        tracing::debug!(%registry, "using OCI_USERNAME/OCI_PASSWORD env credentials");
        return Ok(RegistryAuth::Basic(user, pass));
    }

    if registry == "ghcr.io"
        && let Ok(token) = std::env::var("GITHUB_TOKEN")
    {
        let actor = std::env::var("GITHUB_ACTOR").unwrap_or_else(|_| "oauth2".to_string());
        tracing::debug!(%registry, %actor, "using GITHUB_TOKEN for ghcr.io");
        return Ok(RegistryAuth::Basic(actor, token));
    }

    if let Some(auth) = from_docker_config(registry)? {
        tracing::debug!(%registry, "using docker config credentials");
        return Ok(auth);
    }

    tracing::debug!(%registry, "no credentials found, using anonymous auth");
    Ok(RegistryAuth::Anonymous)
}

#[derive(Deserialize)]
struct DockerConfig {
    #[serde(default)]
    auths: std::collections::HashMap<String, DockerAuthEntry>,
}

#[derive(Deserialize)]
struct DockerAuthEntry {
    #[serde(default)]
    auth: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

fn docker_config_path() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("DOCKER_CONFIG") {
        return Some(PathBuf::from(dir).join("config.json"));
    }
    dirs::home_dir().map(|h| h.join(".docker").join("config.json"))
}

fn from_docker_config(registry: &str) -> Result<Option<RegistryAuth>> {
    let Some(path) = docker_config_path() else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }
    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let cfg: DockerConfig = serde_json::from_str(&raw)
        .with_context(|| format!("parsing {} as JSON", path.display()))?;

    // Try exact-match first, then a few normalized variants.
    let candidates = [
        registry.to_string(),
        format!("https://{registry}"),
        format!("https://{registry}/v1/"),
    ];
    for key in candidates {
        if let Some(entry) = cfg.auths.get(&key) {
            return decode_entry(entry, &path);
        }
    }
    Ok(None)
}

fn decode_entry(entry: &DockerAuthEntry, path: &std::path::Path) -> Result<Option<RegistryAuth>> {
    if let Some(b64) = &entry.auth {
        let decoded = B64
            .decode(b64.trim())
            .with_context(|| format!("decoding base64 auth in {}", path.display()))?;
        let s = std::str::from_utf8(&decoded)
            .with_context(|| format!("auth in {} is not valid UTF-8", path.display()))?;
        let (user, pass) = s
            .split_once(':')
            .with_context(|| format!("auth in {} is not 'user:pass'", path.display()))?;
        return Ok(Some(RegistryAuth::Basic(
            user.to_string(),
            pass.to_string(),
        )));
    }
    if let (Some(u), Some(p)) = (&entry.username, &entry.password) {
        return Ok(Some(RegistryAuth::Basic(u.clone(), p.clone())));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_docker_config(dir: &std::path::Path, contents: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("config.json"), contents).unwrap();
    }

    /// Test the `from_docker_config` path by setting `DOCKER_CONFIG`.
    /// Note: env vars are global — this test must run in isolation.
    #[test]
    fn parses_docker_config_basic_auth() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join(".docker");
        // base64("alice:s3cret") = YWxpY2U6czNjcmV0
        write_docker_config(
            &dir,
            r#"{"auths": {"ghcr.io": {"auth": "YWxpY2U6czNjcmV0"}}}"#,
        );
        // SAFETY: test runs single-threaded with respect to its env mutations;
        // we restore on drop via a guard.
        let _guard = EnvGuard::set("DOCKER_CONFIG", dir.to_str().unwrap());
        let _user_guard = EnvGuard::unset("OCI_USERNAME");
        let _pass_guard = EnvGuard::unset("OCI_PASSWORD");
        let _gh_guard = EnvGuard::unset("GITHUB_TOKEN");

        let auth = resolve("ghcr.io").unwrap();
        match auth {
            RegistryAuth::Basic(u, p) => {
                assert_eq!(u, "alice");
                assert_eq!(p, "s3cret");
            }
            other => panic!("expected Basic, got {other:?}"),
        }
    }

    /// RAII guard that restores env vars on drop. Tests using env are inherently
    /// non-isolated under cargo's threaded runner, but the guard at least keeps
    /// state scoped to the test body.
    struct EnvGuard {
        key: String,
        prev: Option<String>,
    }
    impl EnvGuard {
        fn set(key: &str, value: &str) -> Self {
            let prev = std::env::var(key).ok();
            // SAFETY: setting env is safe in single-threaded test context.
            unsafe { std::env::set_var(key, value) };
            Self {
                key: key.into(),
                prev,
            }
        }
        fn unset(key: &str) -> Self {
            let prev = std::env::var(key).ok();
            unsafe { std::env::remove_var(key) };
            Self {
                key: key.into(),
                prev,
            }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.prev {
                    Some(v) => std::env::set_var(&self.key, v),
                    None => std::env::remove_var(&self.key),
                }
            }
        }
    }
}
