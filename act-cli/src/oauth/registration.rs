//! Dynamic client registration (RFC 7591), and where a registration is kept.
//!
//! **DCR, not Client ID Metadata Documents.** CIMD needs a client-metadata
//! document hosted at a stable HTTPS URL, which adds a hosted dependency to a
//! CLI and collapses every `act` installation into one OAuth client identity —
//! so one installation's revocation would be everyone's. DCR yields a
//! per-installation `client_id` with nothing hosted. It is deprecated in MCP
//! `2026-07-28` and explicitly retained for compatibility.
//!
//! **One registration per issuer, never shared across them** (SEP-2352). The
//! store is keyed by issuer for that reason, not for convenience: presenting
//! server A's `client_id` to server B tells B about A, and where the
//! registration carries a secret it hands B a credential issued by A.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// What an authorization server gave us for this installation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Registration {
    pub client_id: String,
    /// Public clients get none. When one is issued it is credential material:
    /// the file is written 0600 like the credential store, and this type has no
    /// `Display` that could put it in a log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// What was registered. A stored registration whose redirect differs from
    /// the one this run would use cannot be reused — the server will refuse it.
    pub redirect_uri: String,
}

/// Registrations by issuer.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ClientStore {
    #[serde(default)]
    by_issuer: BTreeMap<String, Registration>,
}

/// Beside the credential store, not inside it: a registration is not a
/// credential of any component's, it belongs to this installation.
pub fn store_path(root: &Path) -> PathBuf {
    root.join("oauth-clients.json")
}

impl ClientStore {
    pub fn load(root: &Path) -> Result<Self> {
        let path = store_path(root);
        match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).with_context(|| {
                format!("reading OAuth client registrations from {}", path.display())
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self, root: &Path) -> Result<()> {
        let text = serde_json::to_string_pretty(self)?;
        act_credentials::write_private(&store_path(root), text.as_bytes())
            .with_context(|| format!("writing {}", store_path(root).display()))
    }

    /// A registration for this issuer, if one exists **and** was registered for
    /// the redirect this run will use.
    pub fn get(&self, issuer: &str, redirect_uri: &str) -> Option<&Registration> {
        self.by_issuer
            .get(issuer)
            .filter(|r| r.redirect_uri == redirect_uri)
    }

    pub fn insert(&mut self, issuer: &str, reg: Registration) {
        self.by_issuer.insert(issuer.to_string(), reg);
    }
}

#[derive(Serialize)]
struct RegistrationRequest<'a> {
    client_name: &'a str,
    redirect_uris: [&'a str; 1],
    grant_types: [&'a str; 2],
    response_types: [&'a str; 1],
    token_endpoint_auth_method: &'a str,
    /// SEP-837. It is what tells a server this is a native app, which is what
    /// makes a loopback redirect acceptable to it.
    application_type: &'a str,
}

#[derive(Deserialize)]
struct RegistrationResponse {
    client_id: String,
    #[serde(default)]
    client_secret: Option<String>,
}

/// Register this installation with an authorization server.
pub async fn register(
    client: &reqwest::Client,
    endpoint: &str,
    redirect_uri: &str,
) -> Result<Registration> {
    let body = RegistrationRequest {
        client_name: "act",
        redirect_uris: [redirect_uri],
        // `refresh_token` is requested at registration because a server that
        // was not told about it at this point may refuse the grant later, and
        // the failure would surface as an expired credential nobody can renew.
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
        application_type: "native",
    };
    let resp = client
        .post(endpoint)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("registering a client at {endpoint}"))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    ensure!(
        status.is_success(),
        "{endpoint} refused the client registration with {status}"
    );
    let parsed: RegistrationResponse = serde_json::from_str(&text)
        .with_context(|| format!("{endpoint} did not answer with an RFC 7591 registration"))?;
    Ok(Registration {
        client_id: parsed.client_id,
        client_secret: parsed.client_secret,
        redirect_uri: redirect_uri.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(redirect: &str) -> Registration {
        Registration {
            client_id: "cid".into(),
            client_secret: None,
            redirect_uri: redirect.into(),
        }
    }

    #[test]
    fn a_registration_is_reused_only_for_its_own_issuer() {
        let mut s = ClientStore::default();
        s.insert("https://a.example.com", reg("http://127.0.0.1/callback"));
        assert!(
            s.get("https://a.example.com", "http://127.0.0.1/callback")
                .is_some()
        );
        assert!(
            s.get("https://b.example.com", "http://127.0.0.1/callback")
                .is_none(),
            "SEP-2352: a registration must not cross issuers"
        );
    }

    #[test]
    fn a_registration_for_a_different_redirect_is_not_reused() {
        // The server would refuse it, and the refusal arrives as an opaque
        // `invalid_request` after the browser has already opened.
        let mut s = ClientStore::default();
        s.insert("https://a.example.com", reg("http://127.0.0.1/callback"));
        assert!(
            s.get("https://a.example.com", "http://127.0.0.1:9999/cb")
                .is_none()
        );
    }

    #[test]
    fn the_store_round_trips_and_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = ClientStore::default();
        s.insert(
            "https://a.example.com",
            Registration {
                client_id: "cid".into(),
                client_secret: Some("shh".into()),
                redirect_uri: "http://127.0.0.1/callback".into(),
            },
        );
        s.save(dir.path()).unwrap();

        let back = ClientStore::load(dir.path()).unwrap();
        let r = back
            .get("https://a.example.com", "http://127.0.0.1/callback")
            .expect("round trips");
        assert_eq!(r.client_id, "cid");
        assert_eq!(r.client_secret.as_deref(), Some("shh"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store_path(dir.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "a client secret is material and the file must not be readable by others"
            );
        }
    }

    #[test]
    fn a_missing_store_is_empty_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let s = ClientStore::load(dir.path()).unwrap();
        assert!(
            s.get("https://a.example.com", "http://127.0.0.1/callback")
                .is_none()
        );
    }
}
