//! `act-cli`'s answer to [`act_runtime::credentials::CredentialRefresher`].
//!
//! The runtime knows a stored credential is near expiry and carries an issuer;
//! it does not know what an authorization server is. This is the piece that
//! does — and it lives here, on the far side of the seam, because a host
//! embedding `act-runtime` against some other kind of upstream should be able
//! to renew credentials without inheriting an OAuth stack.

use std::path::PathBuf;
use std::sync::Arc;

use act_runtime::credentials::{CredentialRefresher, RefreshRequest, Refreshed};

use super::registration::{ClientStore, Registration};

/// Renews through the OAuth flow, using the client registration this
/// installation made when the credential was first acquired.
pub struct OAuthRefresher {
    /// Where `oauth-clients.json` lives — the same root the credential store
    /// uses, because the two were written together by `act login`.
    store_root: PathBuf,
}

impl OAuthRefresher {
    pub fn new(store_root: PathBuf) -> Arc<Self> {
        Arc::new(Self { store_root })
    }
}

#[async_trait::async_trait]
impl CredentialRefresher for OAuthRefresher {
    async fn refresh(&self, req: RefreshRequest<'_>) -> Result<Refreshed, String> {
        let clients = ClientStore::load(&self.store_root).map_err(|e| e.to_string())?;
        // Registration is keyed by issuer *and* redirect. A refresh sends no
        // redirect, so the one to reuse is whichever this installation
        // registered for its own loopback — the ephemeral-port form `act login`
        // registers, which is what a DCR registration here always looks like.
        let reg = clients
            .get(
                req.issuer,
                &super::listener::Listener::registered_redirect_uri(),
            )
            .cloned()
            .ok_or_else(|| {
                format!(
                    "no client registration for {} — the credential was acquired \
                     by a different installation, or `oauth-clients.json` is gone",
                    req.issuer
                )
            })?;

        let client = reqwest::Client::builder()
            .user_agent(concat!("act/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| e.to_string())?;

        let acquired =
            super::refresh::refresh(&client, req.issuer, &reg, req.refresh_token, req.now)
                .await
                // `to_string` on the whole chain, not just the head: the context says
                // which stage failed, and none of it carries material — the exchange
                // deliberately never quotes a token endpoint's body back.
                .map_err(|e| format!("{e:#}"))?;

        Ok(Refreshed {
            access_token: acquired.access_token,
            expires_at: acquired.expires_at,
            scopes: acquired.scopes,
            refresh_token: acquired.refresh_token,
        })
    }
}

/// Kept honest by construction: a `Registration` is what both the flow and this
/// refresher speak, so there is no second shape to drift.
#[allow(dead_code)]
fn _assert_shared_shape(r: Registration) -> Registration {
    r
}
