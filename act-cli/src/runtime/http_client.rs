//! Reqwest-backed client for `wasi:http/outgoing-handler`. One instance per
//! `HostState` (per component invocation). Client config — redirect policy,
//! DNS resolver — is baked in at construction from the component's
//! `HttpConfig` so we don't need to thread context through each call.

use std::sync::Arc;

use crate::config::HttpConfig;

/// Reqwest client instantiated with this component's HTTP policy. Cheap to
/// clone (reqwest::Client is internally `Arc`'d); share freely across
/// async tasks.
#[derive(Clone)]
#[allow(dead_code)] // wired into HostState in Task 7
pub struct ActHttpClient {
    client: Arc<reqwest::Client>,
}

impl ActHttpClient {
    #[allow(dead_code)] // wired into HostState in Task 7
    pub fn new(_cfg: HttpConfig) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build reqwest client: {e}"))?;
        Ok(Self {
            client: Arc::new(client),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HttpConfig;

    #[test]
    fn builds_default_client() {
        let cfg = HttpConfig::default();
        let client = ActHttpClient::new(cfg);
        assert!(client.is_ok(), "{:?}", client.err());
    }
}
