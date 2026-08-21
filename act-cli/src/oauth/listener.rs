//! The loopback listener the authorization server redirects back to.
//!
//! One socket, one path, one request, then gone. Everything about it is
//! narrowed on purpose (design §5.3):
//!
//! - **`127.0.0.1` only.** Binding `0.0.0.0` would put a live authorization
//!   callback on every interface, so anyone on the network could deliver a code
//!   — or read one, since the query string is the code.
//! - **Ephemeral port by default.** The redirect URI is registered by us through
//!   DCR, so nothing external needs to know the number in advance. A fixed port
//!   is available for pre-registered clients, whose redirect must match what was
//!   registered.
//! - **One fixed path**, `/callback`. Not an unguessable one: RFC 8252 §7.3
//!   has servers match a registered loopback redirect ignoring only the port,
//!   so a per-run path would break registration reuse. Anything else is refused
//!   before its query is parsed, and `state` is what binds the callback.
//! - **`Host` validated.** A DNS-rebinding page in the user's browser can reach
//!   `127.0.0.1` — this refuses anything whose `Host` is not the loopback
//!   address and port we bound.
//! - **A TTL**, so an abandoned flow does not hold the socket.
//!
//! The page returned to the browser is plain HTML with no script and no
//! external reference: it is rendered inside the user's session, and anything
//! it loaded would be a request an authorization callback caused.

use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use super::state::Pending;

/// The only path this listener answers. Fixed so a registered redirect stays
/// valid across runs (RFC 8252 §7.3 lets the port vary, and nothing else).
pub const CALLBACK_PATH: &str = "/callback";

/// What the authorization server sent back.
#[derive(Debug, PartialEq, Eq)]
pub struct Callback {
    pub code: Option<String>,
    pub state: Option<String>,
    pub iss: Option<String>,
    /// Present when the server refused — `access_denied` when the user said no.
    pub error: Option<String>,
    pub error_description: Option<String>,
}

pub struct Listener {
    inner: TcpListener,
    addr: SocketAddr,
}

impl Listener {
    /// Bind loopback. `port` of `None` takes an ephemeral one.
    pub async fn bind(port: Option<u16>) -> Result<Self> {
        let want = SocketAddr::from((Ipv4Addr::LOCALHOST, port.unwrap_or(0)));
        let inner = TcpListener::bind(want)
            .await
            .with_context(|| format!("binding the OAuth callback listener on {want}"))?;
        let addr = inner.local_addr().context("reading the bound address")?;
        Ok(Self { inner, addr })
    }

    /// The redirect URI to send in the authorization request.
    pub fn redirect_uri(&self) -> String {
        format!("http://{}{CALLBACK_PATH}", self.addr)
    }

    /// What to register with the authorization server: the same shape without a
    /// port, since the port is ephemeral and RFC 8252 §7.3 has the server
    /// ignore it for loopback redirects.
    pub fn registered_redirect_uri() -> String {
        format!("http://127.0.0.1{CALLBACK_PATH}")
    }

    /// Wait for the one callback this listener exists for.
    ///
    /// Requests that are not it — a wrong path, a bad `Host`, a browser's
    /// speculative `/favicon.ico` — are answered and dropped without ending the
    /// wait, because ending it would turn a stray prefetch into a failed login.
    pub async fn accept(&self, pending: &Pending) -> Result<Callback> {
        loop {
            if pending.expired() {
                bail!(
                    "no authorization callback within {} seconds — nothing was stored",
                    super::state::PENDING_TTL.as_secs()
                );
            }
            let accept =
                tokio::time::timeout(std::time::Duration::from_secs(1), self.inner.accept()).await;
            let Ok(accepted) = accept else {
                continue; // No connection this second; re-check the TTL.
            };
            let (stream, _peer) = accepted.context("accepting the callback connection")?;
            match self.serve_one(stream).await {
                Ok(Some(cb)) => return Ok(cb),
                Ok(None) => continue,
                // A malformed request is not a reason to abandon a flow the
                // user is still completing in their browser.
                Err(e) => tracing::debug!(error = %e, "ignoring a callback request"),
            }
        }
    }

    async fn serve_one(&self, mut stream: TcpStream) -> Result<Option<Callback>> {
        let (read_half, mut write_half) = stream.split();
        let mut lines = BufReader::new(read_half).lines();

        let request_line = lines
            .next_line()
            .await
            .context("reading the request line")?
            .unwrap_or_default();
        let mut host_ok = false;
        while let Some(line) = lines.next_line().await.context("reading headers")? {
            if line.is_empty() {
                break;
            }
            if let Some(value) = line
                .strip_prefix("Host:")
                .or_else(|| line.strip_prefix("host:"))
                && value.trim() == self.addr.to_string()
            {
                host_ok = true;
            }
        }

        let target = request_line.split_whitespace().nth(1).unwrap_or("");
        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p, q),
            None => (target, ""),
        };

        // The order matters: `Host` and path are checked before the query is
        // looked at, so a request that guessed neither is refused without this
        // host parsing attacker-chosen parameters.
        if !host_ok {
            respond(&mut write_half, 400, "Bad request.").await?;
            return Ok(None);
        }
        if path != CALLBACK_PATH {
            respond(&mut write_half, 404, "Not found.").await?;
            return Ok(None);
        }

        let params: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let cb = Callback {
            code: params.get("code").cloned(),
            state: params.get("state").cloned(),
            iss: params.get("iss").cloned(),
            error: params.get("error").cloned(),
            error_description: params.get("error_description").cloned(),
        };

        // The browser is told the same thing whether or not `state` matched.
        // A page that said "wrong state" would confirm a guess to whoever made
        // it; the terminal is where the operator learns what happened.
        respond(
            &mut write_half,
            200,
            "You can close this tab and return to your terminal.",
        )
        .await?;
        Ok(Some(cb))
    }
}

async fn respond<W: AsyncWriteExt + Unpin>(w: &mut W, status: u16, message: &str) -> Result<()> {
    // No script, no stylesheet, no image: everything this page could load would
    // be a request an authorization callback caused, inside the user's session.
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>act</title>\
         <p style=\"font:16px system-ui;margin:3rem\">{message}</p>"
    );
    let head = format!(
        "HTTP/1.1 {status} \r\n\
         content-type: text/html; charset=utf-8\r\n\
         content-length: {}\r\n\
         cache-control: no-store\r\n\
         connection: close\r\n\r\n",
        body.len()
    );
    w.write_all(head.as_bytes()).await?;
    w.write_all(body.as_bytes()).await?;
    w.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn get(addr: SocketAddr, target: &str, host: &str) -> String {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut s, &mut buf)
            .await
            .unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[tokio::test]
    async fn it_binds_loopback_and_never_a_wildcard() {
        let l = Listener::bind(None).await.unwrap();
        assert_eq!(l.addr.ip().to_string(), "127.0.0.1");
        assert_ne!(l.addr.port(), 0, "an ephemeral port is resolved once bound");
    }

    #[tokio::test]
    async fn the_redirect_uri_carries_the_one_time_path() {
        let l = Listener::bind(None).await.unwrap();
        let uri = l.redirect_uri();
        assert!(uri.starts_with("http://127.0.0.1:"), "{uri}");
        assert!(uri.ends_with(CALLBACK_PATH), "{uri}");
        // What gets registered carries no port, because the port is ephemeral
        // and RFC 8252 §7.3 has the server ignore it.
        assert_eq!(
            Listener::registered_redirect_uri(),
            "http://127.0.0.1/callback"
        );
    }

    #[tokio::test]
    async fn the_callback_is_read_from_the_one_time_path() {
        let l = Listener::bind(None).await.unwrap();
        let p = Pending::generate().unwrap();
        let addr = l.addr;
        let path = CALLBACK_PATH.to_string();
        let st = p.state().to_string();

        let client = tokio::spawn(async move {
            get(
                addr,
                &format!("{path}?code=the-code&state={st}&iss=https%3A%2F%2Fas.example.com"),
                &addr.to_string(),
            )
            .await
        });
        let cb = l.accept(&p).await.unwrap();
        let page = client.await.unwrap();

        assert_eq!(cb.code.as_deref(), Some("the-code"));
        assert_eq!(cb.state.as_deref(), Some(p.state()));
        assert_eq!(cb.iss.as_deref(), Some("https://as.example.com"));
        assert!(page.contains("close this tab"), "{page}");
        assert!(
            !page.contains("the-code"),
            "the page must not echo the code back into the browser: {page}"
        );
    }

    /// A wrong path and a rebinding `Host` are both refused, and — the part
    /// that matters — neither ends the wait. A browser's speculative
    /// `/favicon.ico` arriving first would otherwise fail the login.
    #[tokio::test]
    async fn strays_are_refused_without_ending_the_wait() {
        let l = Listener::bind(None).await.unwrap();
        let p = Pending::generate().unwrap();
        let addr = l.addr;
        let path = CALLBACK_PATH.to_string();
        let st = p.state().to_string();

        let client = tokio::spawn(async move {
            let wrong_path = get(addr, "/favicon.ico?code=stray", &addr.to_string()).await;
            assert!(wrong_path.starts_with("HTTP/1.1 404"), "{wrong_path}");

            // DNS rebinding: a page on evil.test resolving to 127.0.0.1 sends
            // the port we bound but its own Host.
            let rebound = get(addr, &path, "evil.test").await;
            assert!(rebound.starts_with("HTTP/1.1 400"), "{rebound}");

            get(
                addr,
                &format!("{path}?code=the-code&state={st}"),
                &addr.to_string(),
            )
            .await
        });

        let cb = l.accept(&p).await.unwrap();
        client.await.unwrap();
        assert_eq!(
            cb.code.as_deref(),
            Some("the-code"),
            "the real callback still landed"
        );
    }

    #[tokio::test]
    async fn an_error_response_is_carried_back_not_swallowed() {
        let l = Listener::bind(None).await.unwrap();
        let p = Pending::generate().unwrap();
        let addr = l.addr;
        let path = CALLBACK_PATH.to_string();
        let st = p.state().to_string();

        let client = tokio::spawn(async move {
            get(
                addr,
                &format!(
                    "{path}?error=access_denied&error_description=User%20said%20no&state={st}"
                ),
                &addr.to_string(),
            )
            .await
        });
        let cb = l.accept(&p).await.unwrap();
        client.await.unwrap();
        assert_eq!(cb.error.as_deref(), Some("access_denied"));
        assert_eq!(cb.error_description.as_deref(), Some("User said no"));
        assert_eq!(cb.code, None);
    }
}
