---
title: "API Reference: networking policy"
description: "Public Rust items in runtime/network.rs, runtime/http_policy.rs, and runtime/http_client.rs that implement host, CIDR, and HTTP request filtering."
---

Source files: `act-cli/src/runtime/network.rs`, `act-cli/src/runtime/http_policy.rs`, and `act-cli/src/runtime/http_client.rs`

## Network Primitives

```rust
pub struct NetworkRule {
    pub host: Option<String>,
    pub ports: Option<Vec<u16>>,
    pub cidr: Option<String>,
    pub except_ports: Option<Vec<u16>>,
}
```

```rust
pub enum Decision {
    Allow,
    Deny,
}
```

```rust
pub struct NetworkCheck<'a> {
    pub host: &'a str,
    pub port: u16,
    pub resolved_ips: &'a [IpAddr],
}
```

### Network functions

```rust
pub fn cidr_contains(cidr: &str, ip: IpAddr) -> bool
pub fn host_matches(pattern: &str, host: &str) -> bool
pub fn rule_matches(rule: &NetworkRule, check: &NetworkCheck) -> bool
pub fn decide(
    mode: PolicyMode,
    allow: &[NetworkRule],
    deny: &[NetworkRule],
    check: &NetworkCheck,
) -> Decision
pub async fn resolve_host(host: &str, port: u16) -> Vec<SocketAddr>
pub fn any_deny_cidr_matches(deny_rules: &[NetworkRule], ip: IpAddr, port: u16) -> bool
pub async fn first_cidr_deny_hit(
    deny_rules: &[NetworkRule],
    host: &str,
    port: u16,
) -> Option<SocketAddr>
```

### `NetworkCheck` constructors

```rust
pub fn new(host: &'a str, port: u16) -> Self
pub fn with_resolved(host: &'a str, port: u16, resolved_ips: &'a [IpAddr]) -> Self
```

## HTTP Policy Hook

```rust
pub struct PolicyHttpHooks { /* config + ActHttpClient */ }
```

```rust
pub fn new(
    config: HttpConfig,
    client: Arc<crate::runtime::http_client::ActHttpClient>,
) -> Self
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | `HttpConfig` | — | Effective HTTP policy for this component instance. |
| `client` | `Arc<ActHttpClient>` | — | Reqwest-backed client used after policy approval. |

`PolicyHttpHooks` implements both Wasmtime P2 and P3 `WasiHttpHooks`.

## Reqwest Backend

```rust
#[derive(Clone)]
pub struct ActHttpClient { /* Arc<reqwest::Client> */ }
```

### `ActHttpClient::new`

```rust
pub fn new(cfg: HttpConfig) -> anyhow::Result<Self>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `cfg` | `HttpConfig` | — | Effective HTTP policy used to construct redirect and DNS filtering behavior. |

### `ActHttpClient::send_p2`

```rust
pub async fn send_p2(
    &self,
    request: hyper::Request<UnsyncBoxBody<Bytes, P2ErrorCode>>,
    config: wasmtime_wasi_http::p2::types::OutgoingRequestConfig,
) -> Result<wasmtime_wasi_http::p2::types::IncomingResponse, P2ErrorCode>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `request` | `hyper::Request<UnsyncBoxBody<Bytes, P2ErrorCode>>` | — | Outgoing WASI HTTP request from the guest. |
| `config` | `wasmtime_wasi_http::p2::types::OutgoingRequestConfig` | — | Timeout and TLS behavior from the WASI binding. |

### `ActHttpClient::send_p3`

```rust
pub async fn send_p3(
    &self,
    request: http::Request<UnsyncBoxBody<Bytes, P3ErrorCode>>,
) -> Result<
    (
        http::Response<UnsyncBoxBody<Bytes, P3ErrorCode>>,
        Pin<Box<dyn Future<Output = Result<(), P3ErrorCode>> + Send>>,
    ),
    P3ErrorCode,
>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `request` | `http::Request<UnsyncBoxBody<Bytes, P3ErrorCode>>` | — | P3 outgoing request from the guest. |

## Example

```rust
let check = crate::runtime::network::NetworkCheck::new("example.com", 443);
let allowed = crate::runtime::network::decide(
    crate::config::PolicyMode::Allowlist,
    &allow_rules,
    &deny_rules,
    &check,
);
```

```rust
let client = crate::runtime::http_client::ActHttpClient::new(http.clone())?;
let hooks = crate::runtime::http_policy::PolicyHttpHooks::new(http, std::sync::Arc::new(client));
```

## Practical Notes

- HTTP-layer checks handle scheme and method, then delegate host, port, and CIDR matching to `network.rs`.
- The DNS resolver path matters when rules are CIDR-based, because hostnames must be resolved before the policy can decide which IPs remain valid.
- Redirects are rechecked hop by hop by the custom reqwest redirect policy.

Related pages: [Runtime Policies](/docs/runtime-policies) and [API Reference: runtime core](/docs/api-reference/runtime-core).
