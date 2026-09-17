//! Live check of `registry::client::fetch_manifest` against real registries.
//! Not a test: it needs the network. `cargo run -p act-store --example probe_manifest`
#[tokio::main]
async fn main() {
    act_store::fetch::install_crypto_provider();
    let transport = hclient_native::Native::new(
        hclient_rt_tokio::Tokio,
        hclient_tls_rustls::Rustls::with_webpki_roots(),
        hclient_dns_system::SystemDns::new(hclient_rt_tokio::Tokio),
    );
    let http = hclient::Client::builder(transport).build().expect("client");
    for (reg, repo, tag) in [
        ("actpkg.dev", "library/time", "latest"),
        ("ghcr.io", "actcore/act/shim-tools-sync", "0.1.0"),
    ] {
        match act_store::registry::client::fetch_manifest(&http, reg, repo, tag).await {
            Ok((bytes, digest, token)) => println!(
                "{reg}/{repo}: {} bytes, {digest}, token={}",
                bytes.len(),
                if token.is_some() { "yes" } else { "no" }
            ),
            Err(e) => println!("{reg}/{repo}: FAILED {e}"),
        }
    }
}
