//! Push a component to a local registry through `registry::push`, then read it
//! back — the digests must match what the incumbent produced.
#[tokio::main]
async fn main() {
    act_store::fetch::install_crypto_provider();
    // The local stand uses a private CA. `danger_accept_invalid_certs` is
    // acceptable here and nowhere else: this example exists to exercise the
    // wire format against a throwaway registry on loopback.
    let transport = hclient_native::Native::new(
        hclient_rt_tokio::Tokio,
        hclient_tls_rustls::Rustls::danger_accept_invalid_certs(),
        hclient_dns_system::SystemDns::new(hclient_rt_tokio::Tokio),
    );
    let http = hclient::Client::builder(transport).build().expect("client");

    use act_store::registry::{push, reference::ParsedRef};
    let reg = ParsedRef::parse("localhost:5000/probe/mine:0.0.1").expect("ref");

    let wasm = std::fs::read(std::env::var("PROBE_WASM").expect("PROBE_WASM")).expect("wasm");
    let layer_digest = format!("sha256:{}", act_store::layout::sha256_hex(&wasm));
    let config = b"{}".to_vec();
    let config_digest = format!("sha256:{}", act_store::layout::sha256_hex(&config));

    let token = push::push_token(&http, &reg).await.expect("token probe");
    println!("token: {}", if token.is_some() { "yes" } else { "none" });

    push::push_blob(&http, &reg, &layer_digest, wasm.clone(), token.as_deref())
        .await
        .expect("layer");
    push::push_blob(
        &http,
        &reg,
        &config_digest,
        config.clone(),
        token.as_deref(),
    )
    .await
    .expect("config");
    println!("layer:  {layer_digest}");
    println!("config: {config_digest}");

    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{}}},"layers":[{{"mediaType":"application/wasm","digest":"{layer_digest}","size":{}}}]}}"#,
        config.len(),
        wasm.len()
    );
    let expect = format!(
        "sha256:{}",
        act_store::layout::sha256_hex(manifest.as_bytes())
    );
    let got = push::push_manifest(
        &http,
        &reg,
        "0.0.1",
        manifest.into_bytes(),
        "application/vnd.oci.image.manifest.v1+json",
        token.as_deref(),
    )
    .await
    .expect("manifest");
    println!("manifest computed: {expect}");
    println!("manifest returned: {got}");
    println!(
        "{}",
        if got == expect {
            "MATCH — the registry stored our exact bytes"
        } else {
            "MISMATCH"
        }
    );
}
