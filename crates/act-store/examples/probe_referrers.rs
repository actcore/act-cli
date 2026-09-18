//! Live check of `fetch_referrers`: a registry that has them, and a digest that has none.
#[tokio::main]
async fn main() {
    let transport = hclient_native::Native::new(
        hclient_rt_tokio::Tokio,
        hclient_tls_rustls::Rustls::with_webpki_roots(),
        hclient_dns_system::SystemDns::new(hclient_rt_tokio::Tokio),
    );
    let http = hclient::Client::builder(transport).build().expect("client");
    use act_store::registry::{client, reference::ParsedRef};

    let r = ParsedRef::parse("actpkg.dev/library/time:latest").unwrap();
    let (_, digest, token) =
        client::fetch_manifest(&http, &r.registry, &r.repository, &r.reference)
            .await
            .expect("manifest");

    match client::fetch_referrers(&http, &r, &digest, token.as_deref()).await {
        Some(idx) => {
            println!("referrers for {digest}: {}", idx.manifests().len());
            for m in idx.manifests() {
                println!(
                    "  {:?} {}",
                    m.artifact_type(),
                    &m.digest().to_string()[..24]
                );
            }
        }
        None => println!("referrers for {digest}: none"),
    }

    // A digest that exists nowhere: must be None, not a panic or an error.
    let bogus = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    println!(
        "referrers for a bogus digest: {}",
        match client::fetch_referrers(&http, &r, bogus, token.as_deref()).await {
            Some(i) => format!("{} manifests", i.manifests().len()),
            None => "none (as it should be)".into(),
        }
    );
}
