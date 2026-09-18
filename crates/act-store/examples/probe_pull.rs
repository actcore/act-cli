//! End-to-end: pull a component through the new client and count its referrers.
#[tokio::main]
async fn main() {
    let dir = std::env::temp_dir().join(format!("act-probe-{}", std::process::id()));
    let store = act_store::store::Store::open(&dir).expect("store");
    match act_store::fetch::fetch_oci(&store, "actpkg.dev/library/time:latest").await {
        Ok(s) => {
            println!(
                "pulled: manifest {} wasm {}",
                s.manifest_digest, s.wasm_digest
            );
            match store.list_referrers_by_digest(&s.manifest_digest) {
                Ok(rs) => {
                    println!("referrers stored: {}", rs.len());
                    for r in &rs {
                        println!("  {r:?}");
                    }
                }
                Err(e) => println!("referrer listing failed: {e}"),
            }
        }
        Err(e) => println!("FAILED: {e}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}
