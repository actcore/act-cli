//! Cross-check `ParsedRef` against `oci-client`'s own parser on real forms.
fn main() {
    for s in [
        "actpkg.dev/library/time:0.3.2",
        "ghcr.io/actcore/act/shim-tools-sync:0.1.0",
        "actpkg.dev/library/time",
        "actpkg.dev/library/time@sha256:84370542c13b56a34df9c551eb694400441da0ae799e40b17867877cb901e5fb",
        "localhost:5000/library/time",
    ] {
        let mine = act_store::registry::reference::ParsedRef::parse(s);
        let theirs: Result<oci_client::Reference, _> = s.parse();
        match (mine, theirs) {
            (Ok(m), Ok(t)) => {
                let same = m.registry == t.registry() && m.repository == t.repository();
                println!(
                    "{}  {s}\n    mine:   {}/{} ref={}\n    oci:    {}/{} tag={:?} digest={:?}",
                    if same { "AGREE " } else { "DIFFER" },
                    m.registry,
                    m.repository,
                    m.reference,
                    t.registry(),
                    t.repository(),
                    t.tag(),
                    t.digest()
                );
            }
            (m, t) => println!("?? {s}: mine={:?} theirs_ok={}", m.is_ok(), t.is_ok()),
        }
    }
}
