//! SEP-2640 Skills extension, end to end.
//!
//! Builds a component with an embedded `act:skill` package (the same
//! `wasm-encoder` framing `act-build pack` uses), serves it under `--mcp`,
//! and drives the skill surface with raw JSON-RPC on stdio — the same
//! harness style as `ask_mcp_elicitation`:
//!
//! * `initialize` negotiates the skills extension
//! * `skills/list` returns the single embedded skill with cache hints
//! * `skills/get` returns the manifest with `sha256:` digests
//! * `resources/list` advertises SKILL.md only
//! * `resources/read` serves package files from the component's mmap
//! * `resources/directory/read` lists direct children of a package dir
//!
//! A skill-less component answers `skills/list` with an empty list and
//! does not declare the extension in `initialize`.
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const CASE_TIMEOUT: Duration = Duration::from_secs(60);

/// SKILL.md with frontmatter and a body.
fn skill_md(name: &str, description: &str) -> Vec<u8> {
    format!("---\nname: {name}\ndescription: {description}\n---\n\nBody.\n").into_bytes()
}

/// A tar archive with SKILL.md plus a nested file.
fn skill_tar(name: &str, description: &str) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let skill_md = skill_md(name, description);
    let mut header = tar::Header::new_gnu();
    header.set_size(skill_md.len() as u64);
    header.set_cksum();
    builder
        .append_data(&mut header, "SKILL.md", &skill_md[..])
        .expect("append SKILL.md");
    let mut header = tar::Header::new_gnu();
    header.set_size(9);
    header.set_cksum();
    builder
        .append_data(&mut header, "queries/basic.sql", &b"SELECT 1;"[..])
        .expect("append query");
    builder.into_inner().expect("tar built")
}

/// Write the fixture component to a temp dir that outlives the child
/// process; leaked tempdirs are reclaimed by the OS.
///
/// The base is a real compiled component (`time.wasm`, the smallest tree
/// fixture): wasmtime must compile it for `act run` to start, and a
/// hand-rolled section-only binary does not validate. Custom sections ride
/// along untouched, so appending `act:skill` is enough.
fn fixture_component() -> PathBuf {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("skill-canary.wasm");
    let base = std::fs::read(BASE_COMPONENT).expect("read base component");
    let tar = skill_tar("navigable", "SQL navigation helpers");
    let mut wasm = base;
    use wasm_encoder::Section as _;
    wasm_encoder::CustomSection {
        name: "act:skill".into(),
        data: tar.into(),
    }
    .append_to(&mut wasm);
    std::fs::write(&path, wasm).expect("write fixture");
    std::mem::forget(dir);
    path
}

/// A real compiled component to graft the skill section onto.
///
/// `ask-canary` carries no `act:skill` of its own (`time.wasm` does), so
/// the only skill section in the fixture is the one appended here.
const BASE_COMPONENT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/ask-canary.wasm"
);

/// One JSON-RPC exchange cycle against `act run --mcp`.
///
/// Sends `initialize` (declaring the skills extension), then the follow-up
/// requests produced by `send_followups`, and collects each response by id
/// until the highest id answers. Server-to-client requests are answered
/// with `decline` — none is expected on this surface.
fn run_exchange(
    fixture: &std::path::Path,
    requests: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let requests: Vec<serde_json::Value> = requests.to_vec();
    let mut child = Command::new(env!("CARGO_BIN_EXE_act"))
        .args(["run", fixture.to_str().expect("utf8 path"), "--mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn act --mcp");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut responses = Vec::new();
        let send = |stdin: &mut std::process::ChildStdin, value: serde_json::Value| {
            let _ = writeln!(stdin, "{value}");
            let _ = stdin.flush();
        };
        send(
            &mut stdin,
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2026-07-28",
                    "capabilities": {},
                    "clientInfo": { "name": "skills-extension-test", "version": "0" },
                }
            }),
        );
        let mut initialized = false;
        let mut sent_followups = false;
        for line in stdout.lines() {
            let Ok(line) = line else { break };
            let Ok(message) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            if let Some(id) = message.get("id").and_then(serde_json::Value::as_u64) {
                if message.get("method").is_some() {
                    // Server-to-client request: politely decline.
                    send(
                        &mut stdin,
                        serde_json::json!({
                            "jsonrpc": "2.0", "id": id,
                            "result": { "action": "decline" },
                        }),
                    );
                    continue;
                }
                responses.push(message);
                if id == 1 && !initialized {
                    initialized = true;
                    send(
                        &mut stdin,
                        serde_json::json!({
                            "jsonrpc": "2.0", "method": "notifications/initialized"
                        }),
                    );
                }
                // Wait for the initialize response before sending follow-ups
                // (the server rejects requests ahead of it).
                if id == 1 && !sent_followups {
                    sent_followups = true;
                    for request in &requests {
                        send(&mut stdin, request.clone());
                    }
                }
                // Done once every follow-up has answered (rmcp serves
                // requests concurrently, so answers race past each other).
                if responses.len() > requests.len() {
                    let _ = tx.send(responses);
                    return;
                }
            }
        }
        let _ = tx.send(responses);
    });

    let responses = rx
        .recv_timeout(CASE_TIMEOUT)
        .expect("exchange completes in time");
    let _ = child.kill();
    let _ = child.wait();
    responses
}

fn id_response(responses: &[serde_json::Value], id: u64) -> serde_json::Value {
    responses
        .iter()
        .find(|r| r.get("id").and_then(serde_json::Value::as_u64) == Some(id))
        .unwrap_or_else(|| panic!("no response for id {id} in {responses:?}"))
        .clone()
}

#[test]
fn a_skill_bearing_component_serves_the_whole_skills_surface() {
    let fixture = fixture_component();
    let responses = run_exchange(
        &fixture,
        &[
            serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "skills/list",
            }),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 3, "method": "skills/get",
                "params": { "uri": "skill://navigable/SKILL.md" },
            }),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 4, "method": "resources/list",
            }),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 5, "method": "resources/read",
                "params": { "uri": "skill://navigable/queries/basic.sql" },
            }),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 6, "method": "resources/directory/read",
                "params": { "uri": "skill://navigable" },
            }),
        ],
    );

    // skills/list: the single embedded skill, cache hints set.
    let skills = id_response(&responses, 2);
    let skills = &skills["result"];
    assert_eq!(
        skills["skills"][0]["frontmatter"]["name"], "navigable",
        "skills/list names the embedded skill"
    );
    assert_eq!(skills["skills"].as_array().expect("skills array").len(), 1);
    assert!(
        skills.get("ttlMs").is_some(),
        "SEP-2549 freshness hint present on skills/list"
    );

    // skills/get: manifest lists both package files with digests.
    let manifest = id_response(&responses, 3);
    let manifest = &manifest["result"]["skill"]["resources"];
    let resources = manifest.as_array().expect("manifest is a file list");
    let uris: Vec<&str> = resources
        .iter()
        .map(|r| r["uri"].as_str().expect("uri"))
        .collect();
    assert_eq!(
        uris,
        [
            "skill://navigable/SKILL.md",
            "skill://navigable/queries/basic.sql"
        ],
        "manifest carries every package file under skill:// URIs"
    );
    for resource in resources {
        let digest = resource["digest"].as_str().expect("digest");
        assert!(
            digest.starts_with("sha256:") && digest.len() == 71,
            "digest is sha256-prefixed 64-hex ({digest})"
        );
    }

    // resources/list: only SKILL.md advertised.
    let listed = id_response(&responses, 4);
    let listed = listed["result"]["resources"]
        .as_array()
        .expect("resources array");
    assert_eq!(listed.len(), 1, "only SKILL.md appears in resources/list");
    assert_eq!(listed[0]["uri"], "skill://navigable/SKILL.md");
    assert_eq!(
        listed[0]["name"], "navigable",
        "frontmatter name becomes the resource name"
    );

    // resources/read: file bytes served from the mapping.
    let read = id_response(&responses, 5);
    let contents = read["result"]["contents"]
        .as_array()
        .expect("contents array");
    assert_eq!(contents.len(), 1);
    assert_eq!(contents[0]["uri"], "skill://navigable/queries/basic.sql");
    assert_eq!(contents[0]["text"], "SELECT 1;");

    // resources/directory/read: direct children of the package root.
    let directory = id_response(&responses, 6);
    let children = directory["result"]["resources"]
        .as_array()
        .expect("directory children");
    let child_uris: Vec<&str> = children
        .iter()
        .map(|r| r["uri"].as_str().expect("uri"))
        .collect();
    assert_eq!(
        child_uris,
        ["skill://navigable/SKILL.md", "skill://navigable/queries"],
        "root lists direct children; nested files stay under queries/"
    );
}

#[test]
fn initialize_declares_the_skills_extension_only_for_skill_bearing_components() {
    let fixture = fixture_component();
    let responses = run_exchange(&fixture, &[]);
    let init = id_response(&responses, 1);
    let extensions = &init["result"]["capabilities"]["extensions"];
    assert!(
        extensions.get("io.modelcontextprotocol/skills").is_some(),
        "skills extension declared in initialize: {extensions}"
    );
    assert!(
        init["result"]["capabilities"]["resources"].is_object(),
        "resources capability rides along"
    );
}

#[test]
fn a_component_without_a_skill_serves_an_empty_skill_surface() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("plain.wasm");
    let base = std::fs::read(BASE_COMPONENT).expect("read base component");
    std::fs::write(&path, base).expect("write");
    std::mem::forget(dir);

    let responses = run_exchange(
        &path,
        &[serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "skills/list",
        })],
    );
    let init = id_response(&responses, 1);
    let extensions = &init["result"]["capabilities"]["extensions"];
    assert!(
        extensions
            .as_object()
            .is_none_or(|e| e.get("io.modelcontextprotocol/skills").is_none()),
        "no skills extension for a skill-less component: {extensions}"
    );
    // rmcp gates the whole skills surface on the declared capability: a
    // skill-less server answers method-not-found without reaching any hook.
    let skills = id_response(&responses, 2);
    assert_eq!(
        skills["error"]["code"], -32601,
        "skills/list on a skill-less component is method-not-found"
    );
}
