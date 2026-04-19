#[test]
fn cli_run_help_shows_policy_flags() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_act"))
        .args(["run", "--help"])
        .output()
        .expect("failed to run act");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("fs-policy"), "missing --fs-policy flag");
    assert!(stdout.contains("fs-allow"), "missing --fs-allow flag");
    assert!(stdout.contains("fs-deny"), "missing --fs-deny flag");
    assert!(stdout.contains("http-policy"), "missing --http-policy flag");
    assert!(stdout.contains("http-allow"), "missing --http-allow flag");
    assert!(stdout.contains("http-deny"), "missing --http-deny flag");
    assert!(stdout.contains("profile"), "missing --profile flag");
    assert!(stdout.contains("config"), "missing --config flag");
}

#[test]
fn cli_call_help_shows_policy_flags() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_act"))
        .args(["call", "--help"])
        .output()
        .expect("failed to run act");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("fs-policy"), "missing --fs-policy in call");
    assert!(
        stdout.contains("http-policy"),
        "missing --http-policy in call"
    );
}

#[test]
fn cli_legacy_allow_dir_rejected() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_act"))
        .args(["run", "--allow-dir", "a:b", "foo"])
        .output()
        .expect("failed to run act");
    assert!(
        !output.status.success(),
        "old --allow-dir flag should be rejected"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpected argument") || stderr.contains("--allow-dir"),
        "expected clap to reject removed flag; got: {stderr}"
    );
}

#[test]
fn cli_run_mcp_flag_appears_in_run_help() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_act"))
        .args(["run", "--help"])
        .output()
        .expect("failed to run act");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("mcp"), "missing --mcp flag in run");
}

#[test]
fn cli_info_help_shows_tools_and_format_flags() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_act"))
        .args(["info", "--help"])
        .output()
        .expect("failed to run act");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("tools"), "missing --tools flag in info");
    assert!(stdout.contains("format"), "missing --format flag in info");
}
