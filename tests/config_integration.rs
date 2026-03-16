#[test]
fn cli_help_shows_filesystem_flags() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_act"))
        .args(["serve", "--help"])
        .output()
        .expect("failed to run act");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow-dir"), "missing --allow-dir flag");
    assert!(stdout.contains("allow-fs"), "missing --allow-fs flag");
    assert!(stdout.contains("profile"), "missing --profile flag");
    assert!(stdout.contains("config"), "missing --config flag");
}

#[test]
fn cli_call_help_shows_filesystem_flags() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_act"))
        .args(["call", "--help"])
        .output()
        .expect("failed to run act");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow-dir"), "missing --allow-dir in call");
    assert!(stdout.contains("allow-fs"), "missing --allow-fs in call");
}

#[test]
fn cli_mcp_help_shows_filesystem_flags() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_act"))
        .args(["mcp", "--help"])
        .output()
        .expect("failed to run act");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow-dir"), "missing --allow-dir in mcp");
}

#[test]
fn cli_info_help_does_not_show_filesystem_flags() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_act"))
        .args(["info", "--help"])
        .output()
        .expect("failed to run act");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("allow-dir"),
        "--allow-dir should not be in info"
    );
}
