// Embed a Windows application manifest declaring long-path awareness. This
// lets act.exe open paths > MAX_PATH (260 chars) without requiring UNC
// (`\\?\...`) prefixes in user input. Requires Windows 10 1607+ with the
// `LongPathsEnabled` registry flag set at HKLM\SYSTEM\CurrentControlSet\
// Control\FileSystem. No-op on non-Windows targets.

fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        use embed_manifest::manifest::Setting;
        embed_manifest::embed_manifest(
            embed_manifest::new_manifest("ACTCore.ACT").long_path_aware(Setting::Enabled),
        )
        .expect("failed to embed Windows manifest");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
