//! Engine construction, component loading, and the WASI linker.

use anyhow::Result;
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine};

use crate::store::HostState;
use crate::{credentials, fs_policy};

/// Create a wasmtime engine with component-model and async enabled.
pub fn create_engine() -> Result<Engine> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.wasm_component_model_async(true);
    // Enable wasm exception-handling so components carrying C++-exception
    // extensions run (e.g. numpy 2.x's pocketfft throws). Additive: components
    // without the exceptions proposal are unaffected.
    config.wasm_exceptions(true);
    // SPIKE: enable WasmGC so GC-backed guests (Kotlin/Wasm, future JVM/Dart) run.
    config.wasm_function_references(true);
    config.wasm_gc(true);
    let engine = Engine::new(&config)
        .map_err(|e| anyhow::anyhow!("failed to create wasmtime engine: {e}"))?;
    Ok(engine)
}
/// Load a .wasm component from a file path and report the SHA-256 of its
/// bytes.
///
/// The digest identifies the exact artifact in the audit trail, so it is read
/// from the file rather than inferred from the reference — a local path and an
/// OCI cache entry are treated identically.
pub fn load_component(engine: &Engine, path: &std::path::Path) -> Result<(Component, String)> {
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("failed to read component {}: {e}", path.display()))?;
    let digest = crate::audit::sha256_hex(&bytes);
    let component = Component::from_binary(engine, &bytes)
        .map_err(|e| anyhow::anyhow!("failed to load component from {}: {e}", path.display()))?;
    Ok((component, digest))
}
/// Create a linker with WASI bindings (both P2 and P3).
pub fn create_linker(engine: &Engine) -> Result<Linker<HostState>> {
    let mut linker = Linker::new(engine);
    // Add P2 bindings (components built with wasm32-wasip2 import P2 interfaces)
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)
        .map_err(|e| anyhow::anyhow!("failed to add WASI P2 to linker: {e}"))?;
    // Shadow the default wasi:filesystem bindings with our policy-aware
    // PolicyFilesystem view. Must come AFTER add_to_linker_async registered
    // the defaults.
    linker.allow_shadowing(true);
    wasmtime_wasi::p2::bindings::filesystem::types::add_to_linker::<
        HostState,
        fs_policy::PolicyFilesystem,
    >(&mut linker, |t| t.policy_fs_view())
    .map_err(|e| anyhow::anyhow!("failed to add policy wasi:filesystem/types: {e}"))?;
    wasmtime_wasi::p2::bindings::filesystem::preopens::add_to_linker::<
        HostState,
        fs_policy::PolicyFilesystem,
    >(&mut linker, |t| t.policy_fs_view())
    .map_err(|e| anyhow::anyhow!("failed to add policy wasi:filesystem/preopens: {e}"))?;
    linker.allow_shadowing(false);
    // Add P3 bindings on top
    wasmtime_wasi::p3::add_to_linker(&mut linker)
        .map_err(|e| anyhow::anyhow!("failed to add WASI P3 to linker: {e}"))?;
    // Shadow only the p3 preopens interface. When fs mode ≠ Open, our impl
    // returns zero preopens → p3 guests can't obtain a Descriptor::Dir and
    // every path op fails. Matcher-level gating on individual p3 path ops
    // isn't possible with current wasmtime-wasi public API (Dir::open_at
    // is `pub(crate)`).
    linker.allow_shadowing(true);
    wasmtime_wasi::p3::bindings::filesystem::preopens::add_to_linker::<
        HostState,
        fs_policy::PolicyFilesystem,
    >(&mut linker, |t| t.policy_fs_view())
    .map_err(|e| anyhow::anyhow!("failed to add policy wasi:filesystem/preopens (p3): {e}"))?;
    linker.allow_shadowing(false);
    // Add WASI HTTP bindings (P2 for wasm32-wasip2 components, P3 for async)
    wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)
        .map_err(|e| anyhow::anyhow!("failed to add WASI HTTP P2 to linker: {e}"))?;
    wasmtime_wasi_http::p3::add_to_linker(&mut linker)
        .map_err(|e| anyhow::anyhow!("failed to add WASI HTTP P3 to linker: {e}"))?;
    // `act:credentials` — the one interface in `act-world` the host provides
    // and the component imports. Both its instances are registered; see
    // `credentials::add_to_linker` for why `types` is not optional.
    credentials::add_to_linker(&mut linker)?;
    Ok(linker)
}
