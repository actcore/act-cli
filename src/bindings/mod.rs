wasmtime::component::bindgen!({
    world: "act-world",
    path: "../act-cli/wit",
    require_store_data_send: true,
    skip_mut_forwarding_impls: true,
});
