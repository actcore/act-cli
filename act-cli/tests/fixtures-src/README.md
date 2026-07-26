# Test fixture sources

Hand-rolled component sources whose built wasms live in `tests/fixtures/`.

These are NOT production components — they are minimal artifacts written
to exercise host integration code paths (especially capability interfaces
that don't yet have SDK ergonomic support).

## sessions-canary

Stateful counter component. Exports both `act:tools/tool-provider` and
`act:sessions/session-provider`. Each session holds a `u64` counter;
tools `read` and `increment` operate on the counter identified by
`std:session-id` in call metadata.

### Rebuild

```bash
cd tests/fixtures-src/sessions-canary
cargo build --target wasm32-wasip2 --release
# Pack metadata into the wasm:
cargo run --manifest-path ../../../../act-build/Cargo.toml --release -- \
    pack target/wasm32-wasip2/release/sessions_canary.wasm
# Copy into the fixtures dir:
cp target/wasm32-wasip2/release/sessions_canary.wasm \
    ../../fixtures/sessions-canary.wasm
```

## ask-canary

Consent canary. Exports `act:tools/tool-provider` only, declares `wasi:http`,
and its single tool `fetch` makes one outbound request — so with no grant the
host resolves `wasi:http` to `ask` and every call trips the consent gate.
Used by `tests/ask_mcp_elicitation.rs`, which points it at a dead port so a
refused consent (`HttpRequestDenied`, blocked before the request leaves) is
distinguishable from an approved one (`ConnectionRefused`, blocked at the
transport) without standing up a server.

### Rebuild

```bash
cd tests/fixtures-src/ask-canary
cargo build --target wasm32-wasip2 --release
# Pack metadata into the wasm:
cargo run --manifest-path ../../../../act-build/Cargo.toml --release -- \
    pack target/wasm32-wasip2/release/ask_canary.wasm
# Copy into the fixtures dir:
cp target/wasm32-wasip2/release/ask_canary.wasm ../../fixtures/ask-canary.wasm
```
