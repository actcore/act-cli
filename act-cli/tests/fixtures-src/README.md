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

## fs-canary

Filesystem canary. Exports `act:tools/tool-provider` only, declares
`wasi:filesystem` with the widest possible ceiling (`**`, rw) so a test's
`--grant` is what actually narrows access. Its single tool, `read`, reads the
`path` given in its arguments via plain `std::fs::read_to_string` — so every
call drives the host's per-op capability decision in `runtime/fs_policy.rs`.
Used by `tests/audit_cli.rs` to assert the audit trail's `fs:` rollup clause
and immediate deny line against a real component, not just against
`CapDecisionRecord`'s constructors directly.

### Rebuild

```bash
cd tests/fixtures-src/fs-canary
cargo build --target wasm32-wasip2 --release
# Pack metadata into the wasm:
cargo run --manifest-path ../../../../act-build/Cargo.toml --release -- \
    pack target/wasm32-wasip2/release/fs_canary.wasm
# Copy into the fixtures dir:
cp target/wasm32-wasip2/release/fs_canary.wasm ../../fixtures/fs-canary.wasm
```

## sockets-canary

Sockets canary. Exports `act:tools/tool-provider` only, declares
`wasi:sockets` with the widest possible ceiling (`host = "*"`, tcp) so a
test's `--grant` is what actually narrows access. Its single tool, `connect`,
opens a raw TCP connection to the `host`/`port` given in its arguments via
plain `std::net::TcpStream::connect` — so every call drives the host's
per-op capability decision in `runtime/mod.rs`'s `socket_addr_check` hook
(the `wasi:sockets` counterpart to `fs-canary` for `wasi:filesystem` and
`ask-canary` for `wasi:http`). Used by `tests/audit_cli.rs` to assert the
audit trail's `sockets:` rollup clause and immediate deny/ask-deny lines
against a real component. Pointed at a dead loopback port so an
allowed-but-unreachable connect (`ConnectionRefused`, blocked at the
transport) is distinguishable from a policy-denied one (`PermissionDenied`,
blocked before the connect syscall) without standing up a server — the same
trick `ask-canary` uses for HTTP.

### Rebuild

```bash
cd tests/fixtures-src/sockets-canary
cargo build --target wasm32-wasip2 --release
# Pack metadata into the wasm:
cargo run --manifest-path ../../../../act-build/Cargo.toml --release -- \
    pack target/wasm32-wasip2/release/sockets_canary.wasm
# Copy into the fixtures dir:
cp target/wasm32-wasip2/release/sockets_canary.wasm \
    ../../fixtures/sockets-canary.wasm
```
