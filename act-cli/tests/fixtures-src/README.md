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

## credentials-canary

Credentials canary. The only fixture that **imports** a host interface —
`act:credentials/store@0.1.0` — rather than only exporting ones, so it is the
only one that can drive the host's credential path end to end. It also exports
`act:tools/tool-provider` and `act:sessions/session-provider`; the session
export is not optional, because `get-secret` requires a live session.

Its `whoami` tool fetches the credential under the key `probe` and returns
its `kind`, whether the field map arrived non-empty, the field *names*, the
byte **length** of `std:value` (when present), and the **CBOR major type**
its first field decoded to (`shape`: `"text"` / `"map"` / `"other"`) — never
the value, of either field. The length is the minimal oracle that lets
`tests/credentials_e2e.rs` tell "the host handed over the real material" from
"the host handed over an empty shell with the right kind on it"; `shape` is
the same idea for a field's *encoding*, telling a CBOR map (`std:oauth2`)
apart from CBOR text (`std:string`) without ever decoding what it holds.
`list_keys` returns `list-secrets` metadata, which by construction cannot
carry a value.

The credential is fetched **on the tool call, never inside `open-session`**:
the host marks a session live only once `open-session` returns, and the id is
component-chosen, so a fetch from inside that call is refused as an unknown
session — always. See the credentials design doc §8.3 / §9.2.

### Two artifacts, one build

`credentials-canary.wasm` and `credentials-canary-undeclared.wasm` are the
same compiled bytes packed twice: against `act.toml`, which carries the bare
`[std.capabilities."act:credentials"]` table spec §4 prescribes, and against
`undeclared/act.toml`, which does not. `act-build pack` resolves metadata from
the first project directory it finds walking up from the wasm, so placing a
copy of the wasm in `undeclared/` is what selects the second manifest. Two
artifacts are needed because there is deliberately no flag that un-declares a
capability: an undeclared class is denied and no grant can widen it.

### Rebuild

```bash
cd tests/fixtures-src/credentials-canary
cargo build --target wasm32-wasip2 --release
AB="cargo run --manifest-path ../../../../act-build/Cargo.toml --release --"

# Declaring variant:
cp target/wasm32-wasip2/release/credentials_canary.wasm .
$AB pack credentials_canary.wasm
mv credentials_canary.wasm ../../fixtures/credentials-canary.wasm

# Undeclared twin — same bytes, packed against undeclared/act.toml:
cp target/wasm32-wasip2/release/credentials_canary.wasm undeclared/
$AB pack undeclared/credentials_canary.wasm
mv undeclared/credentials_canary.wasm \
    ../../fixtures/credentials-canary-undeclared.wasm

# oauth-declaring twin — declares one credential whose field is std:oauth2,
# which `act login` must refuse to prompt for (tests/login_cli.rs):
cp target/wasm32-wasip2/release/credentials_canary.wasm oauth-declaring/
$AB pack oauth-declaring/credentials_canary.wasm
mv oauth-declaring/credentials_canary.wasm \
    ../../fixtures/oauth-declaring-canary.wasm

# creds-declaring twin — declares one std:string credential under key
# "default", used by tests/login_cli.rs to exercise `act login`'s
# provisioning and its overwrite guard without the field-type refusal above
# getting in the way first:
cp target/wasm32-wasip2/release/credentials_canary.wasm creds-declaring/
$AB pack creds-declaring/credentials_canary.wasm
mv creds-declaring/credentials_canary.wasm \
    ../../fixtures/creds-declaring-canary.wasm
```
