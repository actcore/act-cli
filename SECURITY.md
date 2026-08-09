# Security Policy

Security is a core priority of the ACT project, not an afterthought.

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it privately via [GitHub Security Advisories](https://github.com/actcore/act-spec/security/advisories/new) or email security@actcore.dev.

Do **not** open a public issue for security vulnerabilities.

## Supply Chain Security

- **Trusted publishing.** All ACT packages use OpenID Connect (OIDC) trusted publishing for crates.io, PyPI, and npm. No long-lived API tokens are stored in CI. We encourage component authors to adopt the same practice.
- **Build provenance.** Every release includes Sigstore-based build provenance attestation, verifiable via `gh attestation verify`.
- **SBOM.** Every release ships a CycloneDX SBOM so users can audit the full dependency tree.

## Sandbox Model

Components run in WebAssembly's capability-based sandbox. No filesystem, network, or system access is available unless explicitly granted by the operator, via the uniform grant model: `--grant '<json>'` for a full grant object, `--allow <id>` / `--deny <id>` to open or deny a capability class by id, or the equivalent `[policy]` section in `~/.config/act/config.toml`. This is enforced by the Wasmtime runtime, not by the component. The default policy mode is ask-by-default: a headless invocation with no grant degrades to deny rather than silently allowing access.

### Audit trail

Every `act run` and `act call` invocation writes a structured audit trail to stderr: what component and digest is running, under what capability modes, every capability decision (allow, deny, or ask) as it resolves, and a per-call summary with outcome and duration. This is the operator-visible record of what the sandbox actually enforced, not just what was configured.

The audit trail is on by default and cannot be silenced by log configuration — `RUST_LOG=off`, `act=warn`, and `-v` all leave it running, because the audit layer carries its own filter, independent of the logging `EnvFilter`. `--no-audit` (or `[audit] enabled = false` in the config file) is the only way to disable it. Tool-call arguments are recorded as a SHA-256 digest by default; `--audit-args` records the full values instead, which can expose credentials in arguments and is opt-in for that reason. Session args — where ACT-AUTH.md says auth belongs — are never recorded under either mode, only the session id they produced.
