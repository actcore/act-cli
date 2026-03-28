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

Components run in WebAssembly's capability-based sandbox. No filesystem, network, or system access is available unless explicitly granted by the operator via `--allow-dir` or `--allow-fs` flags. This is enforced by the Wasmtime runtime, not by the component.
