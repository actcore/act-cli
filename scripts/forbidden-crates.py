#!/usr/bin/env python3
"""Refuse dependencies whose whole job `std` now does.

Two crates are forbidden here, for the same reason: the standard library
grew a macro that replaces them, and both have been stable since Rust 1.96.

    cfg-if          ->  std::cfg_select!
    assert_matches  ->  std::assert_matches!

Carrying either one now buys a dependency, a version to resolve and a licence
to audit in exchange for nothing.

## Why a script rather than cargo-deny

`deny.toml` bans crates across the whole dependency graph, and `cfg-if` is one
of the most widely used crates on crates.io — it arrives under `ring`,
`getrandom`, `sha2`, `wasm-bindgen` and many more. Banning it there would fail
on other people's code, and cargo-deny's `wrappers` escape would mean
re-listing every third-party parent after every bump.

The rule actually meant is narrower: *we* do not depend on these. That is a
property of our own manifests, so it is checked against our own manifests.
This file is identical in every ACT Rust workspace; keep it that way, and keep
per-repository facts (MSRV, parent counts) out of it.

## What counts as a dependency

Every table Cargo reads a dependency name from, including the ones that are
easy to forget: `build-dependencies`, `workspace.dependencies`, and the
target-specific `[target.'cfg(unix)'.dependencies]` form. A rename
(`foo = { package = "cfg-if" }`) is caught by the package name, not the key,
because the key is whatever the author felt like typing.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

# Spelled both ways: Cargo accepts `cfg_if` as a key and normalises it, so a
# check that only knew the hyphen would miss half the ways in.
FORBIDDEN = {
    "cfg-if": "std::cfg_select!",
    "cfg_if": "std::cfg_select!",
    "assert_matches": "std::assert_matches!",
    "assert-matches": "std::assert_matches!",
}

DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")

# Anything under these is someone else's source tree, vendored or built.
SKIP_PARTS = {"target", ".git", "node_modules", ".cargo-home", "vendor"}


def dependency_names(table: dict) -> list[tuple[str, str]]:
    """(key, package-name) for one dependency table."""
    out = []
    for key, spec in table.items():
        package = spec.get("package", key) if isinstance(spec, dict) else key
        out.append((key, package))
    return out


def collect(manifest: dict) -> list[tuple[str, str, str]]:
    """(table, key, package) for every dependency the manifest declares."""
    found = []

    def scan(where: str, table: object) -> None:
        if isinstance(table, dict):
            found.extend((where, k, p) for k, p in dependency_names(table))

    for name in DEPENDENCY_TABLES:
        scan(name, manifest.get(name))

    workspace = manifest.get("workspace")
    if isinstance(workspace, dict):
        scan("workspace.dependencies", workspace.get("dependencies"))

    targets = manifest.get("target")
    if isinstance(targets, dict):
        for triple, tables in targets.items():
            if isinstance(tables, dict):
                for name in DEPENDENCY_TABLES:
                    scan(f"target.{triple}.{name}", tables.get(name))

    return found


def manifests(root: Path):
    for path in sorted(root.rglob("Cargo.toml")):
        if SKIP_PARTS.isdisjoint(path.parts):
            yield path


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    failures = []

    for path in manifests(root):
        try:
            manifest = tomllib.loads(path.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            # `check-toml` owns malformed manifests; not reporting one here
            # would let a file opt out of this gate by being unparseable.
            failures.append(f"{path}: cannot be parsed, so cannot be checked: {exc}")
            continue

        for table, key, package in collect(manifest):
            if package in FORBIDDEN:
                rename = "" if key == package else f" (as `{key}`)"
                failures.append(
                    f"{path.relative_to(root)}: [{table}] declares `{package}`"
                    f"{rename} — use {FORBIDDEN[package]} instead"
                )

    if failures:
        print("Forbidden dependency:", file=sys.stderr)
        for line in failures:
            print(f"  {line}", file=sys.stderr)
        print(
            "\nBoth macros have been stable since Rust 1.96, so the crate buys\n"
            "nothing the standard library does not already provide.\n"
            "See scripts/forbidden-crates.py for the reasoning.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
