#!/usr/bin/env python3
"""Single source of truth for the Ghydra release version.

Five files carry the release version, and they must never disagree:

    src/main/java/eu/starsong/ghidra/api/ApiConstants.java   PLUGIN_VERSION = "v3.0.0"
    bridge_mcp_hydra.py                                      BRIDGE_VERSION = "v3.0.0"
    pyproject.toml                                           version = "3.0.0"
    ghydra/__init__.py                                       __version__ = "3.0.0"
    src/main/resources/extension.properties                   version=3.0.0

The Java plugin and the Python bridge each announce a version that must match
the release tag, so a mismatch means the shipped artifact lies about itself.
The CI calls ``--check`` on every push and pull request to catch drift before
a tag is cut.

``API_VERSION`` (Java) and ``REQUIRED_API_VERSION`` (Python) are a separate
axis: they only move on breaking API changes and are never touched by
``--set``. The checker still asserts that the two agree with each other.

Usage:
    python scripts/version.py --get
    python scripts/version.py --check [--expect 3.0.0]
    python scripts/version.py --set 3.0.0
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (path, regex capturing the version in group 2, prefix to write)
LOCATIONS = [
    (
        "src/main/java/eu/starsong/ghidra/api/ApiConstants.java",
        re.compile(r'(PLUGIN_VERSION\s*=\s*")v?([^"]+)(")'),
        "v",
    ),
    (
        "bridge_mcp_hydra.py",
        re.compile(r'(BRIDGE_VERSION\s*=\s*")v?([^"]+)(")'),
        "v",
    ),
    (
        "pyproject.toml",
        re.compile(r'(^version\s*=\s*")v?([^"]+)(")', re.MULTILINE),
        "",
    ),
    (
        "ghydra/__init__.py",
        re.compile(r'(__version__\s*=\s*")v?([^"]+)(")'),
        "",
    ),
    (
        "src/main/resources/extension.properties",
        re.compile(r"(^version\s*=\s*)v?([^\r\n]+?)(\r?)$", re.MULTILINE),
        "",
    ),
]

# (path, regex capturing the numeric API version in group 1)
API_LOCATIONS = [
    (
        "src/main/java/eu/starsong/ghidra/api/ApiConstants.java",
        re.compile(r"API_VERSION\s*=\s*(\d+)"),
    ),
    (
        "bridge_mcp_hydra.py",
        re.compile(r"REQUIRED_API_VERSION\s*=\s*(\d+)"),
    ),
]

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")


def normalize(version: str) -> str:
    """Strip the optional ``v`` prefix used by the Java/bridge constants."""
    return version.strip().lstrip("v")


def read_version() -> dict[str, str]:
    """Return the version recorded in each location."""
    found: dict[str, str] = {}
    for rel, pattern, _prefix in LOCATIONS:
        path = ROOT / rel
        if not path.is_file():
            raise SystemExit(f"error: {rel} is missing")
        match = pattern.search(path.read_text(encoding="utf-8"))
        if match is None:
            raise SystemExit(f"error: no version found in {rel}")
        found[rel] = match.group(2).strip()
    return found


def read_api_version() -> dict[str, str]:
    """Return the API version recorded in the Java plugin and the bridge."""
    found: dict[str, str] = {}
    for rel, pattern in API_LOCATIONS:
        path = ROOT / rel
        match = pattern.search(path.read_text(encoding="utf-8"))
        if match is None:
            raise SystemExit(f"error: no API version found in {rel}")
        found[rel] = match.group(1).strip()
    return found


def write_version(version: str) -> list[str]:
    """Write ``version`` into every location. Returns the paths that changed.

    Every file is rewritten only after every pattern has been resolved, so a
    bad pattern can never leave the tree with half the versions updated.
    """
    version = normalize(version)
    if not VERSION_RE.match(version):
        raise SystemExit(f"error: '{version}' is not a valid version (want X.Y.Z[-TAG])")

    pending: list[tuple[Path, str, str]] = []
    for rel, pattern, prefix in LOCATIONS:
        path = ROOT / rel
        if not path.is_file():
            raise SystemExit(f"error: {rel} is missing")
        text = path.read_text(encoding="utf-8")
        new_text, count = pattern.subn(
            lambda m: f"{m.group(1)}{prefix}{version}{m.group(3)}", text, count=1
        )
        if count != 1:
            raise SystemExit(f"error: could not rewrite the version in {rel}")
        pending.append((path, text, new_text))

    changed: list[str] = []
    for path, text, new_text in pending:
        if new_text != text:
            path.write_text(new_text, encoding="utf-8")
            changed.append(str(path.relative_to(ROOT)).replace("\\", "/"))
    return changed


def check(expect: str | None) -> int:
    """Validate that every location agrees, and optionally matches ``expect``."""
    versions = read_version()
    unique = sorted(set(versions.values()))
    errors: list[str] = []

    if len(unique) > 1:
        errors.append("version constants disagree:")
        for rel, value in versions.items():
            errors.append(f"  {rel}: {value}")
    else:
        current = unique[0]
        print(f"version: {current}")
        if expect is not None:
            expected = normalize(expect)
            if current != expected:
                errors.append(
                    f"expected version {expected} but the tree carries {current}"
                )

    api_versions = read_api_version()
    if len(set(api_versions.values())) > 1:
        errors.append("API version disagreement between the plugin and the bridge:")
        for rel, value in api_versions.items():
            errors.append(f"  {rel}: {value}")
    else:
        print(f"api_version: {next(iter(api_versions.values()))}")

    if errors:
        for line in errors:
            print(line, file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--get", action="store_true", help="print the current version")
    group.add_argument("--check", action="store_true", help="verify consistency")
    group.add_argument("--set", dest="set_version", metavar="X.Y.Z", help="write a new version")
    parser.add_argument(
        "--expect", metavar="X.Y.Z", help="version the tree must carry (with --check)"
    )
    args = parser.parse_args(argv)

    if args.get:
        versions = read_version()
        print(next(iter(versions.values())))
        return 0

    if args.check:
        return check(args.expect)

    changed = write_version(args.set_version)
    print(f"wrote {normalize(args.set_version)} to {len(changed)} file(s):")
    for rel in changed:
        print(f"  {rel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
