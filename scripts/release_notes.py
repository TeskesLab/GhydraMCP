#!/usr/bin/env python3
"""Extract the release-notes section for a version from CHANGELOG.md.

The release workflows publish these notes verbatim. A tag whose CHANGELOG
section is missing would ship an empty release body, so this script exits
non-zero instead of returning an empty string.

The expected CHANGELOG shape is Keep a Changelog:

    ## [Unreleased]

    ## [3.0.0] - 2026-10-08

    ### Added
    - ...

Usage:
    python scripts/release_notes.py --version 3.0.0 --out release_notes.md
    python scripts/release_notes.py --version 3.0.0        # to stdout
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"


def extract(text: str, version: str) -> str:
    """Return the body of the ``## [version]`` section, or "" when absent."""
    heading = re.compile(rf"^## \[{re.escape(version)}\](?:\s|$)")
    other_heading = re.compile(r"^## \[")
    lines = text.splitlines()
    body: list[str] = []
    capturing = False
    for line in lines:
        if heading.match(line):
            capturing = True
            continue
        if capturing and other_heading.match(line):
            break
        if capturing:
            body.append(line)
    return "\n".join(body).strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True, help="version without the v prefix")
    parser.add_argument("--out", help="write the notes here instead of stdout")
    args = parser.parse_args(argv)

    version = args.version.strip().lstrip("v")
    if not CHANGELOG.is_file():
        print(f"error: {CHANGELOG} is missing", file=sys.stderr)
        return 1

    notes = extract(CHANGELOG.read_text(encoding="utf-8"), version)
    if not notes:
        print(
            f"error: CHANGELOG.md has no non-empty '## [{version}]' section.\n"
            f"       Add the release notes before tagging, or the release ships empty.",
            file=sys.stderr,
        )
        return 1

    if args.out:
        Path(args.out).write_text(notes + "\n", encoding="utf-8")
        print(f"wrote {len(notes.splitlines())} lines of release notes to {args.out}")
    else:
        print(notes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
