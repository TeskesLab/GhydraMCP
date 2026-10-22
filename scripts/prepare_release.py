#!/usr/bin/env python3
"""Prepare a release commit: CHANGELOG section + version constants.

This is the local half of the release automation. It does the part that is
easy to get wrong by hand — moving the ``Unreleased`` notes into a dated
section and writing the same version into all five version locations — and
then refuses to leave the tree in a state the CI would reject.

    python scripts/prepare_release.py --version 3.1.0
    python scripts/prepare_release.py --version 3.1.0 --dry-run

Afterwards the release itself is a tag push; the workflows build, publish and
verify it on both GitHub and the Forgejo instance.
"""

from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import release_notes  # noqa: E402
import version as version_mod  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"

UNRELEASED_RE = re.compile(r"^## \[Unreleased\]\s*$")
SECTION_RE = re.compile(r"^## \[([^\]]+)\]")


def split_unreleased(lines: list[str]) -> tuple[int, int, list[str]]:
    """Return (heading index, next-section index, content lines)."""
    start = None
    for index, line in enumerate(lines):
        if UNRELEASED_RE.match(line):
            start = index
            break
    if start is None:
        raise SystemExit("error: CHANGELOG.md has no '## [Unreleased]' section")

    end = len(lines)
    for index in range(start + 1, len(lines)):
        if SECTION_RE.match(lines[index]):
            end = index
            break

    content = lines[start + 1 : end]
    while content and not content[0].strip():
        content.pop(0)
    while content and not content[-1].strip():
        content.pop()
    return start, end, content


def prepare(version: str, date: str, dry_run: bool) -> int:
    version = version_mod.normalize(version)
    if not version_mod.VERSION_RE.match(version):
        raise SystemExit(f"error: '{version}' is not a valid version (want X.Y.Z[-TAG])")

    text = CHANGELOG.read_text(encoding="utf-8")
    lines = text.splitlines()

    start, end, content = split_unreleased(lines)
    if not content:
        raise SystemExit(
            "error: the '## [Unreleased]' section is empty — there is nothing to release."
        )

    if any(SECTION_RE.match(line) and SECTION_RE.match(line).group(1) == version for line in lines):
        raise SystemExit(
            f"error: CHANGELOG.md already has a '## [{version}]' section."
        )

    rebuilt = (
        lines[: start + 1]
        + ["", f"## [{version}] - {date}", ""]
        + content
        + [""]
        + lines[end:]
    )

    print(f"CHANGELOG.md: '## [Unreleased]' ({len(content)} lines) -> '## [{version}] - {date}'")

    if dry_run:
        print("dry run: nothing written")
        return 0

    CHANGELOG.write_text("\n".join(rebuilt).rstrip() + "\n", encoding="utf-8")

    changed = version_mod.write_version(version)
    print(f"version constants: wrote {version} to {len(changed)} file(s)")
    for rel in changed:
        print(f"  {rel}")

    if version_mod.check(version) != 0:
        raise SystemExit("error: the tree is still inconsistent after the rewrite")

    notes = release_notes.extract(CHANGELOG.read_text(encoding="utf-8"), version)
    if not notes:
        raise SystemExit(f"error: '## [{version}]' has no release notes")

    print("\nRelease prepared. Review the diff, then:")
    print(f"  git add -A")
    print(f"  git commit -m \"chore(release): v{version}\"")
    print(f"  git tag v{version}")
    print(f"  git push github main && git push github v{version}")
    print(f"  git push forgejo main && git push forgejo v{version}")
    print("\nThe tag push is what triggers the release workflows on both platforms.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True, help="release version, e.g. 3.1.0")
    parser.add_argument(
        "--date",
        default=dt.date.today().isoformat(),
        help="release date (default: today)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would change without writing anything",
    )
    args = parser.parse_args(argv)
    return prepare(args.version, args.date, args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
