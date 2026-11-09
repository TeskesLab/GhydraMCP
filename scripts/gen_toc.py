"""Generate a table of contents for the large documents, and check it.

`GHIDRA_HTTP_API.md` is 48 KB of routes and `GHYDRA_CLI.md` is 55 KB of commands.
A reader cannot find the section they want in either, and a hand-written index is
wrong the first time a section is renamed.

So the index is generated from the headings, between markers:

    <!-- toc -->
    ...generated...
    <!-- /toc -->

    python scripts/gen_toc.py                 # write every indexed document
    python scripts/gen_toc.py --check         # fail when one is stale

The heading text is used as-is; anchors follow GitHub's rule (lower-case, spaces
to dashes, punctuation dropped), so the links work on the forge and on GitHub.
"""

from __future__ import annotations

import argparse
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BEGIN = "<!-- toc -->"
END = "<!-- /toc -->"

#: The documents that get an index, and how deep it goes.
INDEXED = {
    "GHIDRA_HTTP_API.md": 3,
    "GHYDRA_CLI.md": 3,
    # The medium guides: their sections are few enough for a level-2 index,
    # which is what a reader needs to see the shape of the page.
    "GHYDRA_GETTING_STARTED.md": 2,
    "GHYDRA_CONCEPTS.md": 2,
    "GHYDRA_RECIPES.md": 2,
    "GHYDRA_TROUBLESHOOTING.md": 2,
    "GHYDRA_OUTPUT.md": 2,
    "GHYDRA_BSIM.md": 2,
    "ARCHITECTURE.md": 2,
    "TESTING.md": 2,
}


def _anchor(text: str) -> str:
    """GitHub's anchor for a heading."""
    slug = text.strip().lower()
    slug = re.sub(r"[`*_]", "", slug)
    slug = re.sub(r"[^\w\s-]", "", slug)
    return re.sub(r"\s+", "-", slug)


def _headings(text: str, depth: int) -> list:
    """(level, title) for every heading up to `depth`, outside the toc block."""
    found = []
    in_toc = False
    for line in text.splitlines():
        if line.strip() == BEGIN:
            in_toc = True
            continue
        if line.strip() == END:
            in_toc = False
            continue
        if in_toc or not line.startswith("#"):
            continue
        match = re.match(r"^(#{1,6})\s+(.*)$", line)
        if not match:
            continue
        level = len(match.group(1))
        if level < 2 or level > depth:
            continue
        found.append((level, match.group(2).strip()))
    return found


def build_toc(text: str, depth: int) -> str:
    """The Markdown index for a document."""
    lines = [BEGIN, ""]
    for level, title in _headings(text, depth):
        indent = "  " * (level - 2)
        lines.append(f"{indent}- [{title}](#{_anchor(title)})")
    lines.extend(["", END])
    return "\n".join(lines)


def apply(text: str, depth: int) -> str:
    """The document with a current index between the markers."""
    toc = build_toc(text, depth)
    if BEGIN in text and END in text:
        start = text.index(BEGIN)
        finish = text.index(END, start) + len(END)
        return text[:start] + toc + text[finish:]
    raise SystemExit(f"the document has no {BEGIN} / {END} markers")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="fail when an index is stale")
    arguments = parser.parse_args(argv)

    stale = []
    for relative, depth in INDEXED.items():
        path = os.path.join(ROOT, relative)
        with io.open(path, encoding="utf-8") as handle:
            current = handle.read()
        updated = apply(current, depth)
        if arguments.check:
            if updated != current:
                stale.append(relative)
            continue
        if updated != current:
            with io.open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write(updated)
            print(f"indexed {relative} ({len(_headings(current, depth))} entries)")
        else:
            print(f"ok: {relative} is current")
    if arguments.check:
        if stale:
            print("stale index: " + ", ".join(stale)
                  + ". Run: python scripts/gen_toc.py", file=sys.stderr)
            return 1
        print("ok: every index is current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())