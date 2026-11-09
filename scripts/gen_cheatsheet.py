"""Generate `GHYDRA_CHEATSHEET.md`: every command, one line each.

The command surface is 40 groups and ~150 commands, and the CLI reference that
documents it is 44 KB — too long to scan when you already know roughly what you
want. A cheat sheet is one line per command, and it is **generated**, so it can
never name a command that does not exist:

    python scripts/gen_cheatsheet.py            # write the document
    python scripts/gen_cheatsheet.py --check    # fail when it is stale

The first line of each command's help is the summary: the same text `--help`
prints, which keeps the cheat sheet and the CLI from disagreeing.
"""

from __future__ import annotations

import argparse
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = os.path.join(ROOT, "docs")
DOCUMENT = os.path.join(DOCS, "GHYDRA_CHEATSHEET.md")

#: The commands people reach for first. Hand-written, and checked as a set: the
#: generator fails if one of these is not a real command any more.
MOST_USED = (
    "instances list",
    "functions decompile",
    "functions analyze",
    "analysis overview",
    "analysis context-pack",
    "analysis capabilities-summary",
    "analysis taint",
    "assert",
    "mission start",
    "runbook record",
    "fleet overview",
    "bsim ingest",
    "bsim query",
    "twin build",
    "inspect",
    "doctor",
    "headless start",
    "headless stop",
    "report build",
    "x64dbg status",
    "kuna status",
)

PREAMBLE = """# The cheat sheet

One line per command. **Generated** from the CLI itself by
`scripts/gen_cheatsheet.py`, so a command listed here exists — and `--check`
fails when it stops existing.

The summary of each line is the first line of its `--help`, which is the text the
CLI prints. Read [GHYDRA_CLI.md](GHYDRA_CLI.md) for the arguments of any one of
them, and [GHYDRA_RECIPES.md](GHYDRA_RECIPES.md) for the jobs that combine them.

## The ones you will actually use

"""


def _tree():
    """The click tree, as [(path, summary, is_group)]."""
    sys.path.insert(0, ROOT)
    from ghydra.cli.main import cli
    rows = []
    for name, command in cli.commands.items():
        subcommands = getattr(command, "commands", None)
        if subcommands:
            for sub_name, sub in subcommands.items():
                summary = (sub.help or "").strip().splitlines()
                rows.append((f"{name} {sub_name}",
                             summary[0] if summary else "", False))
        else:
            summary = (command.help or "").strip().splitlines()
            rows.append((name, summary[0] if summary else "", False))
    return rows


def _resolve(path: str):
    """The command a path names, or None."""
    sys.path.insert(0, ROOT)
    from ghydra.cli.main import cli
    group, _, sub = path.partition(" ")
    command = cli.commands.get(group)
    if command is None:
        return None
    if not sub:
        return command
    return (getattr(command, "commands", None) or {}).get(sub)


def render() -> str:
    rows = _tree()
    missing = [path for path in MOST_USED if _resolve(path) is None]
    if missing:
        raise SystemExit(
            "the cheat sheet names commands that no longer exist: "
            + ", ".join(missing))

    lines = [PREAMBLE.rstrip("\n"), ""]
    lines.append("| Command | What it does |")
    lines.append("| --- | --- |")
    for path in MOST_USED:
        command = _resolve(path)
        summary = (command.help or "").strip().splitlines()
        lines.append(f"| `ghydra {path}` | "
                     f"{(summary[0] if summary else '').replace('|', chr(92) + '|')} |")
    lines.append("")
    lines.append("## Every command")
    lines.append("")
    lines.append(f"`{len(rows)}` commands in "
                 f"`{len({path.partition(' ')[0] for path, _, _ in rows})}` groups.")
    lines.append("")
    lines.append("| Command | What it does |")
    lines.append("| --- | --- |")
    for path, summary, _ in sorted(rows):
        lines.append(f"| `ghydra {path}` | {summary.replace('|', chr(92) + '|')} |")
    lines.append("")
    lines.append("## Regenerating")
    lines.append("")
    lines.append("```bash")
    lines.append("python scripts/gen_cheatsheet.py           # rewrite this document")
    lines.append("python scripts/gen_cheatsheet.py --check   # fail when it is stale")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="fail when the document is stale")
    arguments = parser.parse_args(argv)
    rendered = render()
    current = ""
    if os.path.exists(DOCUMENT):
        with io.open(DOCUMENT, encoding="utf-8") as handle:
            current = handle.read()
    if arguments.check:
        if rendered != current:
            print("stale: GHYDRA_CHEATSHEET.md does not match the CLI. "
                  "Run: python scripts/gen_cheatsheet.py", file=sys.stderr)
            return 1
        print("ok: the cheat sheet is current")
        return 0
    if rendered == current:
        print("ok: nothing to update")
        return 0
    with io.open(DOCUMENT, "w", encoding="utf-8", newline="") as handle:
        handle.write(rendered)
    print(f"wrote {DOCUMENT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())