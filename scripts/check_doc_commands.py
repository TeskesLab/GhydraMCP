"""Check that every `ghydra …` command a document shows really exists.

A documented command that does not exist is worse than no documentation: the
reader runs it, gets a usage error, and stops trusting the rest of the page.
The measurement found two (`ghydra triage`, `ghydra tools groups`) that had been
written from memory.

What is checked, only inside Markdown code fences (prose is not a contract):

* the group and the subcommand resolve in the Click tree;
* every flag is one the command declares — including the second half of a
  `--dry-run/--apply` pair, and the global flags.

A leaf command's positional arguments are skipped, and so are the values of
options that take one, so `ghydra --port 8193 functions list` is read as
`functions list`.

    python scripts/check_doc_commands.py            # report and exit 0/1
"""

from __future__ import annotations

import glob
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Flags that every command accepts, from the root group.
GLOBAL_FLAGS = {
    "--json", "--host", "--port", "--timeout", "--dry-run", "--verbose",
    "--quiet", "--help", "--version", "--no-color", "--pager", "-h", "-p",
    "-H", "-j", "-v", "-q",
}

COMMAND = re.compile(r"^\s*ghydra\s+(.*)$")


def _tree() -> dict:
    """{group: {sub: command}} plus the group commands themselves."""
    sys.path.insert(0, ROOT)
    from ghydra.cli.main import cli
    return cli.commands


def _flags_of(command) -> set:
    flags = set()
    for param in command.params:
        flags.update(param.opts)
        flags.update(getattr(param, "secondary_opts", ()) or ())
    return flags


def _looks_like_value(token: str) -> bool:
    return not token.startswith("-")


def scan(text: str, groups=None) -> list:
    """[(line number, group, sub, flags)] for every command in a code fence."""
    groups = _tree() if groups is None else groups
    found = []
    in_fence = False
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence and not getattr(scan, "everything", False):
            continue
        match = COMMAND.match(line)
        if not match:
            continue
        # A command line is a pipeline: the flags after `|`, `&&`, `;` or a
        # redirect belong to another program (`jq -r …`), not to this one.
        raw = match.group(1)
        for separator in ("|", "&&", ";", ">", "<"):
            raw = raw.split(separator)[0]
        tokens = raw.split()
        if not tokens:
            continue
        # The group is the first token the CLI knows. Everything before it is a
        # global flag (and possibly its value); everything after it belongs to
        # the command.
        start = next((index for index, token in enumerate(tokens)
                      if token in groups), None)
        if start is None:
            # No known group: report the first token that is not a flag. A typo
            # and prose that begins with `ghydra` both surface here.
            start = next((index for index, token in enumerate(tokens)
                          if not token.startswith("-")), None)
            if start is None:
                continue
        before, after = tokens[:start], tokens[start:]
        flags = [token.split("=")[0] for token in before if token.startswith("-")]
        flags.extend(token.split("=")[0] for token in after
                     if token.startswith("-"))
        positionals = [token for token in after if not token.startswith("-")]
        group = positionals[0]
        sub = positionals[1] if len(positionals) > 1 else None
        found.append((number, group, sub, flags))
    return found


def problems_in(relative: str, text: str) -> list:
    """Every command the document shows that the CLI does not have."""
    commands = _tree()
    # A shell script has no fences: every `ghydra …` line in it is a command.
    scan.everything = relative.endswith(".sh")
    problems = []
    for number, group, sub, flags in scan(text, commands):
        command = commands.get(group)
        if command is None:
            # A word after `ghydra` that is not a command: prose that starts with
            # the tool's name, or a real typo. Both are worth knowing about.
            problems.append(f"{relative}:{number}: no command group '{group}'")
            continue
        subcommands = getattr(command, "commands", None) or {}
        if subcommands:
            if sub is None:
                continue
            command = subcommands.get(sub)
            if command is None:
                problems.append(
                    f"{relative}:{number}: '{group}' has no command '{sub}'")
                continue
            path = f"{group} {sub}"
        else:
            path = group
        allowed = _flags_of(command) | GLOBAL_FLAGS
        for flag in flags:
            if flag not in allowed:
                problems.append(
                    f"{relative}:{number}: '{path}' has no option '{flag}'")
    return problems


def _documents() -> list:
    """The files whose `ghydra …` lines are a promise: docs and example scripts."""
    paths = sorted(glob.glob(os.path.join(ROOT, "*.md")))
    paths.extend(sorted(glob.glob(os.path.join(ROOT, "examples", "**", "*.sh"),
                                  recursive=True)))
    return paths


def main() -> int:
    problems = []
    for path in _documents():
        relative = os.path.relpath(path, ROOT).replace(os.sep, "/")
        with io.open(path, encoding="utf-8") as handle:
            problems.extend(problems_in(relative, handle.read()))
    if problems:
        for problem in problems:
            print(f"FAIL {problem}", file=sys.stderr)
        print(f"\n{len(problems)} documented command(s) the CLI does not have.",
              file=sys.stderr)
        return 1
    print("ok: every documented command exists")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())