"""Generate the rename table for the x64dbg side of the vocabulary.

Phase 1's vocabulary rule (`contract/vocabulary.json`) says every tool is
`namespace_verb` in snake_case. The x64dbg plugin has 80 flat PascalCase tools, and
until they are renamed the two servers cannot be confused-free in one agent. This
generates the table that the rename needs — **read from the plugin's own registry**,
so the mapping is not a guess:

    python scripts/gen_x64dbg_vocabulary.py            # write the table
    python scripts/gen_x64dbg_vocabulary.py --check    # fail when it is stale

The other repository is not a dependency of this one: when it is not checked out
(CI, a fresh clone), the generator validates the committed table instead of
regenerating it. The table is a **proposal for the other side** — this repository
never edits that code.

The rule, applied: a PascalCase name is split into words at the capital that starts
a new word (`SEHChain` is `SEH` + `Chain`, not `S` + `EHChain`), lower-cased, and
prefixed with `x64dbg_`.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCUMENT = os.path.join(ROOT, "contract", "x64dbg-vocabulary.json")
CONTRACT_VERSION = 1

#: The plugin repository: this machine's sibling checkout, or wherever the caller
#: says. The table is generated from it and committed, so CI needs neither.
DEFAULT_REPO = os.path.join(os.path.dirname(ROOT), "x64dbg-mcp-server")
REPO_ENV = "X64DBG_REPO"

NAME_PATTERN = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)+$")


def repository() -> str:
    """The plugin's path, or "" when it is not here."""
    candidate = os.environ.get(REPO_ENV) or DEFAULT_REPO
    tools = os.path.join(candidate, "src", "mcp", "tools.zig")
    return candidate if os.path.exists(tools) else ""


def depascalize(name: str) -> str:
    """`GetSEHChain` -> `get_seh_chain`, `run` -> `run`."""
    spaced = re.sub(r"(?<=[a-z0-9])([A-Z])", r" \1", name)
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", spaced)
    return "_".join(word.lower() for word in spaced.split())


def proposed(name: str) -> str:
    """The name the rule gives a tool."""
    return "x64dbg_" + depascalize(name)


def _commit(repo: str) -> str:
    try:
        result = subprocess.run(["git", "-C", repo, "rev-parse", "--short", "HEAD"],
                                capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except Exception:  # noqa: BLE001 - a note is enough
        return "unknown"


def _protocol(repo: str) -> str:
    path = os.path.join(repo, "src", "core", "mcp_server.zig")
    try:
        with io.open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError:
        return "unknown"
    match = re.search(r'PROTOCOL_VERSION\s*=\s*"([^"]+)"', text)
    return match.group(1) if match else "unknown"


def collect(repo: str) -> list:
    """Every tool, from its registry entry: name, flags, description."""
    path = os.path.join(repo, "src", "mcp", "tools.zig")
    with io.open(path, encoding="utf-8") as handle:
        text = handle.read()
    # An entry starts at `.name = "X"` and ends where the next one starts (or at
    # the end of the registry); the flags live inside that block.
    # Only the *complete* assignments start an entry: the prefix alone also matches
    # inside comments and strings, and a block from one of those has no name.
    matches = list(re.finditer(r'\.name\s*=\s*"([A-Za-z0-9_]+)"', text))
    entries = []
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        block = text[start:end]
        name = match.group(1)
        description = re.search(r'\.description\s*=\s*"((?:[^"\\]|\\.)*)"', block)
        entries.append({
            "current": name,
            "proposed": proposed(name),
            "read_only": bool(re.search(r"\.read_only\s*=\s*true", block)),
            "debug_only": bool(re.search(r"\.debug_only\s*=\s*true", block)),
            "description": (description.group(1) if description else "")[:160],
        })
    return entries


def render(repo: str) -> str:
    entries = collect(repo)
    bridge_names = set()
    tools_path = os.path.join(ROOT, "contract", "tools.json")
    if os.path.exists(tools_path):
        with io.open(tools_path, encoding="utf-8") as handle:
            bridge_names = {tool["name"] for tool in json.load(handle)["tools"]}

    collisions = sorted({entry["proposed"] for entry in entries} & bridge_names)
    document = {
        "contract_version": CONTRACT_VERSION,
        "generated_by": "scripts/gen_x64dbg_vocabulary.py",
        "source": {
            "repository": "danalec/x64dbg-mcp-server (fork of duty1g/x64dbg-mcp-server)",
            "commit": _commit(repo),
            "file": "src/mcp/tools.zig",
            "protocol_version": _protocol(repo),
        },
        "rule": {
            "name_pattern": "^[a-z][a-z0-9]*(_[a-z0-9]+)+$",
            "algorithm": "split the PascalCase name into words at the capital that "
                         "starts a new word (SEHChain is SEH + Chain), lower-case "
                         "them, join with underscores, prefix x64dbg_",
        },
        "status": "proposal — this repository never edits the other one; the table "
                  "is what the rename needs, and the plugin keeps its current names "
                  "as aliases for one release",
        "counts": {
            "tools": len(entries),
            "renamed": sum(1 for entry in entries
                           if entry["current"] != entry["proposed"]),
            "read_only": sum(1 for entry in entries if entry["read_only"]),
            "collisions_with_ghydra": len(collisions),
        },
        "collisions_with_ghydra": collisions,
        "tools": entries,
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def check(document_path: str) -> int:
    """Validate the committed table when the plugin repository is not here."""
    with io.open(document_path, encoding="utf-8") as handle:
        document = json.load(handle)
    problems = []
    entries = document.get("tools") or []
    if len(entries) != 80:
        problems.append(f"the table holds {len(entries)} tools, the registry 80")
    names = [entry["proposed"] for entry in entries]
    if len(names) != len(set(names)):
        problems.append("two tools map to the same name")
    for entry in entries:
        if not NAME_PATTERN.match(entry["proposed"]):
            problems.append(f"{entry['current']} -> {entry['proposed']} breaks the rule")
        if not entry["proposed"].startswith("x64dbg_"):
            problems.append(f"{entry['proposed']} has no x64dbg_ prefix")
    if document.get("collisions_with_ghydra"):
        problems.append("the proposal collides with tools this repository already has: "
                        + ", ".join(document["collisions_with_ghydra"]))
    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    return 1 if problems else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="fail when the table is stale or inconsistent")
    arguments = parser.parse_args(argv)

    repo = repository()
    if not repo:
        if not os.path.exists(DOCUMENT):
            print("the plugin repository is not here and the table is missing: "
                  f"set {REPO_ENV} or run this where the repository is checked out",
                  file=sys.stderr)
            return 1
        code = check(DOCUMENT)
        if not arguments.check:
            print("the plugin repository is not here: the committed table was "
                  "validated instead of regenerated")
        elif code == 0:
            print("ok: the committed x64dbg table is consistent (repository absent)")
        return code

    rendered = render(repo)
    current = ""
    if os.path.exists(DOCUMENT):
        with io.open(DOCUMENT, encoding="utf-8") as handle:
            current = handle.read()
    if arguments.check:
        if rendered != current:
            print("stale: contract/x64dbg-vocabulary.json does not match the plugin "
                  "registry. Run: python scripts/gen_x64dbg_vocabulary.py",
                  file=sys.stderr)
            return 1
        print("ok: the x64dbg vocabulary table is current")
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