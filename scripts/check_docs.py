#!/usr/bin/env python3
"""Prove that the documented surface still matches the code (I13).

The repository has repeatedly shipped contradictory counts: the README said
"110 tools" in one place and "99 tools in 24 namespaces" in another, AGENTS.md
said 110, the FORMATTERS dict had 82 entries for 110 tools, and a sixth copy of
the release version hid in ghydra/x64dbg.py outside scripts/version.py.

This guard counts the real decorators, formatters and REST routes, compares them
with the numbers the docs claim, and fails CI on the first disagreement. It is
deliberately static: no Ghidra, no MCP client and no Java build are needed.

Usage:
    python scripts/check_docs.py            # check, exit 0/1
    python scripts/check_docs.py --report   # print the counts too
"""

from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BRIDGE = ROOT / "bridge_mcp_hydra.py"
RESOURCES = ROOT / "src/main/java/eu/starsong/ghidra/resource"

README_TOOLS = re.compile(r"\*\*(\d+) tools in (\d+) namespaces\*\*")
AGENTS_TOOLS = re.compile(r"(\d+) MCP tools in (\d+) namespaces")
ROUTE = re.compile(r"\bapp\.(get|post|put|patch|delete)\(")


def bridge_surface() -> dict[str, int]:
    """Count MCP tools/prompts/resources and FORMATTERS entries from the AST."""
    tree = ast.parse(BRIDGE.read_text(encoding="utf-8"))
    counts: dict[str, int] = {
        "tools": 0, "prompts": 0, "resources": 0, "formatters": 0,
        "namespaces": 0,
    }
    namespaces: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if (isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "mcp"):
                    if target.attr == "tool":
                        counts["tools"] += 1
                        namespaces.add(node.name.split("_", 1)[0])
                    elif target.attr == "prompt":
                        counts["prompts"] += 1
                    elif target.attr == "resource":
                        counts["resources"] += 1
        if (isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "FORMATTERS" for t in node.targets)
                and isinstance(node.value, ast.Dict)):
            counts["formatters"] = len(node.value.keys)

    counts["namespaces"] = len(namespaces)
    return counts


def route_count() -> int:
    return sum(len(ROUTE.findall(path.read_text(encoding="utf-8")))
               for path in sorted(RESOURCES.glob("*.java")))


def documented_counts() -> dict[str, tuple[int, int] | None]:
    readme = README_TOOLS.search((ROOT / "README.md").read_text(encoding="utf-8"))
    agents = AGENTS_TOOLS.search((ROOT / "AGENTS.md").read_text(encoding="utf-8"))
    return {
        "README.md": (int(readme.group(1)), int(readme.group(2))) if readme else None,
        "AGENTS.md": (int(agents.group(1)), int(agents.group(2))) if agents else None,
    }


def compare_counts(surface: dict, documented: dict) -> list[str]:
    """The pure half: given real and claimed counts, return the drift messages."""
    problems: list[str] = []
    tools, namespaces = surface["tools"], surface["namespaces"]
    for name, claimed in documented.items():
        if claimed is None:
            problems.append(f"{name}: no 'N tools in M namespaces' line found")
            continue
        claimed_tools, claimed_namespaces = claimed
        if claimed_tools != tools:
            problems.append(
                f"{name}: claims {claimed_tools} tools, code has {tools}")
        if claimed_namespaces != namespaces:
            problems.append(
                f"{name}: claims {claimed_namespaces} namespaces, code has {namespaces}")
    if surface["formatters"] != tools:
        problems.append(
            f"FORMATTERS has {surface['formatters']} entries for {tools} tools")
    return problems


def version_copy_ok() -> bool:
    """The sixth version copy must follow ghydra.__version__, not be hardcoded."""
    text = (ROOT / "ghydra/x64dbg.py").read_text(encoding="utf-8")
    return '"version": __version__' in text and '"version": "3.' not in text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="store_true", help="print the counts")
    args = parser.parse_args()

    surface = bridge_surface()
    routes = route_count()
    documented = documented_counts()
    problems = compare_counts(surface, documented)

    check = subprocess.run(
        [sys.executable, str(ROOT / "scripts/version.py"), "--check"],
        cwd=ROOT, capture_output=True, text=True)
    if check.returncode != 0:
        problems.append("scripts/version.py --check failed: " + check.stdout.strip())
    if not version_copy_ok():
        problems.append(
            "ghydra/x64dbg.py must use __version__ (scripts/version.py's sixth copy)")

    if args.report:
        print(f"MCP tools:        {surface['tools']}")
        print(f"MCP prompts:      {surface['prompts']}")
        print(f"MCP resources:    {surface['resources']}")
        print(f"FORMATTERS:       {surface['formatters']}")
        print(f"Namespaces:       {surface['namespaces']}")
        print(f"REST routes:      {routes}")
        for name, claimed in documented.items():
            print(f"{name + ':':<18}{claimed}")

    if problems:
        for problem in problems:
            print(f"FAIL {problem}", file=sys.stderr)
        print(f"\n{len(problems)} documentation drift(s). Fix the docs, not this guard.",
              file=sys.stderr)
        return 1

    print(f"OK: {surface['tools']} tools / {surface['formatters']} formatters / "
          f"{surface['namespaces']} namespaces / {routes} REST routes / versions agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
