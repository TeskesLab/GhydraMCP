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
import os
import glob

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


# --------------------------------------------------------------- catalogue
def catalogue_problems() -> list:
    """The generated tool catalogue must be current."""
    sys.path.insert(0, ROOT)
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "gen_tools_doc", os.path.join(ROOT, "scripts", "gen_tools_doc.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as failure:  # noqa: BLE001 - the guard reports, it does not crash
        return [f"cannot load scripts/gen_tools_doc.py: {failure}"]
    try:
        rendered = module.render(module.collect())
    except Exception as failure:  # noqa: BLE001
        return [f"the tool catalogue cannot be generated: {failure}"]
    document = os.path.join(ROOT, "docs", "GHYDRA_TOOLS.md")
    if not os.path.exists(document):
        return ["GHYDRA_TOOLS.md is missing: run scripts/gen_tools_doc.py"]
    with open(document, encoding="utf-8") as handle:
        current = handle.read()
    if rendered != current:
        return ["GHYDRA_TOOLS.md is stale: run scripts/gen_tools_doc.py"]
    return []


# ------------------------------------------------------- duplicate headings
#: Where a repeated heading is the design (one section per release).
REPEATING_HEADINGS_ALLOWED = {"CHANGELOG.md"}


def duplicate_heading_problems() -> list:
    """A document that repeats a heading at the same level has been edited badly.

    The index is generated from the headings, so a duplicate makes the index
    ambiguous — and in practice it means a block was pasted twice (measured: the
    CLI reference carried the same 17-line section 18 times).
    """
    problems = []
    for relative in sorted(INDEXED_DOCUMENTS):
        path = os.path.join(ROOT, relative)
        if not os.path.exists(path) or relative in REPEATING_HEADINGS_ALLOWED:
            continue
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        in_toc = False
        seen = {}
        parents = {}          # level -> the title of the enclosing section
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped == "<!-- toc -->":
                in_toc = True
                continue
            if stripped == "<!-- /toc -->":
                in_toc = False
                continue
            if in_toc or not line.startswith("#"):
                continue
            level = len(line) - len(line.lstrip("#"))
            if level < 2:
                continue
            title = line[level:].strip()
            # A heading is identified by where it sits: `### Tests` under
            # "Troubleshooting" and under "Adding New Tests" are two sections,
            # not a duplicate. The same title under the *same* parent is.
            parent = parents.get(level - 1)
            key = (level, title, parent)
            if key in seen:
                where = f" under '{parent}'" if parent else ""
                problems.append(
                    f"{relative}:{number}: heading '{title}' repeats level {level}"
                    f"{where} (first at line {seen[key]})")
            else:
                seen[key] = number
            parents[level] = title
            for deeper in [key_level for key_level in parents if key_level > level]:
                del parents[deeper]
    return problems


def _load_script(name: str):
    """Import a sibling script as a module, or return the failure."""
    sys.path.insert(0, ROOT)
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(ROOT, "scripts", name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def documented_commands_problems() -> list:
    """Every `ghydra …` command a document shows must exist."""
    try:
        module = _load_script("check_doc_commands")
    except Exception as failure:  # noqa: BLE001
        return [f"cannot load scripts/check_doc_commands.py: {failure}"]
    problems = []
    for path in sorted(glob.glob(os.path.join(ROOT, "*.md"))):
        relative = os.path.basename(path)
        with open(path, encoding="utf-8") as handle:
            problems.extend(module.problems_in(relative, handle.read()))
    return problems


def runner_flags_problems() -> list:
    """Every suite the runner has must be named in the testing document.

    The document lists the flags by hand, because each carries a description
    the runner does not know. That is a list that can fall behind, and it did:
    a suite was added and the document was not updated. The runner's own usage
    line is generated from the suites, so this is the second half of the same
    promise.
    """
    document = os.path.join(ROOT, "docs", "TESTING.md")
    if not os.path.exists(document):
        return ["docs/TESTING.md is missing"]
    try:
        runner = _load_script("../run_tests")
    except Exception as failure:  # noqa: BLE001
        return [f"cannot load run_tests.py: {failure}"]
    with open(document, encoding="utf-8") as handle:
        text = handle.read()
    return [f"docs/TESTING.md does not mention the suite {flag}"
            for flag in sorted(runner.SUITES) if flag not in text]


def x64dbg_vocabulary_problems() -> list:
    """The rename table must be current — or, without the plugin repo, consistent."""
    try:
        module = _load_script("gen_x64dbg_vocabulary")
    except Exception as failure:  # noqa: BLE001
        return [f"cannot load scripts/gen_x64dbg_vocabulary.py: {failure}"]
    if not module.repository():
        # The other repository is not a dependency of this one: validate what is
        # committed instead of pretending it was regenerated.
        if not os.path.exists(module.DOCUMENT):
            return ["contract/x64dbg-vocabulary.json is missing"]
        code = module.check(module.DOCUMENT)
        return [] if code == 0 else ["the committed x64dbg vocabulary is inconsistent"]
    try:
        rendered = module.render(module.repository())
    except Exception as failure:  # noqa: BLE001
        return [f"the x64dbg vocabulary cannot be generated: {failure}"]
    with open(module.DOCUMENT, encoding="utf-8") as handle:
        current = handle.read()
    if rendered != current:
        return ["contract/x64dbg-vocabulary.json is stale: "
                "run scripts/gen_x64dbg_vocabulary.py"]
    return []


def cheatsheet_current_problems() -> list:
    """The generated cheat sheet must match the CLI."""
    try:
        module = _load_script("gen_cheatsheet")
    except Exception as failure:  # noqa: BLE001
        return [f"cannot load scripts/gen_cheatsheet.py: {failure}"]
    try:
        rendered = module.render()
    except SystemExit as failure:
        return [f"the cheat sheet names commands that no longer exist: {failure}"]
    document = os.path.join(ROOT, "docs", "GHYDRA_CHEATSHEET.md")
    if not os.path.exists(document):
        return ["GHYDRA_CHEATSHEET.md is missing: run scripts/gen_cheatsheet.py"]
    with open(document, encoding="utf-8") as handle:
        current = handle.read()
    if rendered != current:
        return ["GHYDRA_CHEATSHEET.md is stale: run scripts/gen_cheatsheet.py"]
    return []


def errors_current_problems() -> list:
    """The generated error reference must be current."""
    sys.path.insert(0, ROOT)
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "gen_errors_doc", os.path.join(ROOT, "scripts", "gen_errors_doc.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as failure:  # noqa: BLE001
        return [f"cannot load scripts/gen_errors_doc.py: {failure}"]
    try:
        rendered = module.render()
    except Exception as failure:  # noqa: BLE001
        return [f"the error reference cannot be generated: {failure}"]
    document = os.path.join(ROOT, "docs", "GHYDRA_ERRORS.md")
    if not os.path.exists(document):
        return ["GHYDRA_ERRORS.md is missing: run scripts/gen_errors_doc.py"]
    with open(document, encoding="utf-8") as handle:
        current = handle.read()
    if rendered != current:
        return ["GHYDRA_ERRORS.md is stale: run scripts/gen_errors_doc.py"]
    return []


def index_current_problems() -> list:
    """The big references must carry a current generated index."""
    sys.path.insert(0, ROOT)
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "gen_toc", os.path.join(ROOT, "scripts", "gen_toc.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as failure:  # noqa: BLE001
        return [f"cannot load scripts/gen_toc.py: {failure}"]
    problems = []
    for relative, depth in module.INDEXED.items():
        path = os.path.join(ROOT, relative)
        if not os.path.exists(path):
            problems.append(f"{relative} is missing")
            continue
        with open(path, encoding="utf-8") as handle:
            current = handle.read()
        try:
            updated = module.apply(current, depth)
        except SystemExit as failure:
            problems.append(f"{relative}: {failure}")
            continue
        if updated != current:
            problems.append(f"{relative}: the index is stale, run scripts/gen_toc.py")
    return problems


#: The documents the guards read: the generated ones and the big references.
INDEXED_DOCUMENTS = ("docs/GHIDRA_HTTP_API.md", "docs/GHYDRA_CLI.md",
                     "docs/DOCUMENTATION.md", "docs/GHYDRA_CONCEPTS.md",
                     "docs/GHYDRA_RECIPES.md", "docs/GHYDRA_TROUBLESHOOTING.md",
                     "docs/ARCHITECTURE.md", "docs/GHYDRA_TOOLS.md",
                     "docs/GHYDRA_GETTING_STARTED.md", "docs/TESTING.md",
                     "CHANGELOG.md")

# ------------------------------------------------------------------- links
def index_link_problems() -> list:
    """Every local document linked from the index must exist."""
    index = os.path.join(ROOT, "docs", "DOCUMENTATION.md")
    if not os.path.exists(index):
        return ["DOCUMENTATION.md is missing: the documentation has no map"]
    with open(index, encoding="utf-8") as handle:
        text = handle.read()
    problems = []
    # Links are relative to the document that holds them, not to the repository.
    base = os.path.dirname(index)
    for target in sorted(set(re.findall(r"\]\(([^)#]+\.md)\)", text))):
        if target.startswith(("http://", "https://")):
            continue
        if not os.path.exists(os.path.join(base, target)):
            problems.append(f"DOCUMENTATION.md links {target}, which does not exist")
    return problems


# -------------------------------------------------------------------- links
def broken_link_problems() -> list:
    """Every local link in every document must resolve, from where the file is.

    A relative link means "next to me", so the base is the document's directory.
    A link to a heading (`#section`) or to the web is not checked here.
    """
    problems = []
    # Only the documents the repository ships: `docs/` also holds gitignored notes
    # that are not maintained as part of it (and are written from the root).
    try:
        listed = subprocess.run(["git", "ls-files", "*.md"], cwd=ROOT,
                                capture_output=True, text=True, check=True)
        documents = [os.path.join(ROOT, line.strip())
                     for line in listed.stdout.splitlines() if line.strip()]
    except Exception:  # noqa: BLE001 - no git: fall back to the tree
        documents = sorted(glob.glob(os.path.join(ROOT, "*.md")))
        documents.extend(sorted(glob.glob(os.path.join(ROOT, "docs", "**", "*.md"),
                                         recursive=True)))
    for document in documents:
        relative = os.path.relpath(document, ROOT).replace(os.sep, "/")
        with open(document, encoding="utf-8") as handle:
            text = handle.read()
        for target in sorted(set(re.findall(r"\]\(([^)\s]+)\)", text))):
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            local = target.split("#")[0]
            if not local:
                continue
            if not os.path.exists(os.path.join(os.path.dirname(document), local)):
                problems.append(f"{relative} links {target}, which does not exist")
    return problems


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

    problems.extend(catalogue_problems())
    problems.extend(index_link_problems())
    problems.extend(duplicate_heading_problems())
    problems.extend(broken_link_problems())
    problems.extend(index_current_problems())
    problems.extend(errors_current_problems())
    problems.extend(documented_commands_problems())
    problems.extend(cheatsheet_current_problems())
    problems.extend(x64dbg_vocabulary_problems())
    problems.extend(runner_flags_problems())
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
