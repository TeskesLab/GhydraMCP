#!/usr/bin/env python3
"""Generate the bridge's copy of the core modules (I1).

The bridge ships as **one file** and must not import the ``ghydra`` package, so
the pure helpers it shares with the CLI are duplicated. This script removes the
duplication for the modules listed in ``CORE_MODULES``: it reads each one,
renames its public names into the bridge's private namespace (``_core_*``), and
writes them into ``bridge_mcp_hydra.py`` between markers.

    python scripts/gen_core.py            # write the regions
    python scripts/gen_core.py --check    # fail when a region is stale

The check is what makes the mechanism trustworthy: CI runs it, so a change to a
core module that was not regenerated fails instead of silently leaving the two
surfaces disagreeing — which is exactly the failure mode I1 exists to remove.

Only **pure functions** belong in a core module. A generated copy of a pure
function is identical on both sides; anything with I/O or hidden state is not.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BRIDGE = os.path.join(ROOT, "bridge_mcp_hydra.py")

BEGIN = "# >>> generated from {source} ({digest}) — edit the core, then run scripts/gen_core.py"
END = "# <<< end generated from {source}"

#: The core modules that are generated into the bridge, in order.
CORE_MODULES = ("ghydra/core/digest.py",)

#: Public name -> the private name the bridge uses.
RENAMES = {
    "VOLATILE_KEYS": "_CORE_VOLATILE_KEYS",
    "canonical": "_core_canonical",
    "digest": "_core_digest",
    "stable_result": "_core_stable_result",
}

#: Names the generated code may reference from the bridge's own imports.
ALLOWED_EXTERNALS = {"json", "hashlib", "Any", "Iterable", "str", "dict", "set",
                     "isinstance", "value", "volatile", "payload", "dropped",
                     "key", "item", "encode", "sha256", "dumps", "(", ")"}


def _rename(node: ast.AST) -> None:
    """Rename the core's public names in place, and drop the annotations.

    The annotations are dropped so the generated block needs no extra imports;
    they are documentation, and the core module keeps them.
    """
    for child in ast.walk(node):
        if isinstance(child, ast.FunctionDef):
            child.name = RENAMES.get(child.name, child.name)
            child.returns = None
            for argument in list(child.args.args) + list(child.args.kwonlyargs):
                argument.annotation = None
            if child.args.vararg is not None:
                child.args.vararg.annotation = None
            if child.args.kwarg is not None:
                child.args.kwarg.annotation = None
        elif isinstance(child, ast.Assign):
            for target in child.targets:
                if isinstance(target, ast.Name) and target.id in RENAMES:
                    target.id = RENAMES[target.id]
        elif isinstance(child, ast.Name) and child.id in RENAMES:
            child.id = RENAMES[child.id]


def _source_of(module_path: str) -> str:
    """The body of a core module, renamed and unparsed."""
    with open(module_path, encoding="utf-8") as handle:
        text = handle.read()
    tree = ast.parse(text)
    body = []
    for node in tree.body:
        # Imports and the module docstring stay in the core module: the bridge
        # already imports json and hashlib, and its docstring is its own.
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Expr)):
            continue
        _rename(node)
        body.append(node)
    return "\n\n".join(ast.unparse(node) for node in body)


def _region(module_path: str) -> str:
    relative = module_path
    function_source = _source_of(os.path.join(ROOT, module_path))
    module_digest = hashlib.sha256(
        function_source.encode("utf-8")).hexdigest()[:16]
    return "\n".join([
        BEGIN.format(source=relative, digest=module_digest),
        function_source,
        END.format(source=relative),
    ])


def _bridge_text() -> str:
    with open(BRIDGE, encoding="utf-8") as handle:
        return handle.read()


def _splice(bridge: str, module_path: str, region: str) -> str:
    """Put the region where it belongs, replacing the previous copy."""
    begin = BEGIN.format(source=module_path, digest="").split(" (")[0]
    end = END.format(source=module_path)
    start = bridge.find(begin)
    if start < 0:
        # First generation: the block goes just before the tool groups, after
        # every helper it could reference.
        anchor = "_TOOL_GROUPS = {"
        if anchor not in bridge:
            raise SystemExit(f"cannot find the insertion point in {BRIDGE}")
        return bridge.replace(anchor, region + "\n\n\n" + anchor, 1)
    finish = bridge.find(end, start)
    if finish < 0:
        raise SystemExit(f"the begin marker for {module_path} has no end marker")
    finish += len(end)
    return bridge[:start] + region + bridge[finish:]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="fail when a generated region is stale")
    arguments = parser.parse_args(argv)

    bridge = _bridge_text()
    original = bridge
    for module_path in CORE_MODULES:
        bridge = _splice(bridge, module_path, _region(module_path))

    if arguments.check:
        if bridge != original:
            print("stale: the bridge's generated core does not match the "
                  "core modules. Run: python scripts/gen_core.py", file=sys.stderr)
            return 1
        print(f"ok: {len(CORE_MODULES)} core module(s) are generated and current")
        return 0

    if bridge == original:
        print("ok: nothing to regenerate")
        return 0
    with open(BRIDGE, "w", encoding="utf-8", newline="") as handle:
        handle.write(bridge)
    print(f"wrote {len(CORE_MODULES)} core module(s) into bridge_mcp_hydra.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())