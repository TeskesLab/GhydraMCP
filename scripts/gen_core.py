"""Generate the bridge's copy of the core modules (I1).

The bridge ships as **one file** and must not import the ``ghydra`` package, so
the pure helpers it shares with the CLI are duplicated. This script removes the
duplication for the modules listed in ``CORE_MODULES``: it reads each one,
renames its public names into the bridge's private namespace, and writes them
into ``bridge_mcp_hydra.py`` between markers.

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
CORE_MODULES = (
    "ghydra/core/digest.py",
    "ghydra/core/runbook.py",
    "ghydra/core/hints.py",
    "ghydra/core/cache.py",
    "ghydra/core/diff.py",
    "ghydra/core/fleet.py",
    "ghydra/core/capabilities.py",
    "ghydra/core/contextpack.py",
)

#: Per module, the public name -> the private name the bridge uses.
CORE_RENAMES = {
    "ghydra/core/digest.py": {
        "VOLATILE_KEYS": "_CORE_VOLATILE_KEYS",
        "canonical": "_core_canonical",
        "digest": "_core_digest",
        "stable_result": "_core_stable_result",
    },
    "ghydra/core/runbook.py": {
        "RUNBOOK_METHODS": "_CORE_RUNBOOK_METHODS",
        "BadSteps": "_CoreBadSteps",
        "BadEntry": "_CoreBadEntry",
        "validate_steps": "_core_validate_steps",
    },
    "ghydra/core/cache.py": {
        "CACHE_VERSION": "_CORE_CACHE_VERSION",
        "IDENTITY_FIELDS": "_CORE_CACHE_IDENTITY_FIELDS",
        "STATISTIC_FIELDS": "_CORE_CACHE_STATISTIC_FIELDS",
        "identity_from_program": "_core_cache_identity",
        "cache_key": "_core_cache_key",
        # Names the module imports (imports are stripped from the generated
        # block, so the bridge's own generated name is used instead).
        "digest": "_core_digest",
    },
    "ghydra/core/diff.py": {
        "PROGRAM_FIELDS": "_CORE_DIFF_PROGRAM_FIELDS",
        "name_set": "_core_diff_name_set",
        "diff_names": "_core_diff_names",
        "diff_snapshots": "_core_diff_snapshots",
    },
    "ghydra/core/fleet.py": {
        "KINDS": "_CORE_FLEET_KINDS",
        "IDENTITY_FIELDS": "_CORE_FLEET_IDENTITY_FIELDS",
        "program_identity_of": "_core_fleet_identity_of",
        "merge_answers": "_core_fleet_merge",
    },
    "ghydra/core/capabilities.py": {
        "CAPABILITY_RULES": "_CORE_CAPABILITY_RULES",
        "_IMPORT_KEYS": "_CORE_CAP_IMPORT_KEYS",
        "_STRING_KEYS": "_CORE_CAP_STRING_KEYS",
        "_ADDRESS_KEYS": "_CORE_CAP_ADDRESS_KEYS",
        "_items": "_core_cap_items",
        "_text": "_core_cap_text",
        "_address": "_core_cap_address",
        "_evidence": "_core_cap_evidence",
        "build_capability_report": "_core_build_capability_report",
    },
    "ghydra/core/contextpack.py": {
        "TEMPLATES": "_CORE_CONTEXT_TEMPLATES",
        "_CHAR_PER_TOKEN": "_CORE_CONTEXT_CHAR_PER_TOKEN",
        "classify_question": "_core_context_classify",
        "estimate_tokens": "_core_context_tokens",
        "build_context_pack": "_core_build_context_pack",
    },
    "ghydra/core/hints.py": {
        "HINT_PATTERNS": "_CORE_HINT_PATTERNS",
        "parse_goal": "_core_parse_goal",
    },
}


def _rename(node: ast.AST, renames: dict[str, str]) -> None:
    """Rename the module's public names in place, and drop the annotations.

    The annotations are dropped so the generated block needs no extra imports;
    they are documentation, and the core modules keep them.
    """
    for child in ast.walk(node):
        if isinstance(child, ast.ClassDef):
            child.name = renames.get(child.name, child.name)
            child.bases = [ast.Name(id=renames[base.id], ctx=ast.Load())
                           if isinstance(base, ast.Name) and base.id in renames
                           else base for base in child.bases]
        elif isinstance(child, ast.FunctionDef):
            child.name = renames.get(child.name, child.name)
            child.returns = None
            for argument in list(child.args.args) + list(child.args.kwonlyargs):
                argument.annotation = None
            if child.args.vararg is not None:
                child.args.vararg.annotation = None
            if child.args.kwarg is not None:
                child.args.kwarg.annotation = None
        elif isinstance(child, ast.Assign):
            for target in child.targets:
                if isinstance(target, ast.Name) and target.id in renames:
                    target.id = renames[target.id]
        elif isinstance(child, ast.Name) and child.id in renames:
            child.id = renames[child.id]


def _source_of(module_path: str) -> str:
    """The body of a core module, renamed and unparsed.

    ``module_path`` is the workspace-relative path, which is also the key of
    ``CORE_RENAMES``; the join happens here so the two can never disagree.
    """
    with open(os.path.join(ROOT, module_path), encoding="utf-8") as handle:
        text = handle.read()
    tree = ast.parse(text)
    renames = CORE_RENAMES.get(module_path, {})
    body = []
    for node in tree.body:
        # Imports and the module docstring stay in the core module: the bridge
        # already imports json and hashlib, and its docstring is its own.
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Expr)):
            continue
        _rename(node, renames)
        body.append(node)
    return "\n\n".join(ast.unparse(node) for node in body)


def _imported_names(module_path: str) -> set[str]:
    """The names a module imports (stripped from the generated block)."""
    with open(os.path.join(ROOT, module_path), encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name)
    return names


def _bridge_imports() -> set[str]:
    """The names the bridge itself imports at module level.

    A generated body may use those: the region is spliced into the bridge, which
    already has `json`, `hashlib`, `re` and friends. Only an import the bridge
    lacks is a real error.
    """
    cached = getattr(_bridge_imports, "_cached", None)
    if cached is not None:
        return cached
    with open(BRIDGE, encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name)
    _bridge_imports._cached = names
    return names


def _unresolved_imports(module_path: str, source: str) -> set[str]:
    """Imported names the generated body still uses, and the bridge lacks."""
    renames = CORE_RENAMES.get(module_path, {})
    available = _bridge_imports()
    imported = _imported_names(module_path)
    used = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id in imported and node.id not in renames and node.id not in available:
                used.add(node.id)
    return used


def _region(module_path: str) -> str:
    relative = module_path
    function_source = _source_of(module_path)
    unresolved = _unresolved_imports(module_path, function_source)
    if unresolved:
        names = ", ".join(sorted(unresolved))
        raise SystemExit(
            f"{module_path}: the generated body uses imported name(s) {names}, "
            f"which are stripped from the region. Add them to CORE_RENAMES "
            f"[{module_path!r}] mapping each to the bridge's generated copy.")
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
        # First generation: the block goes right after the imports, so every
        # helper that uses a generated name is defined later. (Inserting it near
        # the tool groups put the names after their users, which is a
        # NameError at import time.)
        anchor = "def safe_get("
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