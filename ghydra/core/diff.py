"""What changed between two snapshots, told by address and by name.

`analysis_diff` compares two analyses; a mission compares a program against the
one it recorded. Both need the same answer to "what moved?", and both carried
their own copy of it.

Two decisions define the comparison:

* **A function is identified by its address, and its name is a fact about it.** A
  function at the same address with a different name is *renamed* — not one
  removal plus one addition — because that is what a reviewer needs to see.
* **Imports and strings are compared as sets of names.** Order and duplication
  are not a change; presence is. An empty name is not a value and is dropped.

The rest of what a diff needs — reading the two snapshots — is I/O and stays in
the callers. This module is pure, which is what lets it be generated into the
bridge.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Set

#: The fields of /program a diff reports on.
PROGRAM_FIELDS = ("name", "executable_path", "image_base", "language", "compiler")


def name_set(values: Iterable[str]) -> Set[str]:
    """The non-empty names of a listing, as a set (order and repeats are noise)."""
    return {value for value in values if value}


def diff_names(before: Set[str], after: Set[str]) -> Dict[str, Any]:
    """The names added and removed between two sets.

    Args:
        before: The names of the first snapshot.
        after: The names of the second one.

    Returns:
        dict: ``added`` and ``removed`` (sorted, so the answer is stable) plus
              both counts.
    """
    return {"added": sorted(after - before), "removed": sorted(before - after),
            "count_a": len(before), "count_b": len(after)}


def diff_snapshots(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """What changed between two snapshots, section by section.

    Args:
        a: The first snapshot: ``program``, ``functions``, ``imports``,
           ``strings`` and the ``*_complete`` flags.
        b: The second one, in the same shape.

    Returns:
        dict: ``functions`` (added/removed/renamed, with counts and whether both
              listings were complete), ``imports``, ``strings``,
              ``program_changed``, ``changed`` and a ``summary`` of counts.
    """
    by_addr_a = {fn["address"]: fn for fn in a.get("functions") or []
                 if fn.get("address")}
    by_addr_b = {fn["address"]: fn for fn in b.get("functions") or []
                 if fn.get("address")}
    added: List[Dict[str, Any]] = []
    removed: List[Dict[str, Any]] = []
    renamed: List[Dict[str, Any]] = []
    for address, fn in sorted(by_addr_b.items()):
        if address not in by_addr_a:
            added.append({"address": address, "name": fn.get("name")})
        elif fn.get("name") != by_addr_a[address].get("name"):
            renamed.append({"address": address,
                            "from": by_addr_a[address].get("name"),
                            "to": fn.get("name")})
    for address, fn in sorted(by_addr_a.items()):
        if address not in by_addr_b:
            removed.append({"address": address, "name": fn.get("name")})

    imports = diff_names(name_set(a.get("imports") or []),
                         name_set(b.get("imports") or []))
    strings = diff_names(name_set(a.get("strings") or []),
                         name_set(b.get("strings") or []))

    result: Dict[str, Any] = {
        "program": {"a": a.get("program") or {}, "b": b.get("program") or {}},
        "program_changed": (a.get("program") or {}) != (b.get("program") or {}),
        "functions": {
            "added": added, "removed": removed, "renamed": renamed,
            "count_a": len(by_addr_a), "count_b": len(by_addr_b),
            "complete": bool(a.get("functions_complete", True))
                        and bool(b.get("functions_complete", True)),
        },
        "imports": imports,
        "strings": strings,
    }
    result["changed"] = bool(
        added or removed or renamed or imports["added"] or imports["removed"]
        or strings["added"] or strings["removed"] or result["program_changed"])
    result["summary"] = {
        "functions_added": len(added), "functions_removed": len(removed),
        "functions_renamed": len(renamed),
        "imports_added": len(imports["added"]),
        "imports_removed": len(imports["removed"]),
        "strings_added": len(strings["added"]),
        "strings_removed": len(strings["removed"]),
        "program_changed": result["program_changed"],
    }
    return result