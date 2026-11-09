"""Compare two binaries, or two versions of one (R6).

`analysis_diff` answers the question a patch-diff or a regression gate asks:
*what changed between these two analyses?* It composes facts the API already
returns — the program fingerprint, the function list, the imports, the defined
strings and the segments — into one report of what was added, removed or moved.

Two rules make the answer usable:

* **A function is identified by its address, and its name is a fact about it.**
  A function at the same address with a different name is *renamed*, not one
  removal plus one addition; a function that moved keeps its name identity only
  when the name is unique in both snapshots. Anything ambiguous is reported as
  an address change rather than guessed.
* **A truncated listing is not a diff.** If a collection could not be read to
  its end, the section says `complete: false` and the counts it reports are a
  floor; nothing is claimed to be "removed" from a list that was not read.
"""

from __future__ import annotations

from typing import Any, Dict, List

PAGE_LIMIT = 1000
MAX_PAGES = 20

PROGRAM_FIELDS = ("name", "executable_path", "image_base", "language", "compiler")


def _get(client, endpoint: str, params: Dict[str, Any] | None = None) -> Any:
    try:
        return client.get(endpoint, params=params)
    except Exception:
        return {"success": False, "error": {"code": "DIFF_READ_FAILED"}}


def _page(client, endpoint: str, keys=("name", "value")) -> Dict[str, Any]:
    """Read a listing to its end, saying whether it was read completely."""
    items: List[Any] = []
    offset = 0
    complete = True
    for _page_number in range(MAX_PAGES):
        response = _get(client, endpoint, {"offset": offset, "limit": PAGE_LIMIT})
        if not isinstance(response, dict) or not response.get("success", False):
            return {"items": items, "complete": False, "error": True}
        payload = response.get("result")
        page = payload if isinstance(payload, list) else []
        items.extend(page)
        meta = response.get("meta") or {}
        total = meta.get("total") if isinstance(meta, dict) else None
        if not page or len(page) < PAGE_LIMIT:
            break
        if isinstance(total, int) and len(items) >= total:
            break
        offset += len(page)
    else:
        complete = False  # the page cap was hit before the listing ended

    names = []
    for item in items:
        if not isinstance(item, dict):
            continue
        for key in keys:
            value = item.get(key)
            if isinstance(value, str) and value:
                names.append(value)
                break
    return {"items": items, "complete": complete, "error": False}


def collect_snapshot(client, include_strings: bool = True) -> Dict[str, Any]:
    """Everything a diff compares, read once from one instance."""
    program: Dict[str, Any] = {}
    response = _get(client, "program")
    payload = response.get("result") if isinstance(response, dict) else None
    if isinstance(payload, dict):
        program = {key: payload.get(key) for key in PROGRAM_FIELDS
                   if payload.get(key) is not None}

    functions_page = _page(client, "functions")
    functions = []
    for item in functions_page["items"]:
        if not isinstance(item, dict):
            continue
        functions.append({
            "address": str(item.get("address") or ""),
            "name": item.get("name"),
            "size": item.get("size"),
        })

    imports_page = _page(client, "symbols/imports", ("name", "label", "symbol"))
    strings_page = (_page(client, "strings", ("value", "name", "string"))
                    if include_strings else {"items": [], "complete": True, "error": False})

    return {
        "program": program,
        "functions": functions,
        "functions_complete": functions_page["complete"],
        "imports": sorted({name for name in imports_page_names(imports_page)}),
        "imports_complete": imports_page["complete"],
        "strings": sorted(set(imports_page_names(strings_page))),
        "strings_complete": strings_page["complete"],
    }


def imports_page_names(page: Dict[str, Any]) -> List[str]:
    names: List[str] = []
    for item in page.get("items") or []:
        if isinstance(item, dict):
            for key in ("name", "label", "symbol", "value", "string"):
                value = item.get(key)
                if isinstance(value, str) and value:
                    names.append(value)
                    break
    return names


def _sets(values: List[str]) -> set:
    return {value for value in values if value}


def diff_snapshots(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """What changed between two snapshots, section by section."""
    # ---- functions, by address -------------------------------------------
    by_addr_a = {fn["address"]: fn for fn in a.get("functions") or [] if fn.get("address")}
    by_addr_b = {fn["address"]: fn for fn in b.get("functions") or [] if fn.get("address")}
    added, removed, renamed = [], [], []
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

    # ---- imports and strings, by name ------------------------------------
    imports = _diff_names(_sets(a.get("imports") or []), _sets(b.get("imports") or []))
    strings = _diff_names(_sets(a.get("strings") or []), _sets(b.get("strings") or []))

    result = {
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
        "imports_added": len(imports["added"]), "imports_removed": len(imports["removed"]),
        "strings_added": len(strings["added"]), "strings_removed": len(strings["removed"]),
        "program_changed": result["program_changed"],
    }
    return result


def _diff_names(before: set, after: set) -> Dict[str, Any]:
    return {"added": sorted(after - before), "removed": sorted(before - after),
            "count_a": len(before), "count_b": len(after)}


def to_text(report: Dict[str, Any]) -> str:
    """A text rendering shared by the CLI and the bridge."""
    if not isinstance(report, dict):
        return str(report)
    summary = report.get("summary") or {}
    functions = report.get("functions") or {}
    lines = ["Diff" + (" — the program fingerprint changed"
                       if report.get("program_changed") else " — same program fingerprint")]
    if not functions.get("complete", True):
        lines.append("  note: a function listing was truncated; the counts are a floor")
    lines.append(f"  functions: +{summary.get('functions_added', 0)} "
                 f"-{summary.get('functions_removed', 0)} "
                 f"~{summary.get('functions_renamed', 0)} renamed "
                 f"({functions.get('count_a', 0)} -> {functions.get('count_b', 0)})")
    lines.append(f"  imports:   +{summary.get('imports_added', 0)} "
                 f"-{summary.get('imports_removed', 0)}")
    lines.append(f"  strings:   +{summary.get('strings_added', 0)} "
                 f"-{summary.get('strings_removed', 0)}")

    def section(title, rows, fmt):
        if not rows:
            return
        lines.append(f"\n{title}:")
        for row in rows[:40]:
            lines.append("  " + fmt(row))
        if len(rows) > 40:
            lines.append(f"  ... {len(rows) - 40} more")

    section("functions added", functions.get("added") or [],
            lambda row: f"+ {row.get('address')} {row.get('name') or '?'}")
    section("functions removed", functions.get("removed") or [],
            lambda row: f"- {row.get('address')} {row.get('name') or '?'}")
    section("functions renamed", functions.get("renamed") or [],
            lambda row: f"~ {row.get('address')} {row.get('from')} -> {row.get('to')}")
    section("imports added", (report.get("imports") or {}).get("added") or [],
            lambda row: f"+ {row}")
    section("imports removed", (report.get("imports") or {}).get("removed") or [],
            lambda row: f"- {row}")
    section("strings added", (report.get("strings") or {}).get("added") or [],
            lambda row: f"+ {row[:100]}")
    section("strings removed", (report.get("strings") or {}).get("removed") or [],
            lambda row: f"- {row[:100]}")
    return "\n".join(lines)