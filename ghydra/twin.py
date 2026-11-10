"""The digital twin (R2): a snapshot of a binary that answers without Ghidra.

The bet, and the reason this exists: most questions asked of an analysis are
*about facts already fetched* — which functions exist, which import is there,
what the strings say, what changed between two builds. Those do not need a
decompiler; they need the facts, kept.

So a twin is a **snapshot**: one JSON document holding what the API said about a
binary, cheap to read, diffable in git, and answerable with no Ghidra running.
The rules it keeps:

* **the snapshot records provenance** — the source instance, the program's md5
  and the time — so a snapshot whose binary changed can be recognised as stale
  instead of trusted;
* **it is a floor, not the whole binary**: strings and functions are capped, and
  the document says how many were kept of how many existed;
* **a diff of two twins reuses the pure comparison** (`ghydra/core/diff.py`), so
  "what changed between these builds" has one definition, on line and offline;
* **it is not a cache with a nicer name**: this module measures itself against
  the live API (`scripts/bench_twin.py`). If it is not faster, R2 dies — that is
  the criterion that was written down before the code.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional

from .core.diff import diff_snapshots

#: Bumping this invalidates every snapshot on disk.
TWIN_VERSION = 1

#: How many strings and functions a snapshot keeps by default.
DEFAULT_MAX_STRINGS = 5000
DEFAULT_MAX_FUNCTIONS = 20000

#: The page the server clamps every listing to.
PAGE = 1000


def twin_dir() -> str:
    """Where the snapshots live ($GHYDRA_STATE_DIR wins, then ~/.ghydra)."""
    base = os.environ.get("GHYDRA_STATE_DIR")
    root = base if base else os.path.join(os.path.expanduser("~"), ".ghydra")
    return os.path.join(root, "twins")


#: Names Windows refuses as a file name, whatever the extension.
_RESERVED_NAMES = {"con", "prn", "aux", "nul", "conin$", "conout$"} | {
    f"{prefix}{number}" for prefix in ("com", "lpt") for number in range(1, 10)}


def _safe_name(name: str) -> str:
    """A readable file stem for a name: no separators, no device names."""
    safe = "".join(character if character.isalnum() or character in "._-"
                   else "_" for character in str(name))
    safe = safe.strip("._- ") or "twin"
    # A device name is refused with or without an extension, and in any case.
    if safe.split(".")[0].lower() in _RESERVED_NAMES:
        safe = "_" + safe
    return safe


def _legacy_twin_path(name: str) -> str:
    """Where a snapshot made before the digest suffix lives."""
    safe = "".join(character if character.isalnum() or character in "._-"
                   else "_" for character in str(name))
    return os.path.join(twin_dir(), f"{safe}.json")


def twin_path(name: str) -> str:
    """The file a twin is saved to, from its name.

    The digest is of the **original** name, so two names that sanitize to the same
    stem are two files: `a/b` and `a_b` used to share one, and the second snapshot
    overwrote the first.
    """
    digest = hashlib.sha256(str(name).encode("utf-8")).hexdigest()[:8]
    return os.path.join(twin_dir(), f"{_safe_name(name)}-{digest}.json")


def _bare_address(value: Any) -> str:
    """An address in a form two spellings of the same address agree on.

    ``str.lstrip("0x")`` is not this: it removes the *characters* 0 and x from
    the left, so it mangles an address that starts with a zero in another way.

    Ghidra writes an address as unprefixed, zero-padded hexadecimal
    (``00401000``) and a caller writes ``0x401000``; comparing the text leaves
    ``00401000 != 401000`` for the same address. So the value is compared as the
    number it is, and the address space is kept apart: ``ram:401000`` and
    ``00401000`` are different places.
    """
    text = str(value or "").strip().lower()
    space = ""
    if ":" in text:
        space, _, text = text.rpartition(":")
        text = text.strip()
    if text.startswith("0x"):
        text = text[2:]
    if not text:
        return space
    try:
        return space + format(int(text, 16), "x")
    except ValueError:
        # Not an address: compare it as the text it is.
        return space + text


def _result(envelope: Any) -> Any:
    if isinstance(envelope, dict) and envelope.get("success", False):
        return envelope.get("result")
    return None


def _page(client, endpoint: str, limit: int,
          params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Every item of a listing, paged through what the server advertises.

    The server clamps a page to 1000 items, so a single request would silently
    truncate a larger listing. The walk follows ``meta.total`` and stops at
    ``limit`` — and the caller records that it stopped.
    """
    items: List[Dict[str, Any]] = []
    offset = 0
    while len(items) < limit:
        wanted = min(PAGE, limit - len(items))
        query = dict(params or {})
        query.update({"limit": wanted, "offset": offset})
        payload = _result(client.get(endpoint, params=query))
        if not isinstance(payload, list) or not payload:
            break
        items.extend(item for item in payload if isinstance(item, dict))
        if len(payload) < wanted:
            break
        offset += wanted
    return items


def build(client, name: Optional[str] = None,
          max_strings: int = DEFAULT_MAX_STRINGS,
          max_functions: int = DEFAULT_MAX_FUNCTIONS) -> Dict[str, Any]:
    """Take a snapshot of the program the instance is serving.

    Args:
        client: A configured API client.
        name: The name to save it under (default: the program's name).
        max_strings: How many strings to keep at most.
        max_functions: How many functions to keep at most.

    Returns:
        dict: The snapshot document (also what :func:`save` writes).
    """
    program = _result(client.get("program")) or {}
    exports = _page(client, "symbols/exports", max_functions)
    imports = _page(client, "symbols/imports", max_functions)
    functions = _page(client, "functions", max_functions)
    strings = _page(client, "strings", max_strings)

    recorded = {
        "name": program.get("name"),
        "path": program.get("executablePath") or program.get("path"),
        "md5": (program.get("executableMd5") or program.get("executableMD5")
                or program.get("md5")),
        "language": program.get("language"),
        "image_base": program.get("imageBase"),
        "compiler": program.get("compiler"),
    }
    document = {
        "twin_version": TWIN_VERSION,
        "built_at": round(time.time(), 3),
        "source": getattr(client, "base_url", None) or getattr(client, "host", None),
        "name": name or str(recorded.get("name") or "binary"),
        "program": recorded,
        "statistics": program.get("statistics") or {},
        "functions": [
            {"name": item.get("name"), "address": item.get("address"),
             "return_type": item.get("returnType") or item.get("return_type"),
             "is_thunk": item.get("isThunk") or item.get("is_thunk"),
             # The function *listing* carries a count, not the parameters
             # themselves. Recording `parameters: []` made every snapshot claim
             # zero parameters for every function.
             "parameter_count": (item.get("parameterCount")
                                 if item.get("parameterCount") is not None
                                 else item.get("parameter_count"))}
            for item in functions
        ],
        "imports": [str(item.get("name")) for item in imports if item.get("name")],
        "exports": [str(item.get("name")) for item in exports if item.get("name")],
        "strings": [str(item.get("value") or item.get("string") or "")
                    for item in strings if (item.get("value") or item.get("string"))],
        "counts": {
            "functions": len(functions),
            "imports": len(imports),
            "exports": len(exports),
            "strings": len(strings),
            "functions_total": (program.get("statistics") or {}).get("functionCount"),
            "strings_total": (program.get("statistics") or {}).get("stringCount"),
        },
        "truncated": {
            "functions": len(functions) >= max_functions,
            "strings": len(strings) >= max_strings,
        },
    }
    return document


def save(document: Dict[str, Any], path: Optional[str] = None) -> str:
    """Write a snapshot, atomically enough that a half file is never read."""
    target = path or twin_path(str(document.get("name") or "binary"))
    directory = os.path.dirname(target)
    if directory:
        # `os.path.dirname("twin.json")` is "" and makedirs("") raises: a caller
        # writing the twin next to itself is normal and must work.
        os.makedirs(directory, exist_ok=True)
    temporary = target + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(document, handle, ensure_ascii=False, indent=1)
        handle.write("\n")
    os.replace(temporary, target)
    return target


def resolve_path(path_or_name: str) -> str:
    """The file to read: the path given, or the snapshot of that name.

    `twin build --name app-1.2` writes to the state directory, so a command that
    only accepted a path made the documented example fail.
    """
    if os.path.exists(path_or_name):
        return path_or_name
    for candidate in (twin_path(str(path_or_name)),
                      _legacy_twin_path(str(path_or_name))):
        if os.path.exists(candidate):
            return candidate
    return path_or_name


def load(path: str) -> Dict[str, Any]:
    """Read a snapshot, refusing a document from another version."""
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict):
        raise ValueError(f"{path} is not a twin snapshot")
    version = document.get("twin_version")
    if version != TWIN_VERSION:
        raise ValueError(f"{path} was written by twin version {version}, "
                         f"this build reads version {TWIN_VERSION}")
    return document


def fingerprint(document: Dict[str, Any]) -> str:
    """A digest of what the snapshot says the binary *is*.

    Used to recognise a snapshot of another binary (or of the same path rebuilt)
    without comparing every field by hand.
    """
    recorded = document.get("program") or {}
    material = json.dumps({
        "name": recorded.get("name"),
        "md5": recorded.get("md5"),
        "language": recorded.get("language"),
        "image_base": recorded.get("image_base"),
    }, sort_keys=True, default=str)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def query(document: Dict[str, Any], kind: str, needle: str = "",
          limit: int = 50) -> Dict[str, Any]:
    """Answer a question from the snapshot alone.

    Args:
        document: A loaded snapshot.
        kind: ``functions``, ``function``, ``imports``, ``exports``,
              ``strings`` or ``overview``.
        needle: The address or the text to look for (case-insensitive for text).
        limit: How many items to return at most.

    Returns:
        dict: the answer, with the counts that say whether the snapshot could
              answer it at all
    """
    limit = max(1, int(limit))
    lowered = (needle or "").lower()
    truncated = document.get("truncated") or {}

    if kind == "overview":
        return {"kind": kind, "program": document.get("program"),
                "counts": document.get("counts"), "built_at": document.get("built_at"),
                "source": document.get("source"),
                "truncated": truncated, "matched": 1, "returned": 1}

    if kind == "function":
        wanted = (needle or "").strip().lower()
        wanted_bare = _bare_address(wanted)
        for function in document.get("functions") or []:
            if _bare_address(function.get("address")) == wanted_bare:
                return {"kind": kind, "function": function, "matched": 1,
                        "returned": 1, "truncated": truncated}
            if str(function.get("name") or "").lower() == wanted:
                return {"kind": kind, "function": function, "matched": 1,
                        "returned": 1, "truncated": truncated}
        answer = {"kind": kind, "function": None, "matched": 0, "returned": 0,
                  "truncated": truncated}
        if (truncated or {}).get("functions"):
            # "Not found" in a snapshot that was capped means "not in the part I
            # kept", which is a weaker claim and has to be worded as one.
            answer["reason"] = ("this snapshot keeps only the first functions it "
                                "saw; the function may exist in the program")
        return answer

    if kind == "functions":
        matches = [function for function in document.get("functions") or []
                   if lowered in str(function.get("name") or "").lower()]
        return {"kind": kind, "items": matches[:limit], "matched": len(matches),
                "returned": min(len(matches), limit), "truncated": truncated}

    if kind in ("imports", "exports", "strings"):
        matches = [value for value in document.get(kind) or []
                   if lowered in value.lower()]
        return {"kind": kind, "items": matches[:limit], "matched": len(matches),
                "returned": min(len(matches), limit), "truncated": truncated}

    raise ValueError(f"unknown query kind: {kind}")


def as_diff_snapshot(document: Dict[str, Any]) -> Dict[str, Any]:
    """The snapshot in the shape the shared comparison understands.

    One definition of "what changed" serves both the live `analysis_diff` and
    two twins on disk, which is the point of putting the comparison in the core.
    """
    counts = document.get("counts") or {}
    truncated = document.get("truncated") or {}
    capped = bool(truncated.get("functions"))
    total = counts.get("functions_total")
    # A snapshot can be short for two reasons: the cap was hit, or the listing
    # returned fewer functions than the program's own statistics claim (measured
    # on where.exe: 104 listed against 198 counted). Either way the comparison
    # must know, or a diff would report phantom removals.
    # Complete needs a known total: with no total, a snapshot that lists
    # nothing is indistinguishable from a snapshot of an empty program, and a
    # diff over it would report every function of the other side as removed.
    if not isinstance(total, int):
        complete = False
    else:
        complete = not capped and total <= (counts.get("functions") or 0)
    # The strings and the imports of a snapshot can be capped too, and the
    # comparison needs to know: without this a capped string listing produced
    # false differences against a whole one.
    strings_total = counts.get("strings_total")
    if isinstance(strings_total, int):
        strings_complete = (not truncated.get("strings")
                            and strings_total <= (counts.get("strings") or 0))
    else:
        strings_complete = not truncated.get("strings")
    # The imports have no total of their own, so the cap flag is all there is.
    imports_complete = not truncated.get("imports")
    return {
        "program": document.get("program") or {},
        "functions": document.get("functions") or [],
        "imports": document.get("imports") or [],
        "strings": document.get("strings") or [],
        "functions_complete": complete,
        "imports_complete": imports_complete,
        "strings_complete": strings_complete,
    }


def diff(left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
    """What changed between two twins, using the shared comparison."""
    report = diff_snapshots(as_diff_snapshot(left), as_diff_snapshot(right))
    report["provenance"] = {
        "a": {"name": left.get("name"), "md5": (left.get("program") or {}).get("md5"),
              "fingerprint": fingerprint(left), "built_at": left.get("built_at")},
        "b": {"name": right.get("name"), "md5": (right.get("program") or {}).get("md5"),
              "fingerprint": fingerprint(right), "built_at": right.get("built_at")},
    }
    report["same_binary"] = fingerprint(left) == fingerprint(right)
    # A comparison over a snapshot that is not complete is not a complete
    # comparison: say it once, in the report, so a reader cannot miss it. The
    # verdict covers every section — the functions alone used to decide it.
    report["complete"] = bool(report.get("complete", True))
    return report