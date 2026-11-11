"""Merging the answers of several instances into one picture.

A fleet query asks the same question of several Ghidra instances. Two things
make the answer usable, and both were written twice (once for the CLI, once for
the bridge):

* **the merge is by file, not by port** — the program's identity decides; two
  ports serving the same binary are one row, and their answers must agree, so a
  disagreement is reported rather than silently overwritten;
* **a port that did not answer is a fact** — it is carried into the answer as
  ``unreachable`` instead of being dropped, because "not present" and "not
  asked" are different answers.

What stays in the callers is the I/O: reading each instance's program and
asking it the question. This module only merges what came back, which is what
makes it pure and safe to generate into the bridge.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

#: The questions a fleet can be asked.
KINDS = ("overview", "has_function", "has_import", "has_string", "xrefs_to")

#: The fields that identify the program, most specific first.
IDENTITY_FIELDS = ("programId", "path", "executablePath", "imageBase")


def program_identity_of(program: Any) -> str:
    """The key two instances serving the same file share.

    ``programId`` is project + pathname, and is what the plugin already uses to
    name a program. The path is the fallback. A program with none of them has no
    identity (``""``), which the caller reports rather than merging every
    stranger together.

    Args:
        program: The ``result`` of ``/program`` (any shape).

    Returns:
        str: The identity, or the empty string when the program has none.
    """
    if not isinstance(program, dict):
        return ""
    for key in IDENTITY_FIELDS:
        value = program.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def merge_answers(seen: List[Dict[str, Any]], kind: str,
                  target: Optional[str],
                  unreachable: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Merge what every reachable instance answered into one report.

    Args:
        seen: One entry per instance that answered: ``port``, ``identity``,
              ``name``, ``program`` and ``answer`` (itself a dict with
              ``ok``/``present``/``detail``/``complete``).
        kind: The question, echoed in the report.
        target: What the question was about (``None`` for an overview).
        unreachable: The ports that did not answer, with their reason.

    Returns:
        dict: The envelope — one row per *binary*, the counts, the members that
              could not answer, the rows that were partial or truncated.
    """
    members: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for entry in seen:
        identity = entry.get("identity")
        if not identity:
            continue
        answer = entry.get("answer") or {}
        existing = members.get(identity)
        if existing is None:
            members[identity] = {"identity": identity, "name": entry.get("name"),
                                 "ports": [entry.get("port")],
                                 "program": entry.get("program"),
                                 "answer": answer}
            order.append(identity)
        else:
            existing["ports"].append(entry.get("port"))
            if existing["answer"].get("present") != answer.get("present"):
                existing.setdefault("disagreements", []).append(
                    {"port": entry.get("port"), "answer": answer})

    rows = []
    for identity in order:
        member = members[identity]
        answer = member.get("answer") or {}
        row = {"identity": identity, "name": member.get("name"),
               "ports": member["ports"],
               "present": bool(answer.get("present")),
               "ok": bool(answer.get("ok")),
               "detail": answer.get("detail") or {}}
        if answer.get("complete") is False:
            row["complete"] = False
        if member.get("disagreements"):
            row["disagreements"] = member["disagreements"]
        rows.append(row)

    partial = [row["identity"] for row in rows if not row["ok"]]
    truncated = [row["identity"] for row in rows if row.get("complete") is False]
    missing = list(unreachable or [])
    return {"success": True, "result": {
        "kind": kind, "target": target, "binaries": rows, "count": len(rows),
        "with_it": sum(1 for row in rows if row["present"]),
        "without_it": sum(1 for row in rows if row["ok"] and not row["present"]),
        "unreachable": missing, "partial": partial, "truncated": truncated,
        "ok": not partial and not missing}}