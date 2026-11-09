"""Fleet queries: one question, several instances (R7).

The instances were already addressable, but a question could only be asked of
one at a time. A fleet query takes **a list of ports**, asks the same question
of every one, and merges the answers **by file identity** — the program's
``programId`` (or its executable path when there is none) — so two ports serving
the same program are one row, not two.

Three rules make the answer usable:

* **A port that does not answer is reported, never dropped.** An unreachable
  instance is a fact about the fleet; silently skipping it would turn "not
  present" into "not asked".
* **The merge is by file, not by port.** Two CodeBrowsers with the same binary
  open agree; two binaries with the same name in different directories do not
  merge, because their ``programId`` (project + path) differs.
* **A listing is read to its end, or the answer says it was not.** The import
  and string lookups page to ``meta.total`` and report ``complete: false`` when
  the cap was hit, so an "absent" is never claimed from a truncated scan.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

PAGE_LIMIT = 1000
MAX_PAGES = 5

#: The questions a fleet can be asked.
KINDS = ("overview", "has_function", "has_import", "has_string", "xrefs_to")

IDENTITY_FIELDS = ("programId", "path", "executablePath", "imageBase")


def _get(client, endpoint: str, params: Dict[str, Any] | None = None) -> Any:
    try:
        return client.get(endpoint, params=params)
    except Exception as exc:
        return {"success": False,
                "error": {"code": getattr(exc, "code", "FLEET_CALL_FAILED"),
                          "message": str(exc)}}


def _result(envelope: Any) -> Any:
    if isinstance(envelope, dict) and envelope.get("success", False):
        return envelope.get("result")
    return None


def _quote(value: str) -> str:
    from urllib.parse import quote
    return quote(value, safe="")


def program_identity_of(program: Any) -> str:
    """The key two instances serving the same file share.

    ``programId`` is project + pathname, and is what the plugin already uses to
    name a program. The executable path is the fallback; a completely unknown
    program gets the empty string, which the caller reports as unknown rather
    than merging every stranger together.
    """
    if not isinstance(program, dict):
        return ""
    for key in IDENTITY_FIELDS:
        value = program.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def collect_member(client, port: int) -> Dict[str, Any]:
    """What one fleet member is: its identity, or why it is not there."""
    response = _get(client, "program")
    program = _result(response)
    identity = program_identity_of(program)
    if not identity:
        error = (response.get("error") or {}) if isinstance(response, dict) else {}
        code = error.get("code") if isinstance(error, dict) else None
        return {"port": port, "reachable": False,
                "error": code or "FLEET_NO_PROGRAM"}
    return {"port": port, "reachable": True, "identity": identity,
            "program": program,
            "name": program.get("name") if isinstance(program, dict) else None}


def _paged_names(client, endpoint: str, keys) -> Dict[str, Any]:
    """A listing read to its end, saying whether it was read completely."""
    names: List[str] = []
    offset = 0
    complete = True
    for _page in range(MAX_PAGES):
        response = _get(client, endpoint, {"offset": offset, "limit": PAGE_LIMIT})
        if not isinstance(response, dict) or not response.get("success", False):
            return {"names": names, "complete": False, "error": True}
        payload = response.get("result")
        page = payload if isinstance(payload, list) else []
        for item in page:
            if not isinstance(item, dict):
                continue
            for key in keys:
                value = item.get(key)
                if isinstance(value, str) and value:
                    names.append(value)
                    break
        meta = response.get("meta") or {}
        total = meta.get("total") if isinstance(meta, dict) else None
        if not page or len(page) < PAGE_LIMIT:
            break
        if isinstance(total, int) and len(names) >= total:
            break
        offset += len(page)
    else:
        complete = False
    return {"names": names, "complete": complete, "error": False}


def ask(client, kind: str, target: Optional[str] = None) -> Dict[str, Any]:
    """Ask one instance one question, and say what its answer means."""
    if kind == "overview":
        response = _get(client, "program")
        program = _result(response)
        if not isinstance(program, dict):
            return {"ok": False, "error": "FLEET_NO_PROGRAM"}
        return {"ok": True, "present": True,
                "detail": {"name": program.get("name"),
                           "path": program.get("executablePath") or program.get("path"),
                           "language": program.get("language"),
                           "statistics": program.get("statistics")}}
    if kind == "has_function":
        response = _get(client, f"functions/by-name/{_quote(str(target))}")
        payload = _result(response)
        if isinstance(payload, dict) and payload.get("address"):
            return {"ok": True, "present": True,
                    "detail": {"address": str(payload["address"])}}
        error = (response.get("error") or {}) if isinstance(response, dict) else {}
        code = error.get("code") if isinstance(error, dict) else None
        if code in ("FUNCTION_NOT_FOUND", "SYMBOL_NOT_FOUND", "NOT_FOUND"):
            return {"ok": True, "present": False, "detail": {}}
        return {"ok": False, "error": code or "FLEET_QUERY_FAILED"}
    if kind == "has_import":
        listing = _paged_names(client, "symbols/imports",
                              ("name", "label", "symbol"))
        wanted = str(target or "").lower()
        matched = [name for name in listing["names"] if wanted and wanted in name.lower()]
        result = {"ok": not listing["error"], "present": bool(matched),
                  "detail": {"matched": matched[:5]},
                  "complete": listing["complete"]}
        if listing["error"]:
            result["error"] = "FLEET_QUERY_FAILED"
        return result
    if kind == "has_string":
        listing = _paged_names(client, "strings", ("value", "name", "string"))
        wanted = str(target or "")
        matched = [value for value in listing["names"] if wanted and wanted in value]
        result = {"ok": not listing["error"], "present": bool(matched),
                  "detail": {"matched": matched[:5]},
                  "complete": listing["complete"]}
        if listing["error"]:
            result["error"] = "FLEET_QUERY_FAILED"
        return result
    if kind == "xrefs_to":
        response = _get(client, f"xrefs/to-name/{_quote(str(target))}")
        payload = _result(response)
        items = payload if isinstance(payload, list) else []
        meta = response.get("meta") or {} if isinstance(response, dict) else {}
        total = meta.get("total") if isinstance(meta, dict) else None
        count = total if isinstance(total, int) else len(items)
        return {"ok": True, "present": bool(count), "detail": {"count": count}}
    return {"ok": False, "error": f"FLEET_UNKNOWN_KIND: {kind}"}


def query(clients: Dict[int, Any], kind: str,
          target: Optional[str] = None) -> Dict[str, Any]:
    """Ask every member, merge by file identity, and report what could not be asked."""
    if kind not in KINDS:
        return {"success": False,
                "error": {"code": "FLEET_UNKNOWN_KIND",
                          "message": f"the kinds are: {', '.join(KINDS)}"}}

    members: Dict[str, Dict[str, Any]] = {}
    unreachable: List[Dict[str, Any]] = []
    order: List[str] = []
    for port in sorted(clients):
        member = collect_member(clients[port], port)
        if not member["reachable"]:
            unreachable.append({"port": port, "reason": member.get("error")})
            continue
        identity = member["identity"]
        answer = ask(clients[port], kind, target)
        existing = members.get(identity)
        if existing is None:
            members[identity] = {"identity": identity, "name": member.get("name"),
                                 "ports": [port], "program": member.get("program"),
                                 "answer": answer}
            order.append(identity)
        else:
            # Two ports, one program: the answers must agree, and the row keeps
            # both ports so a disagreement can be seen.
            existing["ports"].append(port)
            if existing["answer"].get("present") != answer.get("present"):
                existing.setdefault("disagreements", []).append(
                    {"port": port, "answer": answer})

    rows = []
    for identity in order:
        member = members[identity]
        answer = member["answer"]
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
    return {"success": True, "result": {
        "kind": kind, "target": target,
        "binaries": rows,
        "count": len(rows),
        "with_it": sum(1 for row in rows if row["present"]),
        "without_it": sum(1 for row in rows if row["ok"] and not row["present"]),
        "unreachable": unreachable,
        "partial": partial,
        "truncated": truncated,
        "ok": not partial and not unreachable,
    }}


def to_text(report: Dict[str, Any]) -> str:
    """A text rendering shared by the CLI and the bridge."""
    if not isinstance(report, dict):
        return str(report)
    result = report.get("result", report)
    if not isinstance(result, dict):
        return str(result)
    kind = result.get("kind")
    target = result.get("target")
    heading = f"Fleet: {kind}" + (f" {target}" if target else "")
    lines = [heading,
             f"  binaries: {result.get('count', 0)}  "
             f"with it: {result.get('with_it', 0)}  "
             f"without it: {result.get('without_it', 0)}"]
    for row in result.get("binaries") or []:
        marker = "YES" if row.get("present") else ("no " if row.get("ok") else "???")
        line = (f"  [{marker}] {row.get('name') or row.get('identity')}"
                f"  ports {','.join(str(port) for port in row.get('ports') or [])}")
        detail = row.get("detail") or {}
        if detail.get("address"):
            line += f"  at {detail['address']}"
        if detail.get("count") is not None:
            line += f"  refs {detail['count']}"
        if detail.get("matched"):
            line += f"  matched {', '.join(str(m) for m in detail['matched'][:2])}"
        if row.get("complete") is False:
            line += "  (listing truncated)"
        lines.append(line)
        if row.get("disagreements"):
            lines.append(f"       the ports disagree: {row['disagreements']}")
    for item in result.get("unreachable") or []:
        lines.append(f"  [---] port {item.get('port')} did not answer "
                     f"({item.get('reason')})")
    if result.get("partial"):
        lines.append(f"  note: the question could not be answered for "
                     f"{len(result['partial'])} member(s)")
    return "\n".join(lines)