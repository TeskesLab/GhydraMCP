"""Declarative assertions about a binary, for CI (I16).

``ghydra assert`` answers a yes/no question about a binary in a way a CI job
can gate on: "this build has no import of CreateRemoteThread", "the string
/api/telemetry exists", "main reaches strcmp". Each assertion is evaluated
against the REST API (or a headless run in CI), and the report is emitted as
text, JUnit XML or SARIF 2.1.0.

Two rules make the answer trustworthy:

* **A truncated listing is not proof.** A ``no_import``/``no_string`` that
  never saw the whole list is reported as ``inconclusive``, never as a pass.
  The check is only a pass when the listing was read to its end.
* **Evidence is carried.** Every verdict names what was looked at (the count
  of imports scanned, the address of the matching function), so a failure can
  be read without re-running anything.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

PAGE_LIMIT = 1000
MAX_PAGES = 20

ASSERTION_KINDS = (
    "has_import", "no_import",
    "has_string", "no_string",
    "has_function", "no_function",
    "has_xref_to", "reaches",
)

ERROR_BAD_FILE = "ASSERTION_BAD_FILE"
ERROR_BAD_SPEC = "ASSERTION_BAD_SPEC"
ERROR_UNKNOWN_KIND = "ASSERTION_UNKNOWN_KIND"


class AssertionError_(Exception):
    """An assertion file that cannot be used (bad JSON, unknown kind)."""

    def __init__(self, message: str, code: str = ERROR_BAD_SPEC):
        super().__init__(message)
        self.code = code


def load_assertions(path: str) -> List[Dict[str, Any]]:
    """Read and validate an assertion file.

    Accepts a bare list or ``{"assertions": [...]}``; every entry needs
    ``kind`` and, depending on the kind, ``name``/``from``/``to``.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as exc:
        raise AssertionError_(f"cannot read {path}: {exc}", ERROR_BAD_FILE) from exc
    except ValueError as exc:
        raise AssertionError_(f"{path} is not valid JSON: {exc}", ERROR_BAD_FILE) from exc

    items = data.get("assertions") if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise AssertionError_("expected a list of assertions or {'assertions': [...]}")
    validated = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise AssertionError_(f"assertion #{index + 1} is not an object")
        kind = item.get("kind")
        if kind not in ASSERTION_KINDS:
            raise AssertionError_(
                f"assertion #{index + 1}: unknown kind {kind!r} "
                f"(known: {', '.join(ASSERTION_KINDS)})", ERROR_UNKNOWN_KIND)
        target = item.get("name") or item.get("target")
        if kind == "reaches":
            if not item.get("from") or not item.get("to"):
                raise AssertionError_(f"assertion #{index + 1}: reaches needs from and to")
        elif not target:
            raise AssertionError_(f"assertion #{index + 1}: '{kind}' needs a name")
        label = target
        if kind == "reaches":
            label = f"{item.get('from')} -> {item.get('to')}"
        validated.append({
            "id": str(item.get("id") or f"A{index + 1}"),
            "kind": kind,
            "name": label,
            "from": item.get("from"),
            "to": item.get("to"),
            "message": item.get("message") or "",
        })
    return validated


def _page_items(client, endpoint: str) -> tuple:
    """Every item of a listing, paged; returns (items, complete)."""
    items: List[Any] = []
    offset = 0
    for _page in range(MAX_PAGES):
        response = client.get(endpoint, params={"offset": offset,
                                               "limit": PAGE_LIMIT})
        payload = response.get("result")
        page = payload if isinstance(payload, list) else []
        items.extend(page)
        meta = response.get("meta") or {}
        total = meta.get("total") if isinstance(meta, dict) else None
        if not page or len(page) < PAGE_LIMIT:
            return items, True
        if isinstance(total, int) and len(items) >= total:
            return items, True
        offset += len(page)
    return items, False


def _names(items: List[Any], keys=("name", "value", "label")) -> List[str]:
    found = []
    for item in items:
        if not isinstance(item, dict):
            continue
        for key in keys:
            value = item.get(key)
            if isinstance(value, str) and value:
                found.append(value)
                break
    return found


def _result(assertion: Dict[str, Any], status: str, evidence: str) -> Dict[str, Any]:
    return {"id": assertion["id"], "kind": assertion["kind"],
            "target": assertion["name"], "status": status,
            "evidence": evidence,
            "message": assertion.get("message") or ""}


def _evaluate_listing(client, assertion, endpoint, keys) -> Dict[str, Any]:
    items, complete = _page_items(client, endpoint)
    names = _names(items, keys)
    wanted = str(assertion["name"]).lower()
    matched = [name for name in names if wanted in name.lower()]
    kind = assertion["kind"]
    scanned = f"scanned {len(items)} entries ({len(names)} distinct names)"
    if not complete:
        scanned += " (listing truncated: the answer is inconclusive)"
    if kind.startswith("has_"):
        if matched:
            return _result(assertion, "pass", f"{scanned}; matched {matched[0]!r}")
        if not complete:
            return _result(assertion, "inconclusive", scanned)
        return _result(assertion, "fail", f"{scanned}; no match")
    # no_*: a match fails; an incomplete scan cannot prove absence
    if matched:
        return _result(assertion, "fail", f"{scanned}; matched {matched[0]!r}")
    if not complete:
        return _result(assertion, "inconclusive", scanned)
    return _result(assertion, "pass", f"{scanned}; no match")


def _evaluate_function(client, assertion) -> Dict[str, Any]:
    name = str(assertion["name"])
    kind = assertion["kind"]
    try:
        response = client.get(f"functions/by-name/{_quote(name)}")
    except Exception as exc:  # a 404 is the answer, not a failure of the check
        if _is_missing(exc):
            if kind == "has_function":
                return _result(assertion, "fail", "the function does not exist")
            return _result(assertion, "pass", "the function does not exist")
        raise
    payload = response.get("result") or {}
    address = payload.get("address") or payload.get("entry") or "?"
    if kind == "has_function":
        return _result(assertion, "pass", f"found at {address}")
    return _result(assertion, "fail", f"found at {address}")


def _is_missing(exc: Exception) -> bool:
    """Is this exception "the thing is not there", rather than a failed check?"""
    code = str(getattr(exc, "code", "") or "")
    if code in ("FUNCTION_NOT_FOUND", "SYMBOL_NOT_FOUND", "NOT_FOUND",
                "NO_SYMBOL", "HTTP_404"):
        return True
    text = str(exc).lower()
    return "not found" in text or "no function" in text or "404" in text


def _evaluate_xrefs(client, assertion) -> Dict[str, Any]:
    name = str(assertion["name"])
    try:
        response = client.get(f"xrefs/to-name/{_quote(name)}")
    except Exception as exc:  # a 404 is the answer, not a failure of the check
        if _is_missing(exc):
            return _result(assertion, "fail",
                           f"{name} is not present in the binary")
        raise
    payload = response.get("result")
    items = payload if isinstance(payload, list) else []
    meta = response.get("meta") or {}
    total = meta.get("total") if isinstance(meta, dict) else None
    count = total if isinstance(total, int) else len(items)
    evidence = f"{count} reference(s) to {name}"
    return _result(assertion, "pass" if count else "fail", evidence)


def _evaluate_reaches(client, assertion) -> Dict[str, Any]:
    try:
        response = client.get("analysis/call-path", params={
            "from": assertion["from"], "to": assertion["to"]})
    except Exception as exc:  # a name that is not there cannot be reached
        if _is_missing(exc):
            return _result(assertion, "fail",
                           f"{assertion['from']} cannot reach "
                           f"{assertion['to']}: one of them is not in the binary")
        raise
    payload = response.get("result") or {}
    path = payload.get("path") if isinstance(payload, dict) else None
    if isinstance(path, list) and path:
        return _result(assertion, "pass", f"path with {len(path)} hop(s)")
    reason = payload.get("reason") if isinstance(payload, dict) else None
    return _result(assertion, "fail", reason or "no path found")


def _quote(value: str) -> str:
    from urllib.parse import quote
    return quote(value, safe="")


def evaluate(client, assertions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Evaluate every assertion and return the report."""
    results = []
    for assertion in assertions:
        kind = assertion["kind"]
        if kind in ("has_import", "no_import"):
            results.append(_evaluate_listing(
                client, assertion, "symbols/imports",
                ("name", "label", "symbol")))
        elif kind in ("has_string", "no_string"):
            results.append(_evaluate_listing(
                client, assertion, "strings", ("value", "name", "string")))
        elif kind in ("has_function", "no_function"):
            results.append(_evaluate_function(client, assertion))
        elif kind == "has_xref_to":
            results.append(_evaluate_xrefs(client, assertion))
        elif kind == "reaches":
            results.append(_evaluate_reaches(client, assertion))
        else:  # load_assertions rejects these; keep the report honest anyway
            results.append(_result(assertion, "inconclusive",
                                   f"unknown kind {kind!r}"))

    failed = [item for item in results if item["status"] == "fail"]
    inconclusive = [item for item in results if item["status"] == "inconclusive"]
    return {
        "success": True,
        "result": {
            "assertions": results,
            "total": len(results),
            "passed": len(results) - len(failed) - len(inconclusive),
            "failed": len(failed),
            "inconclusive": len(inconclusive),
            "ok": not failed,
        },
    }


def to_text(report: Dict[str, Any]) -> str:
    result = report.get("result", report)
    lines = [f"Assertions: {result.get('total', 0)} "
             f"({result.get('passed', 0)} passed, {result.get('failed', 0)} failed, "
             f"{result.get('inconclusive', 0)} inconclusive)"]
    for item in result.get("assertions") or []:
        marker = {"pass": "PASS", "fail": "FAIL"}.get(item["status"], "????")
        line = f"  [{marker}] {item['id']} {item['kind']} {item.get('target', '')}"
        if item.get("message"):
            line += f" — {item['message']}"
        lines.append(line)
        if item.get("evidence"):
            lines.append(f"         {item['evidence']}")
    return "\n".join(lines)


def _xml_escape(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def to_junit(report: Dict[str, Any], suite_name: str = "ghydra-assert") -> str:
    """JUnit XML, so a CI runner can read the verdict natively."""
    result = report.get("result", report)
    items = result.get("assertions") or []
    failures = [item for item in items if item["status"] == "fail"]
    skipped = [item for item in items if item["status"] == "inconclusive"]
    lines = [f'<?xml version="1.0" encoding="UTF-8"?>',
             f'<testsuite name="{_xml_escape(suite_name)}" tests="{len(items)}" '
             f'failures="{len(failures)}" errors="0" skipped="{len(skipped)}">']
    for item in items:
        name = _xml_escape(f"{item['id']} {item['kind']} {item.get('target', '')}")
        lines.append(f'  <testcase classname="{_xml_escape(suite_name)}" name="{name}">')
        if item["status"] == "fail":
            detail = _xml_escape(item.get("message") or item.get("evidence") or "failed")
            lines.append(f'    <failure message="{detail}">'
                         f'{_xml_escape(item.get("evidence", ""))}</failure>')
        elif item["status"] == "inconclusive":
            lines.append(f'    <skipped message="{_xml_escape(item.get("evidence", ""))}"/>')
        lines.append("  </testcase>")
    lines.append("</testsuite>")
    return "\n".join(lines)


def to_sarif(report: Dict[str, Any]) -> str:
    """SARIF 2.1.0, so the result lands in a code-scanning dashboard."""
    result = report.get("result", report)
    items = result.get("assertions") or []
    rules = []
    seen = set()
    for item in items:
        if item["kind"] in seen:
            continue
        seen.add(item["kind"])
        rules.append({
            "id": item["kind"],
            "name": item["kind"],
            "shortDescription": {"text": f"Binary assertion: {item['kind']}"},
        })
    results = []
    for item in items:
        if item["status"] != "fail":
            continue
        results.append({
            "ruleId": item["kind"],
            "level": "error",
            "message": {"text": f"{item['id']} {item['kind']} {item.get('target', '')}: "
                                f"{item.get('message') or 'assertion failed'}"},
            "locations": [],
            "properties": {"assertion": item["id"],
                           "target": item.get("target", ""),
                           "evidence": item.get("evidence", "")},
        })
    document = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "ghydra-assert", "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(document, ensure_ascii=False, indent=2)


def render(report: Dict[str, Any], fmt: str = "text") -> str:
    format_name = (fmt or "text").lower()
    if format_name == "junit":
        return to_junit(report)
    if format_name == "sarif":
        return to_sarif(report)
    return to_text(report)
