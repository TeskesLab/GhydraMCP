"""Reproducible runbooks (R6).

A runbook is a sequence of API calls with the digest of each answer, written as
JSONL next to the analysis. Replaying it against another binary, or another
version of the same one, says *what changed*: identical answers, answers that
moved, and calls that failed. That turns reverse engineering from a one-off
session into an artifact that can be versioned and re-run in CI.

The format is deliberately plain text so it diffs well in git:

    {"runbook": 1, "created": ..., "program": {...}, "steps": 2}
    {"step": 1, "request": {"method": "GET", "endpoint": "functions/..."}, "ok": true, "digest": "..."}
    {"step": 2, ...}

The digest covers the normalized answer (`result` only), so metadata that
legitimately changes per call - request id, timestamp, port - does not make
every replay look different.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional

from .core.runbook import BadEntry, BadSteps, validate_steps

RUNBOOK_VERSION = 1

ERROR_BAD_FILE = "RUNBOOK_BAD_FILE"
ERROR_BAD_STEPS = "RUNBOOK_BAD_STEPS"
ERROR_BAD_ENTRY = "RUNBOOK_BAD_ENTRY"

#: The methods a step may use (defined once, in the core).
RUNBOOK_METHODS = ("GET", "POST", "PATCH", "PUT", "DELETE")

#: The fields of an answer that are allowed to change between two runs.
VOLATILE_KEYS = ("id", "timestamp", "instance", "_links", "api_links")


class RunbookError(Exception):
    """A runbook that cannot be read, written or replayed."""

    def __init__(self, message: str, code: str = ERROR_BAD_FILE):
        super().__init__(message)
        self.code = code


def canonical(value: Any) -> str:
    """The text a digest is taken over: sorted keys, no separators noise."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def stable_result(envelope: Any) -> Any:
    """The part of an answer that a replay is compared on."""
    if isinstance(envelope, dict):
        payload = envelope.get("result", envelope)
        if isinstance(payload, dict):
            return {key: value for key, value in payload.items()
                    if key not in VOLATILE_KEYS}
        return payload
    return envelope


def load_steps(path: str) -> List[Dict[str, Any]]:
    """Read the steps to record, as a list or ``{"steps": [...]}``."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as exc:
        raise RunbookError(f"cannot read {path}: {exc}", ERROR_BAD_FILE) from exc
    except ValueError as exc:
        raise RunbookError(f"{path} is not valid JSON: {exc}", ERROR_BAD_FILE) from exc

    # The rules live in the core (I1); this only maps their failure to the
    # error codes this surface answers with.
    return checked_steps(data)


def checked_steps(data: Any) -> List[Dict[str, Any]]:
    """The validated steps, with the exceptions this module raises.

    Validation is generated from ``ghydra/core/runbook.py``; a document that is
    not a list raises ``RUNBOOK_BAD_STEPS`` and a bad entry raises
    ``RUNBOOK_BAD_ENTRY``, so the caller can tell "the file is wrong" from
    "step 3 is wrong".
    """
    try:
        return validate_steps(data)
    except BadSteps as exc:
        raise RunbookError(str(exc), ERROR_BAD_STEPS) from exc
    except BadEntry as exc:
        raise RunbookError(str(exc), ERROR_BAD_ENTRY) from exc


def program_fingerprint(client) -> Dict[str, Any]:
    """What the runbook was recorded against.

    The name, the executable path and the image base are the facts a replay
    needs to tell "the same program" from "another one with the same name".
    """
    try:
        response = client.get("program")
    except Exception:
        return {}
    payload = response.get("result") if isinstance(response, dict) else None
    if not isinstance(payload, dict):
        return {}
    return {key: payload.get(key) for key in
            ("name", "executable_path", "image_base", "language", "compiler")
            if payload.get(key) is not None}


def _call(client, step: Dict[str, Any]) -> Any:
    method = step["method"]
    endpoint = step["endpoint"]
    params = step.get("params")
    payload = step.get("payload")
    if method == "GET":
        return client.get(endpoint, params=params)
    if method == "POST":
        return client.post(endpoint, data=payload)
    if method == "PATCH":
        return client.patch(endpoint, data=payload)
    if method == "PUT":
        return client.put(endpoint, data=payload)
    return client.delete(endpoint)


def record(client, steps: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Run the steps once and build the runbook document."""
    header = {
        "runbook": RUNBOOK_VERSION,
        "created": int(time.time()),
        "program": program_fingerprint(client),
        "steps": len(steps),
    }
    entries = []
    for index, step in enumerate(steps, start=1):
        response = _call(client, step)
        ok = bool(isinstance(response, dict) and response.get("success", False))
        code = None
        if not ok and isinstance(response, dict):
            error = response.get("error")
            if isinstance(error, dict):
                code = error.get("code")
        entries.append({
            "step": index,
            "request": {key: step[key] for key in
                        ("method", "endpoint", "params", "payload")
                        if step.get(key) is not None},
            "ok": ok,
            "code": code,
            "digest": digest(stable_result(response)),
        })
    return {"header": header, "entries": entries}


def save(runbook: Dict[str, Any], path: str) -> None:
    """Write the runbook as JSONL: one header line, then one line per step."""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(canonical(runbook["header"]) + "\n")
        for entry in runbook["entries"]:
            handle.write(canonical(entry) + "\n")


def load(path: str) -> Dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as handle:
            lines = [line for line in handle.read().splitlines() if line.strip()]
    except OSError as exc:
        raise RunbookError(f"cannot read {path}: {exc}", ERROR_BAD_FILE) from exc
    if not lines:
        raise RunbookError(f"{path} is empty", ERROR_BAD_FILE)
    try:
        header = json.loads(lines[0])
    except ValueError as exc:
        raise RunbookError(f"{path}: the first line is not JSON: {exc}",
                           ERROR_BAD_FILE) from exc
    if not isinstance(header, dict) or "runbook" not in header:
        raise RunbookError(f"{path}: the first line is not a runbook header",
                           ERROR_BAD_FILE)
    entries = []
    for number, line in enumerate(lines[1:], start=2):
        try:
            entry = json.loads(line)
        except ValueError as exc:
            raise RunbookError(f"{path}:{number} is not JSON: {exc}",
                               ERROR_BAD_FILE) from exc
        if isinstance(entry, dict):
            entries.append(entry)
    version = header.get("runbook")
    if version != RUNBOOK_VERSION:
        raise RunbookError(
            f"runbook version {version!r} is not supported (this build reads "
            f"version {RUNBOOK_VERSION})", ERROR_BAD_FILE)
    return {"header": header, "entries": entries}


def replay(runbook: Dict[str, Any], client) -> Dict[str, Any]:
    """Re-run every step and say what moved."""
    recorded = runbook.get("entries") or []
    now = program_fingerprint(client)
    recorded_program = (runbook.get("header") or {}).get("program") or {}
    program_changed = bool(recorded_program and now
                           and canonical(recorded_program) != canonical(now))

    results = []
    for entry in recorded:
        request = entry.get("request") or {}
        step = {"method": request.get("method") or "GET",
                "endpoint": request.get("endpoint") or "",
                "params": request.get("params"),
                "payload": request.get("payload")}
        try:
            response = _call(client, step)
        except Exception as exc:  # a call that cannot run is a failed replay
            results.append({"step": entry.get("step"), "endpoint": step["endpoint"],
                            "status": "failed", "code": getattr(exc, "code", None),
                            "reason": str(exc)})
            continue
        ok = bool(isinstance(response, dict) and response.get("success", False))
        if not ok:
            error = response.get("error") if isinstance(response, dict) else None
            results.append({"step": entry.get("step"), "endpoint": step["endpoint"],
                            "status": "failed",
                            "code": (error or {}).get("code") if isinstance(error, dict) else None,
                            "reason": (error or {}).get("message") if isinstance(error, dict) else None})
            continue
        current = digest(stable_result(response))
        same = current == entry.get("digest")
        results.append({
            "step": entry.get("step"),
            "endpoint": step["endpoint"],
            "status": "identical" if same else "changed",
            "digest_recorded": entry.get("digest"),
            "digest_current": current,
        })

    changed = [item for item in results if item["status"] == "changed"]
    failed = [item for item in results if item["status"] == "failed"]
    return {
        "success": True,
        "result": {
            "steps": results,
            "total": len(results),
            "identical": len(results) - len(changed) - len(failed),
            "changed": len(changed),
            "failed": len(failed),
            "program_changed": program_changed,
            "recorded_program": recorded_program,
            "current_program": now,
            "ok": not changed and not failed,
        },
    }


def to_text(report: Dict[str, Any]) -> str:
    result = report.get("result", report)
    lines = [f"Replay: {result.get('total', 0)} step(s) — "
             f"{result.get('identical', 0)} identical, "
             f"{result.get('changed', 0)} changed, {result.get('failed', 0)} failed"]
    if result.get("program_changed"):
        lines.append("  note: the program fingerprint changed since the recording")
    for item in result.get("steps") or []:
        marker = {"identical": "SAME", "changed": "DEFT", "failed": "FAIL"}.get(
            item["status"], "????")
        line = f"  [{marker}] step {item.get('step')} {item.get('endpoint')}"
        if item.get("code"):
            line += f" ({item['code']})"
        if item.get("reason"):
            line += f" — {item['reason']}"
        lines.append(line)
    return "\n".join(lines)
