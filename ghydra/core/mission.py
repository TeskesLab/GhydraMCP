"""The mission's rules that hold without a Ghidra: the budget and the dossier.

A mission spends three budgets and then writes a document. Both were duplicated
between the CLI and the bridge, and both are pure once the numbers are passed in:

* **the budget** — which limit trips first (calls, then tokens, then wall clock),
  how a spent call is counted (a token is about four characters, never zero),
  and the row the report shows. Time is a *parameter*, not a clock read, so the
  arithmetic is testable without sleeping.
* **the dossier** — the Markdown a human reads and a CI job keeps. One renderer
  means the CLI and the bridge cannot produce different artifacts for the same
  mission, which matters because the artifact is the evidence.

What stays in the callers is every call to the API, the clock, and the file.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

MISSION_VERSION = 1

DEFAULT_CALLS = 60
DEFAULT_TOKENS = 200_000
DEFAULT_SECONDS = 900

ERROR_NO_PROGRAM = "MISSION_NO_PROGRAM"
ERROR_BUDGET = "MISSION_BUDGET"
ERROR_BAD_FILE = "MISSION_BAD_FILE"

STATUS_OPEN = "open"
STATUS_VERIFIED = "verified"
STATUS_UNVERIFIED = "unverified"
STATUS_UNKNOWN = "unknown"


def tokens_of(payload: Any) -> int:
    """The token estimate of one answer: about four characters per token.

    Never zero: a call that answered nothing still cost a call, and a budget
    that counts it as free would let an empty loop run forever.
    """
    text = json.dumps(payload, default=str) if payload is not None else ""
    return max(1, len(text) // 4)


def budget_exhausted(calls: int, max_calls: int, tokens: int, max_tokens: int,
                     elapsed: float,
                     max_seconds: Optional[int] = None) -> Optional[str]:
    """Which budget is spent, in the order that matters, or ``None``.

    Args:
        calls: Calls already spent.
        max_calls: The call limit.
        tokens: Tokens already spent.
        max_tokens: The token limit.
        elapsed: Seconds since the mission started.
        max_seconds: The wall-clock limit, when the surface enforces one.

    Returns:
        str | None: The reason the mission must stop, in the words the report
                    uses, or ``None`` when there is room left.
    """
    if calls >= max_calls:
        return f"the call budget ({max_calls}) is spent"
    if tokens >= max_tokens:
        return f"the token budget ({max_tokens}) is spent"
    if max_seconds is not None and elapsed >= max_seconds:
        return f"the time budget ({max_seconds}s) is spent"
    return None


def budget_row(calls: int, max_calls: int, tokens: int, max_tokens: int,
               seconds: float,
               max_seconds: Optional[int] = None) -> Dict[str, Any]:
    """The budget as the report shows it.

    ``max_seconds`` is included only when the caller enforces one, so a surface
    that has no wall clock does not advertise a limit it never checks.
    """
    row: Dict[str, Any] = {"calls": calls, "max_calls": max_calls,
                           "tokens": tokens, "max_tokens": max_tokens,
                           "seconds": round(float(seconds), 1)}
    if max_seconds is not None:
        row["max_seconds"] = max_seconds
    return row


def dossier(goal: str, mission_id: str, program: Dict[str, Any],
            hints: Dict[str, Any], budget: Dict[str, Any],
            failed: Optional[str], skipped: List[str],
            findings: List[Dict[str, Any]],
            verification: Optional[Dict[str, Any]] = None) -> str:
    """The dossier a human reads, and the artifact a CI job keeps.

    Args:
        goal: The objective, in the words the user gave.
        mission_id: The id the mission is stored under.
        program: The program fingerprint (``name``, ``executable_path``).
        hints: The hints read from the goal.
        budget: The row from :func:`budget_row`.
        failed: Why the mission stopped early, when it did.
        skipped: The steps that were not run, with the reason in their name.
        findings: The findings, each with id/title/kind/confidence/status and
                  the evidence digests behind it.
        verification: The re-read result, when the mission verified itself.

    Returns:
        str: The Markdown document.
    """
    lines = [f"# Mission: {goal}", "",
             f"- id: `{mission_id}`",
             f"- program: `{program.get('name') or '?'}` "
             f"({program.get('executable_path') or 'no path'})",
             f"- hints: {json.dumps(hints, ensure_ascii=False)}",
             f"- budget: {budget['calls']}/{budget['max_calls']} calls, "
             f"~{budget['tokens']} tokens, {budget['seconds']}s", ""]
    if failed:
        lines.extend([f"**The mission stopped: {failed}**", ""])
    if skipped:
        lines.extend([f"Skipped steps: {', '.join(skipped)}", ""])

    lines.extend(["## Findings", ""])
    if not findings:
        lines.append("_No finding was recorded._")
    for finding in findings:
        lines.append(f"### {finding['id']} — {finding['title']}")
        lines.append("")
        lines.append(f"- kind: `{finding.get('kind')}`  "
                     f"confidence: `{finding.get('confidence')}`  "
                     f"status: `{finding.get('status')}`")
        if finding.get("detail"):
            lines.extend(["", "```", str(finding["detail"])[:2000], "```"])
        for item in finding.get("evidence") or []:
            lines.append(f"- evidence: `{item.get('endpoint')}` "
                         f"(digest `{(item.get('digest') or '')[:16]}`)")
        lines.append("")

    if verification is not None:
        lines.extend(["## Verification", "",
                      f"- evidence items re-read: {verification['checked']}",
                      f"- findings verified: {verification['verified']}"])
        if verification.get("unverified"):
            lines.append(f"- **unverified: {', '.join(verification['unverified'])}** "
                         f"(their evidence moved or could not be re-read)")
        else:
            lines.append("- every conclusion still holds against its evidence")
        lines.append("")

    unknowns = [item for item in findings
                if item.get("status") == STATUS_UNKNOWN]
    lines.extend(["## Not determined", ""])
    if not unknowns:
        lines.append("_Nothing was left undetermined._")
    for item in unknowns:
        lines.append(f"- {item['id']}: {item['title']} — "
                     f"{item.get('detail') or ''}".rstrip())
    lines.append("")
    return "\n".join(lines)