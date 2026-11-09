"""The parts of source-to-sink reasoning that are pure.

The taint pass talks to the API for the facts — the source, the sink, the calls
of a function, the call graph — but three decisions on top of those facts are
pure, and both surfaces needed them:

* **a call site** is the call whose target is the wanted address *or* whose
  target name contains the wanted function's name;
* **an address key** sorts addresses numerically and keeps unparseable ones last
  instead of letting them abort the sort;
* **a summary** counts the hypotheses by confidence and says whether anything at
  ``direct``/``reachable`` was found — ``weak`` alone does not count as found.

The disclaimer is here too: it is the sentence that tells the reader these are
hypotheses and not proof, and it has to be the same sentence on both surfaces.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

#: The fields of /program a taint report echoes.
PROGRAM_FIELDS = ("name", "executable_path", "image_base")

#: The server clamps every page to this many items.
PAGE_LIMIT = 1000

#: A listing that never ends must stop somewhere.
MAX_PAGES = 5

#: Ghidra's CALL-family pcode opcodes (CALL=57, CALLIND=58 in PcodeOp).
CALL_OPCODES = {57, 58}

CONFIDENCE_DIRECT = "direct"
CONFIDENCE_REACHABLE = "reachable"

#: Said next to every finding, because a heuristic is not a verdict.
DISCLAIMER = (
    "These are hypotheses from pcode and the call graph, not proof of "
    "exploitability. Branches are not modelled; a 'direct' finding means the "
    "sink call appears after the source call in the same function."
)


def result_of(envelope: Any) -> Any:
    """The payload of a successful envelope, or ``None``.

    A failed answer is not an empty result: it is no result, which the callers
    report as a gap rather than as an absence of evidence.
    """
    if isinstance(envelope, dict) and envelope.get("success", False):
        return envelope.get("result")
    return None


def site_for(calls: List[Dict[str, Any]], wanted: str,
             wanted_name: str) -> Optional[str]:
    """The call site whose target is the wanted address or name.

    Args:
        calls: The calls of a function, each with ``target`` and ``at``.
        wanted: The address (or symbol) the sink resolved to.
        wanted_name: The name of the function the sink resolved to.

    Returns:
        str | None: The address of the first matching call, or ``None``.
    """
    wanted_lower = (wanted or "").lower()
    for call in calls:
        target = (call.get("target") or "").lower()
        if not target:
            continue
        if target == wanted_lower or (wanted_name or "").lower() in target:
            return call["at"]
    return None


def address_key(address: str) -> tuple:
    """Sort key for an address: numeric order, unparseable values last.

    Returned as a tuple so ``sorted`` never compares an int with a string — a
    single odd address would otherwise raise and lose the whole report.
    """
    try:
        return (0, int(str(address), 16))
    except (TypeError, ValueError):
        return (1, 0)


def summarize(report: Dict[str, Any]) -> Dict[str, Any]:
    """The counts a report carries, shared by both surfaces.

    ``found`` is true only for a ``direct`` or ``reachable`` hypothesis: a pile
    of ``weak`` ones is not a finding.
    """
    hypotheses = report.get("hypotheses") or []
    by_confidence: Dict[str, int] = {}
    for item in hypotheses:
        key = item.get("confidence") or "unknown"
        by_confidence[key] = by_confidence.get(key, 0) + 1
    return {
        "total": len(hypotheses),
        "direct": by_confidence.get(CONFIDENCE_DIRECT, 0),
        "reachable": by_confidence.get(CONFIDENCE_REACHABLE, 0),
        "weak": by_confidence.get("weak", 0),
        "found": bool(by_confidence.get(CONFIDENCE_DIRECT)
                      or by_confidence.get(CONFIDENCE_REACHABLE)),
    }