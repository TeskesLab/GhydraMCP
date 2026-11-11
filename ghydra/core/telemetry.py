"""Reading the local tool log back: the window, the aggregate, the advice.

The bridge writes one JSON object per tool call to a local file; this module
turns those rows into the report a human reads. Everything here is pure — the
caller hands over the rows and the current time — so the CLI and the bridge
cannot summarize the same log differently.

Three rules decide the report:

* **the window is the caller's**, not the clock's: `filter_recent` takes `now`
  so "the last 7 days" means the same thing on both surfaces, and a test can
  pin it;
* **a tool with no calls is not in the table** — the report lists what was used,
  not the whole catalogue;
* **the advice is about patterns, not one call**: a suggestion appears only when
  the log shows the pattern the composed tool replaces, and it names the tool
  that replaces it.

What stays in the callers is reading the file and finding its path: that is I/O.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

#: The log is capped at this size, trimmed oldest first.
MAX_BYTES = 1_000_000

#: How many lines survive a trim.
KEEP_LINES = 2000

#: The list of inspection calls the context pack answers in one request.
INSPECTION_TOOLS = ("functions_get", "functions_decompile", "analysis_callers",
                    "analysis_callees", "xrefs_list", "inspect_address")

#: The listings that a composed overview replaces.
LISTING_TOOLS = ("functions_list", "data_list", "symbols_list", "variables_list")


def filter_recent(entries: List[Dict[str, Any]], days: int,
                  now: Optional[float] = None) -> List[Dict[str, Any]]:
    """The entries inside the last ``days`` days.

    Args:
        entries: The rows of the log (as :func:`read_entries` returns them).
        days: The size of the window, at least one day.
        now: The current epoch time; passed in so the answer is reproducible.

    Returns:
        list: The entries whose timestamp is inside the window.
    """
    import time as _time
    moment = _time.time() if now is None else now
    cutoff = moment - max(1, int(days)) * 86400
    return [entry for entry in entries
            if float(entry.get("ts") or 0) >= cutoff]


def recommendations(entries: List[Dict[str, Any]]) -> List[str]:
    """Name the composed tool when the log shows the pattern it replaces."""
    found: List[str] = []
    counts: Dict[str, int] = {}
    slow: Dict[str, float] = {}
    for entry in entries:
        tool = str(entry.get("tool"))
        counts[tool] = counts.get(tool, 0) + 1
        if entry.get("ok"):
            slow[tool] = max(slow.get(tool, 0.0), float(entry.get("ms") or 0))

    inspection = sum(counts.get(name, 0) for name in INSPECTION_TOOLS)
    if inspection >= 4:
        found.append(
            f"{inspection} inspection calls in the window: "
            f"analysis_context_pack(question, address) answers that pattern "
            f"in one call, with a token budget and citable addresses.")
    listing = sum(counts.get(name, 0) for name in LISTING_TOOLS)
    if listing >= 4:
        found.append(
            f"{listing} listing calls: programs_overview composes the counts "
            f"and imports in one call, and a page takes limit/offset.")
    batch = counts.get("functions_decompile", 0)
    if batch >= 4:
        found.append(
            f"{batch} single decompiles: functions_batch_decompile takes a "
            f"list (async_mode=True for a long batch).")
    for tool, worst in sorted(slow.items(), key=lambda item: -item[1])[:3]:
        if worst >= 500:
            found.append(
                f"{tool} took up to {worst:.0f} ms: consider async_mode=True "
                f"or a narrower request.")
    return found[:5]


def summarize(entries: List[Dict[str, Any]], days: int = 7,
              path: str = "") -> Dict[str, Any]:
    """Aggregate the log rows into the report the CLI and the tool share.

    Args:
        entries: The rows inside the window (see :func:`filter_recent`).
        days: The window, echoed in the report.
        path: Where the log lives, echoed so the reader can open it.

    Returns:
        dict: call and failure totals per tool (the 25 busiest), the error codes
              seen, the advice, and the path of the log. An empty window says so
              instead of answering with an empty table.
    """
    totals: Dict[str, Dict[str, Any]] = {}
    codes: Dict[str, int] = {}
    for entry in entries:
        tool = str(entry.get("tool"))
        row = totals.setdefault(tool, {"tool": tool, "calls": 0, "failed": 0,
                                       "ms_total": 0.0, "ms_max": 0.0,
                                       "tokens": 0})
        row["calls"] += 1
        if not entry.get("ok"):
            row["failed"] += 1
        row["ms_total"] += float(entry.get("ms") or 0)
        row["ms_max"] = max(row["ms_max"], float(entry.get("ms") or 0))
        row["tokens"] += int(entry.get("tokens") or 0)
        code = entry.get("code")
        if code:
            codes[str(code)] = codes.get(str(code), 0) + 1

    rows = []
    for row in sorted(totals.values(), key=lambda item: -item["calls"]):
        rows.append({**row,
                     "ms_avg": round(row["ms_total"] / row["calls"], 1),
                     "ms_max": round(row["ms_max"], 1)})
    report: Dict[str, Any] = {
        "days": days,
        "calls": len(entries),
        "tools": rows[:25],
        "error_codes": codes,
        "recommendations": recommendations(entries),
        "path": path,
    }
    if not entries:
        report["message"] = "no telemetry recorded in this window"
    return report