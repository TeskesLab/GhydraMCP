"""Local telemetry reader and summarizer (I14).

The bridge records one JSON object per tool call under
``~/.ghydra/telemetry.jsonl`` (or under ``GHYDRA_STATE_DIR``). Nothing is ever
sent anywhere; this module only reads that file back. The bridge carries its
own copy (it ships as one file and must not import the ghydra package);
``test_telemetry.py`` asserts the two summarizers agree.
"""

from __future__ import annotations

import json
import os

MAX_BYTES = 1_000_000
KEEP_LINES = 2000


def telemetry_path() -> str:
    base = os.environ.get("GHYDRA_STATE_DIR") or os.path.join(
        os.path.expanduser("~"), ".ghydra")
    return os.path.join(base, "telemetry.jsonl")


def read_entries(max_entries: int = 5000) -> list:
    try:
        with open(telemetry_path(), encoding="utf-8") as handle:
            lines = handle.read().splitlines()[-max_entries:]
    except OSError:
        return []
    entries = []
    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and entry.get("tool"):
            entries.append(entry)
    return entries


def recommendations(entries: list) -> list:
    """Name the composed tool when the log shows the pattern it replaces."""
    found = []
    counts: dict[str, int] = {}
    slow: dict[str, float] = {}
    for entry in entries:
        tool = str(entry.get("tool"))
        counts[tool] = counts.get(tool, 0) + 1
        if entry.get("ok"):
            slow[tool] = max(slow.get(tool, 0.0), float(entry.get("ms") or 0))

    inspection = sum(counts.get(name, 0) for name in (
        "functions_get", "functions_decompile", "analysis_callers",
        "analysis_callees", "xrefs_list", "inspect_address"))
    if inspection >= 4:
        found.append(
            f"{inspection} inspection calls in the window: "
            f"analysis_context_pack(question, address) answers that pattern "
            f"in one call, with a token budget and citable addresses.")
    listing = sum(counts.get(name, 0) for name in (
        "functions_list", "data_list", "symbols_list", "variables_list"))
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


def summarize(entries: list, days: int = 7) -> dict:
    """Aggregate the log rows into the report the CLI and the tool share."""
    totals: dict[str, dict] = {}
    codes: dict[str, int] = {}
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
    return {
        "days": days,
        "calls": len(entries),
        "tools": rows[:25],
        "error_codes": codes,
        "recommendations": recommendations(entries),
        "path": telemetry_path(),
    }
