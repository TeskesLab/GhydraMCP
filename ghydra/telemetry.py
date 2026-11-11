"""Local telemetry reader and summarizer (I14).

The bridge records one JSON object per tool call under
``~/.ghydra/telemetry.jsonl`` (or under ``GHYDRA_STATE_DIR``): the tool name, a
timestamp, whether the call failed, its error code, the duration and an estimate
of the answer's size. Never the arguments, the results, a path, a symbol, an
address or any binary content, and no identifier of any kind. Nothing is ever
sent anywhere; this module only reads that file back. ``GHYDRA_TELEMETRY=0``
stops the recording and deleting the file erases what was recorded. The bridge carries its
own copy (it ships as one file and must not import the ghydra package);
``test_telemetry.py`` asserts the two summarizers agree.
"""

from __future__ import annotations

import json
import os

from .core import telemetry as core_telemetry

#: Both defined once, in the core (I1).
MAX_BYTES = core_telemetry.MAX_BYTES
KEEP_LINES = core_telemetry.KEEP_LINES


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
    """Delegates to the core (I1)."""
    return core_telemetry.recommendations(entries)


def summarize(entries: list, days: int = 7) -> dict:
    """Delegates to the core (I1), which also decides what an empty window says."""
    return core_telemetry.summarize(entries, days, telemetry_path())
