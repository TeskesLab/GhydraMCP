"""The hints a mission goal carries, read from the words.

A mission takes a goal in prose and has nobody to ask, so the goal itself has to
carry what the plan needs. This module is the one place that decides how:

* ``source`` — where data enters (``from recv``, ``de entrada ReadFile``);
* ``sink`` — where it would be dangerous (``to system``, ``reaches WinExec``);
* ``address`` — an explicit ``0x…`` the goal is about;
* ``function`` — a named function (``a função main``).

Nothing is inferred beyond the words: a goal that names no source and no sink
simply gets no taint step, and the dossier records that as an unknown. Both
surfaces read the goal with this same function, so the CLI and the bridge can
never form different hypotheses from the same sentence.
"""

from __future__ import annotations

import re
from typing import Any, Dict

#: The hint each key is read with. Order is the order they appear in the dict.
HINT_PATTERNS = {
    "source": r"\b(?:de|from|entrada|enters?|input)\s+[`\"']?([A-Za-z_][\w.]*)",
    "sink": (r"\b(?:para|to|ate|até|into|sink|reach(?:es)?|alcanc[ae]|alcança|"
             r"chega(?:r)?)\s+[`\"']?([A-Za-z_][\w.]*)"),
    "address": r"\b(0x[0-9A-Fa-f]+)\b",
    "function": r"\b(?:funcao|função|function)\s+[`\"']?([A-Za-z_]\w*)",
}


def parse_goal(goal: Any) -> Dict[str, str]:
    """The hints a goal carries, keyed by kind.

    Args:
        goal: The objective, as the user wrote it (any language in the patterns).

    Returns:
        dict: The hints that matched; empty when the goal names none of them.
    """
    text = str(goal or "")
    hints: Dict[str, str] = {}
    for key, pattern in HINT_PATTERNS.items():
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            hints[key] = match.group(1)
    return hints