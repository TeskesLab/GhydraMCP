"""The shape of a runbook step, and the validation of a steps document.

The CLI read a file and the bridge read text, but the *rules* were the same
code written twice — down to the message — and the only difference was which
exception type carried the failure. This module is the one place those rules
live:

* a steps document is a list, or ``{"steps": [...]}``, and it cannot be empty;
* a step is an object with a non-empty ``endpoint`` and a known method (GET by
  default), and ``params``/``payload`` are optional;
* the failure says which step and what is wrong with it, because "invalid steps"
  alone does not tell a caller which line to fix.

The two exception types are what let each surface keep its own error codes: the
CLI maps :class:`BadSteps` to ``RUNBOOK_BAD_STEPS`` and :class:`BadEntry` to
``RUNBOOK_BAD_ENTRY``, and the bridge answers ``RUNBOOK_BAD_STEPS`` for both.
"""

from __future__ import annotations

from typing import Any, Dict, List

#: The methods a step may use.
RUNBOOK_METHODS = ("GET", "POST", "PATCH", "PUT", "DELETE")


class BadSteps(ValueError):
    """The document is not a usable list of steps."""


class BadEntry(ValueError):
    """One step is not something the runbook could call."""


def validate_steps(data: Any) -> List[Dict[str, Any]]:
    """The steps of a parsed document, validated and normalised.

    Args:
        data: The parsed JSON — a list of steps or ``{"steps": [...]}``.

    Returns:
        list[dict]: One dict per step, with endpoint, method, params, payload.

    Raises:
        BadSteps: when the document holds no usable list.
        BadEntry: when a step is not an object, has no endpoint or a bad method.
    """
    items = data.get("steps") if isinstance(data, dict) else data
    if not isinstance(items, list) or not items:
        raise BadSteps("expected a non-empty list of steps or {'steps': [...]}")
    steps: List[Dict[str, Any]] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise BadEntry(f"step #{index + 1} is not an object")
        endpoint = item.get("endpoint")
        if not isinstance(endpoint, str) or not endpoint.strip():
            raise BadEntry(f"step #{index + 1}: 'endpoint' is required")
        method = str(item.get("method") or "GET").upper()
        if method not in RUNBOOK_METHODS:
            raise BadEntry(f"step #{index + 1}: unknown method {method!r}")
        steps.append({
            "endpoint": endpoint.strip(),
            "method": method,
            "params": item.get("params") or None,
            "payload": item.get("payload") or None,
        })
    return steps