"""The canonical form of an answer, and its digest.

Three features need to answer "is this the same answer as before?": the runbook
(does the replay match?), the cache (is this the entry I stored?) and the mission
(is the evidence unchanged?). They agreed on the *idea* and each carried its own
copy of the code — exactly the duplication I1 exists to remove.

What "the same" means is defined here, once:

* keys are sorted, separators are tight and non-ASCII text is kept verbatim, so
  two equal values always produce equal text (``canonical``);
* the text is hashed with SHA-256 (``digest``);
* the fields that legitimately change between two calls — the request id, the
  timestamp, the instance and the links — are dropped before hashing
  (``stable_result``).

Everything here is pure: the same value gives the same digest on both surfaces,
which is what lets ``scripts/gen_core.py`` copy the code into the bridge.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

#: The parts of an envelope that change between two identical calls.
VOLATILE_KEYS = ("id", "timestamp", "instance", "_links", "api_links")


def canonical(value: Any) -> str:
    """The text a digest is taken over: sorted keys, no separator noise."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def digest(value: Any) -> str:
    """The SHA-256 of the canonical form of a value."""
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def stable_result(value: Any, volatile: Iterable[str] = VOLATILE_KEYS) -> Any:
    """The part of an answer that two identical calls share.

    A dict loses the volatile keys; anything else is returned as it is. The
    list of volatile keys is a parameter so a caller can widen it, never so it
    can silently narrow it in one place and not the other.
    """
    if isinstance(value, dict):
        payload = value.get("result", value)
        if isinstance(payload, dict):
            dropped = set(volatile)
            return {key: item for key, item in payload.items()
                    if key not in dropped}
        return payload
    return value