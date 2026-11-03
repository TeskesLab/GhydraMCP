"""Helpers for the arguments that carry a list.

The batch decompilation takes a list of functions. A shell has no list, so
the list arrives as text: JSON ('["main", "0x401000"]'), a comma-separated
list, or one bare name. All three are accepted, because the caller should
not have to guess which one the command wants.
"""

import json
from typing import List


# How many functions one batch may ask for. The server refuses a longer one,
# so the deadline of a batch is sized for the batch it will actually accept.
MAX_BATCH_TARGETS = 200


def parse_targets(text: str) -> List[str]:
    """The targets of a batch, from JSON text, from a list, or from a bare name.

    Args:
        text: JSON text ('["main", "0x401000"]'), a single name, or several
              names separated by commas or newlines.

    Returns:
        list[str]: The targets, in order, without the empty ones.

    Raises:
        ValueError: when the text is JSON that is not a list of names.
    """
    if isinstance(text, (list, tuple)):
        return [str(item).strip() for item in text if str(item).strip()]

    raw = str(text).strip()
    if not raw:
        return []

    try:
        parsed = json.loads(raw)
    except ValueError:
        parts = [part.strip() for part in raw.replace(";", ",").split(",")]
        return [part for part in parts if part]

    if isinstance(parsed, list):
        return [str(item).strip() for item in parsed if str(item).strip()]
    if isinstance(parsed, str):
        return [parsed.strip()] if parsed.strip() else []
    raise ValueError("the targets must be a list of function names or addresses")
