"""Shared location for persisted Ghidra analysis state."""

import os


def state_dir() -> str:
    """Create the state directory: GHYDRA_STATE_DIR, otherwise ~/.ghidra."""
    base = os.environ.get("GHYDRA_STATE_DIR")
    if not base:
        base = os.path.join(os.path.expanduser("~"), ".ghidra")
    os.makedirs(base, exist_ok=True)
    return base
