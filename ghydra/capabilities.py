"""Capability triage — re-exported from the single core (I1).

The implementation lives in :mod:`ghydra.core.capabilities`, which is pure and is
generated into the bridge. This module keeps the historical import path so the
CLI, the tests and the docs do not need to change.
"""

from .core.capabilities import (  # noqa: F401  (re-exported public names)
    CAPABILITY_RULES,
    build_capability_report,
)

__all__ = ["CAPABILITY_RULES", "build_capability_report"]
