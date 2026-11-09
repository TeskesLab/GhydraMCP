"""The context pack — re-exported from the single core (I1).

The implementation lives in :mod:`ghydra.core.contextpack`, which is pure and is
generated into the bridge. This module keeps the historical import path so the
CLI, the tests and the docs do not need to change.
"""

from .core.contextpack import (  # noqa: F401  (re-exported public names)
    TEMPLATES,
    build_context_pack,
    classify_question,
    estimate_tokens,
)

__all__ = ["TEMPLATES", "build_context_pack", "classify_question",
           "estimate_tokens"]
