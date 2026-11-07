#!/usr/bin/env python3
"""Global bridge contract: every MCP tool has a formatter.

The per-namespace suites (test_kuna.py, test_x64dbg.py, test_rea_parity.py)
only check their own tool lists. A tool added anywhere else could fall through
to ``format_simple_result(response, "Done")`` without any test noticing — 28 of
the 110 tools did exactly that, which threw away the server's result (most
visibly the script catalogue and the captured output of ``scripts_run``).

This suite checks the whole registered catalogue. It needs neither Ghidra nor
any external binary, so it always gives a signal.

Run with:  python test_surface_parity.py
"""

import inspect
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bridge_mcp_hydra as bridge


def _registered_tools():
    """The names FastMCP actually registered, not a hand-maintained list."""
    return set(getattr(bridge.mcp._tool_manager, "_tools", {}))


class SurfaceParityTests(unittest.TestCase):
    """The invariant the three per-namespace suites could not see."""

    def test_every_registered_tool_has_a_formatter(self):
        registered = _registered_tools()
        self.assertTrue(registered, "the bridge registered no tools")
        missing = sorted(registered - set(bridge.FORMATTERS))
        self.assertEqual(
            [], missing,
            "tools without a FORMATTERS entry (they answer 'Done'): "
            + ", ".join(missing),
        )

    def test_no_formatter_is_registered_for_a_tool_that_does_not_exist(self):
        orphaned = sorted(set(bridge.FORMATTERS) - _registered_tools())
        self.assertEqual(
            [], orphaned,
            "stale FORMATTERS entries: " + ", ".join(orphaned),
        )

    def test_every_formatter_is_callable_and_takes_kwargs(self):
        for name, fn in bridge.FORMATTERS.items():
            with self.subTest(formatter=name):
                self.assertTrue(callable(fn))
                params = inspect.signature(fn).parameters.values()
                self.assertTrue(
                    any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params),
                    f"{name} is called as fn(response, **tool_kwargs)",
                )

    def test_no_tool_declares_a_reserved_parameter(self):
        """'arguments' is the MCP container's own name; a flattened client loses it."""
        for name in _registered_tools():
            fn = getattr(bridge, name, None)
            if fn is None:
                continue
            with self.subTest(tool=name):
                self.assertNotIn("arguments", inspect.signature(fn).parameters)

    def test_every_registered_tool_is_callable_on_the_bridge(self):
        for name in _registered_tools():
            with self.subTest(tool=name):
                self.assertTrue(callable(getattr(bridge, name, None)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
