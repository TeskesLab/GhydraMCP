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

    def test_every_tool_actually_applies_its_formatter(self):
        """A FORMATTERS entry on an unwrapped tool is dead: text_output applies it."""
        for name in _registered_tools():
            fn = getattr(bridge, name, None)
            if fn is None:
                continue
            with self.subTest(tool=name):
                self.assertTrue(
                    hasattr(fn, "__wrapped__"),
                    f"{name} is missing @text_output; FORMATTERS[{name}] is never used",
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

class PagingCountTests(unittest.TestCase):
    """I10: ?count=false is offered by both listing tools and reaches the server.

    The counting walk over a large program is what a first-page request pays
    for nothing; the option is only useful if both the tool and the request
    carry it, so both halves are asserted here.
    """

    def setUp(self):
        self.sent = []

    def _patched(self):
        from unittest import mock
        return mock.patch.object(bridge, "_get_instance_port",
                                 side_effect=lambda port=None: 8192)

    def _fake_get(self, port, endpoint, params=None):
        self.sent.append((endpoint, dict(params or {})))
        return {"success": True, "result": [{"name": "f"}],
                "meta": {"counted": False, "offset": 0, "limit": 100, "count": 1}}

    def test_functions_list_sends_count_false(self):
        from unittest import mock
        with self._patched(), mock.patch.object(
                bridge, "safe_get", side_effect=self._fake_get):
            bridge.functions_list.__wrapped__(count=False)
        endpoint, params = self.sent[0]
        self.assertEqual("functions", endpoint)
        self.assertEqual("false", params["count"])

    def test_symbols_list_sends_count_false(self):
        from unittest import mock
        with self._patched(), mock.patch.object(
                bridge, "safe_get", side_effect=self._fake_get):
            bridge.symbols_list.__wrapped__(count=False)
        endpoint, params = self.sent[0]
        self.assertEqual("symbols", endpoint)
        self.assertEqual("false", params["count"])

    def test_the_default_keeps_counting(self):
        from unittest import mock
        with self._patched(), mock.patch.object(
                bridge, "safe_get", side_effect=self._fake_get):
            bridge.functions_list.__wrapped__()
        self.assertEqual("true", self.sent[0][1]["count"])

    def test_both_tools_document_the_option(self):
        for tool in (bridge.functions_list, bridge.symbols_list):
            with self.subTest(tool=tool.__name__):
                self.assertIn("count", inspect.signature(tool).parameters)

class BSimStatusTests(unittest.TestCase):
    """BSim discovery (R1): the tool, its formatter and the answer's shape.

    The live half is validated against a running Ghidra; what can be pinned
    down without one is that the tool exists, renders, and that "not ready"
    always carries the reason a client needs to fix it.
    """

    def test_the_tool_is_registered_with_a_formatter(self):
        tools = set(getattr(bridge.mcp._tool_manager, "_tools", {}))
        self.assertIn("bsim_status", tools)
        self.assertIn("bsim_status", bridge.FORMATTERS)

    def test_it_is_part_of_the_analysis_workflow(self):
        self.assertEqual("functions", bridge._tool_group("bsim_status"))

    def test_a_ready_answer_says_so_without_a_reason(self):
        text = bridge.format_bsim_status({"success": True, "result": {
            "available": True, "database": "/tmp/sig.h2", "database_exists": True,
            "ready": True, "reason": None}})
        self.assertIn("BSim: ready", text)
        self.assertIn("/tmp/sig.h2", text)

    def test_a_missing_database_is_reported_with_how_to_fix_it(self):
        text = bridge.format_bsim_status({"success": True, "result": {
            "available": True, "database": None, "database_exists": False,
            "ready": False,
            "reason": "no signature database is configured; set "
                      "-Dghydra.bsim.database=<path>"}})
        self.assertIn("not ready", text)
        self.assertIn("no signature database is configured", text)

    def test_an_absent_engine_is_reported_as_absent(self):
        text = bridge.format_bsim_status({"success": True, "result": {
            "available": False, "database": None, "database_exists": False,
            "ready": False, "reason": "this Ghidra build has no BSim query engine"}})
        self.assertIn("engine: absent", text)
        self.assertIn("has no BSim query engine", text)

    def test_an_error_answer_renders_as_the_error(self):
        failure = {"success": False,
                   "error": {"code": "INSTANCE_NOT_FOUND", "message": "no instance"}}
        self.assertIn("INSTANCE_NOT_FOUND", bridge.format_bsim_status(failure))


if __name__ == "__main__":
    unittest.main(verbosity=2)
