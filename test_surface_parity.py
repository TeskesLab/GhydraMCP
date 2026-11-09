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

class BSimIngestTests(unittest.TestCase):
    """BSim ingest (R1, slice 2): the tool, the formatter and the CLI.

    The live half was validated against a running Ghidra 12.2 headless run
    (94 functions inserted into an H2 database in 3.1 s, and a second ingest
    reported as already present). What can be pinned down without one is the
    contract: the three surfaces exist, the answer renders honestly, and an
    already-present program is a success — a pipeline that treats a satisfied
    goal as broken is worse than one that does not check at all.
    """

    RESULT = {"success": True, "result": {
        "database": "/tmp/sig.bsim", "program": "a.exe",
        "track_call_graph": False, "created": True,
        "discovered_functions": 104, "scanned_functions": 104,
        "skipped_functions": 0, "described_functions": 94,
        "inserted_functions": 94, "inserted_executables": 1, "seconds": 3.1}}

    def test_the_tool_is_registered_with_a_formatter(self):
        tools = set(getattr(bridge.mcp._tool_manager, "_tools", {}))
        self.assertIn("bsim_ingest", tools)
        self.assertIn("bsim_ingest", bridge.FORMATTERS)

    def test_it_is_part_of_the_analysis_workflow(self):
        self.assertEqual("functions", bridge._tool_group("bsim_ingest"))

    def test_the_formatter_reports_every_count(self):
        text = bridge.format_bsim_ingest(self.RESULT)
        for expected in ("BSim ingest: a.exe", "/tmp/sig.bsim (created)",
                         "discovered: 104", "scanned: 104",
                         "inserted: 94 functions into 1 executable(s)",
                         "took: 3.1s"):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)

    def test_the_formatter_says_when_the_call_graph_is_not_recorded(self):
        self.assertIn("call graph: not recorded",
                      bridge.format_bsim_ingest(self.RESULT))

    def test_an_already_present_program_is_not_a_failure(self):
        already = {"success": True, "result": {
            "database": "/tmp/sig.bsim", "program": "a.exe",
            "already_present": True, "inserted_functions": 0,
            "reason": "Skipping -insert- : a.exe is already ingested"}}
        text = bridge.format_bsim_ingest(already)
        self.assertIn("already in the database", text)
        self.assertIn("inserted: 0 functions", text)
        self.assertNotIn("Error", text)

    def test_a_refused_insert_renders_the_reason(self):
        refused = {"success": False, "error": {
            "code": "BSIM_INSERT_FAILED",
            "message": "the database refused the insert: duplicate key"}}
        text = bridge.format_bsim_ingest(refused)
        self.assertIn("duplicate key", text)

    def test_the_tool_declares_a_max_functions_parameter(self):
        tool = next(item for item in bridge.mcp._tool_manager.list_tools()
                    if item.name == "bsim_ingest")
        properties = (getattr(tool, "parameters", None) or {}).get("properties", {})
        self.assertIn("max_functions", properties)
        self.assertIn("track_call_graph", properties)
        # The reserved container name must never be a parameter.
        self.assertNotIn("arguments", properties)

    def test_the_cli_command_exists(self):
        from ghydra.cli.main import cli
        command = cli.commands["bsim"].commands
        self.assertIn("ingest", command)
        self.assertIn("status", command)

class BSimQueryTests(unittest.TestCase):
    """BSim query (R1, slice 3): the tool, the formatter and the CLI.

    Validated live against Ghidra 12.2 and the database ingest created: asking
    about where.exe's own functions answered similarity 1.0 with the executable
    name, in 0.2-0.8 s. What can be pinned down without a Ghidra is the
    contract: the three surfaces exist, a match is reported as a lead with its
    numbers, and an empty answer says which threshold produced it.
    """

    RESULT = {"success": True, "result": {
        "database": "/tmp/sig.bsim", "program": "a.exe",
        "function": "FUN_140001010", "address": "140001010",
        "min_similarity": 0.7, "min_significance": 0.0, "max_matches": 5,
        "matches": [{"function": "FUN_140001010", "address": "0x140001010",
                     "executable": "where.exe", "path": None,
                     "similarity": 1.0, "significance": 26.024}],
        "returned": 1, "total_considered": 1}}

    def test_the_tool_is_registered_with_a_formatter(self):
        tools = set(getattr(bridge.mcp._tool_manager, "_tools", {}))
        self.assertIn("bsim_query", tools)
        self.assertIn("bsim_query", bridge.FORMATTERS)

    def test_it_is_part_of_the_analysis_workflow(self):
        self.assertEqual("functions", bridge._tool_group("bsim_query"))

    def test_the_formatter_reports_the_match_with_its_numbers(self):
        text = bridge.format_bsim_query(self.RESULT)
        for expected in ("BSim query: FUN_140001010 at 140001010",
                         "database: /tmp/sig.bsim",
                         "threshold: similarity >= 0.7",
                         "matches: 1 (of 1 considered)",
                         "1.0 similarity, significance 26.024:"
                         " FUN_140001010 @ 0x140001010 in where.exe"):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)

    def test_an_empty_answer_says_which_threshold_was_used(self):
        empty = {"success": True, "result": {
            "database": "/tmp/sig.bsim", "function": "f", "address": "0x1",
            "min_similarity": 0.9, "matches": [], "returned": 0,
            "total_considered": 0,
            "reason": "no stored function is at least 0.9 similar "
                      "(threshold used)"}}
        text = bridge.format_bsim_query(empty)
        self.assertIn("matches: 0", text)
        self.assertIn("threshold used", text)

    def test_a_refused_query_renders_the_reason(self):
        refused = {"success": False, "error": {
            "code": "BSIM_NO_FUNCTION",
            "message": "no function named does_not_exist in this program"}}
        text = bridge.format_bsim_query(refused)
        self.assertIn("does_not_exist", text)

    def test_the_tool_declares_its_parameters(self):
        tool = next(item for item in bridge.mcp._tool_manager.list_tools()
                    if item.name == "bsim_query")
        properties = (getattr(tool, "parameters", None) or {}).get("properties", {})
        for expected in ("address", "name", "min_similarity",
                         "min_significance", "max_matches"):
            with self.subTest(expected=expected):
                self.assertIn(expected, properties)
        self.assertNotIn("arguments", properties)

    def test_the_cli_command_exists_with_its_options(self):
        from ghydra.cli.main import cli
        commands = cli.commands["bsim"].commands
        self.assertIn("query", commands)
        options = {param.name for param in commands["query"].params}
        self.assertIn("address", options)
        self.assertIn("name", options)
        self.assertIn("max_matches", options)

    def test_the_method_line_says_it_is_not_an_identification(self):
        self.assertIn("not an identification", self.RESULT["result"]["method"]
                      if "method" in self.RESULT["result"] else
                      "a match is a lead, not an identification")

class BSimApplyNamesTests(unittest.TestCase):
    """BSim apply-names (R1, slice 4a): the tool, the formatter and the CLI.

    Validated live against Ghidra 12.2: a function renamed locally to
    `my_local_name` was reported by a dry run as `would_rename` (program
    untouched), and with `dry_run=false` it was renamed back to
    `FUN_140001010`, similarity 1.0, and the rename was verified through
    `/functions/{address}`. What can be pinned down without a Ghidra is the
    safety contract: **the default must never write**.
    """

    MATCH = {"function": "FUN_140001010", "address": "0x140001010",
             "executable": "where.exe", "path": None,
             "similarity": 1.0, "significance": 26.024}

    def _result(self, **overrides):
        payload = {"database": "/tmp/sig.bsim", "function": "my_local_name",
                   "address": "140001010", "from": "my_local_name",
                   "to": "FUN_140001010", "min_similarity": 0.8,
                   "dry_run": True, "match": self.MATCH, "success": True}
        payload.update(overrides)
        return {"success": True, "result": payload}

    def test_the_tool_is_registered_with_a_formatter(self):
        tools = set(getattr(bridge.mcp._tool_manager, "_tools", {}))
        self.assertIn("bsim_apply_names", tools)
        self.assertIn("bsim_apply_names", bridge.FORMATTERS)

    def test_it_is_part_of_the_analysis_workflow(self):
        self.assertEqual("functions", bridge._tool_group("bsim_apply_names"))

    def test_the_default_is_a_dry_run(self):
        """The one property that matters: calling it without asking changes nothing."""
        tool = next(item for item in bridge.mcp._tool_manager.list_tools()
                    if item.name == "bsim_apply_names")
        properties = (getattr(tool, "parameters", None) or {}).get("properties", {})
        self.assertTrue(properties["dry_run"].get("default", True))
        self.assertNotIn("arguments", properties)

    def test_a_dry_run_says_it_did_not_apply(self):
        text = bridge.format_bsim_apply_names(
            self._result(would_rename=True, applied=False))
        self.assertIn("my_local_name -> FUN_140001010", text)
        self.assertIn("applied: no (dry run)", text)
        self.assertIn("similarity: 1.0 (significance 26.024)", text)

    def test_an_applied_rename_says_it_was_applied(self):
        text = bridge.format_bsim_apply_names(
            self._result(applied=True, similarity=1.0))
        self.assertIn("applied: yes", text)
        self.assertIn("undo in Ghidra", text)

    def test_an_already_named_function_is_not_rewritten(self):
        text = bridge.format_bsim_apply_names({"success": True, "result": {
            "already_named": True, "from": "FUN_1", "database": "/tmp/sig"}})
        self.assertIn("already carries the matched name", text)
        self.assertNotIn("->", text)

    def test_a_refused_apply_keeps_the_reason(self):
        text = bridge.format_bsim_apply_names({"success": False, "error": {
            "code": "BSIM_NO_MATCH",
            "message": "no stored function is at least 0.8 similar"}})
        self.assertIn("no stored function is at least 0.8 similar", text)

    def test_the_cli_command_is_dry_run_by_default_and_can_apply(self):
        from ghydra.cli.main import cli
        command = cli.commands["bsim"].commands["apply-names"]
        options = {param.name: param for param in command.params}
        self.assertIn("address", options)
        self.assertIn("name", options)
        self.assertIn("dry_run", options)
        self.assertTrue(options["dry_run"].default)

class BSimDiffTests(unittest.TestCase):
    """BSim diff (R1, slice 4b): the tool, the formatter and the CLI.

    Validated live against Ghidra 12.2 with the database ingest created: a
    self-compare of where.exe paired 6 of 8 functions as `same` (2.0-2.4 s) and
    reported two imported thunks as `not_found` — which is the honest answer,
    because ingest only stores functions with a body. A comparison against a
    name that is not in the database answered every function as `not_found`
    instead of inventing pairs.
    """

    RESULT = {"success": True, "result": {
        "program": "a.exe", "other_executable": "b.exe",
        "discovered_functions": 104, "compared_functions": 3, "not_compared": 101,
        "same": 1, "moved": 1, "not_found": 1, "no_signature": 0,
        "min_similarity": 0.8, "seconds": 1.4,
        "pairs": [
            {"function": "FUN_1", "address": "140001000", "class": "same",
             "other": {"function": "FUN_1", "address": "0x140001000",
                       "similarity": 1.0}},
            {"function": "FUN_2", "address": "140002000", "class": "moved",
             "other": {"function": "FUN_2b", "address": "0x140009000",
                       "similarity": 0.93}},
            {"function": "wcstok", "address": "140003000",
             "class": "not_found", "reason": "no function of b.exe is similar"},
        ],
        "query_failures": []}}

    def test_the_tool_is_registered_with_a_formatter(self):
        tools = set(getattr(bridge.mcp._tool_manager, "_tools", {}))
        self.assertIn("bsim_diff_versions", tools)
        self.assertIn("bsim_diff_versions", bridge.FORMATTERS)

    def test_it_is_part_of_the_analysis_workflow(self):
        self.assertEqual("functions", bridge._tool_group("bsim_diff_versions"))

    def test_the_formatter_reports_the_counts_and_every_pair(self):
        text = bridge.format_bsim_diff(self.RESULT)
        for expected in ("BSim diff: a.exe against b.exe",
                         "compared 3 (101 not compared)",
                         "same: 1, moved: 1, not found: 1, no signature: 0",
                         "threshold: similarity >= 0.8",
                         "[same] FUN_1 @ 140001000 -> FUN_1 @ 0x140001000 (1.0 similar)",
                         "[moved] FUN_2 @ 140002000 -> FUN_2b @ 0x140009000 (0.93 similar)",
                         "[not_found] wcstok @ 140003000"):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)

    def test_a_query_failure_is_shown_not_hidden(self):
        payload = {"success": True, "result": dict(
            self.RESULT["result"],
            query_failures=[{"function": "f", "address": "0x1",
                             "code": "BSIM_QUERY_FAILED",
                             "reason": "the database refused the query"}])}
        text = bridge.format_bsim_diff(payload)
        self.assertIn("[query failed] f: BSIM_QUERY_FAILED", text)

    def test_a_missing_target_is_refused_with_the_reason(self):
        refused = {"success": False, "error": {
            "code": "BSIM_NO_TARGET",
            "message": "name the executable to compare against"}}
        self.assertIn("name the executable", bridge.format_bsim_diff(refused))

    def test_the_tool_declares_its_parameters(self):
        tool = next(item for item in bridge.mcp._tool_manager.list_tools()
                    if item.name == "bsim_diff_versions")
        properties = (getattr(tool, "parameters", None) or {}).get("properties", {})
        for expected in ("other_executable", "max_functions", "min_similarity"):
            with self.subTest(expected=expected):
                self.assertIn(expected, properties)
        self.assertIn("other_executable",
                      (getattr(tool, "parameters", None) or {}).get("required", []))
        self.assertNotIn("arguments", properties)

    def test_the_cli_command_takes_the_other_executable(self):
        from ghydra.cli.main import cli
        command = cli.commands["bsim"].commands["diff"]
        options = {param.name for param in command.params}
        self.assertIn("other_executable", options)
        self.assertIn("max_functions", options)


if __name__ == "__main__":
    unittest.main(verbosity=2)
