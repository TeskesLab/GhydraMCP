#!/usr/bin/env python3
"""Tests for the local telemetry (I14).

No Ghidra, no network: the recorder writes into a temporary state dir, the
summarizer is exercised over synthetic entries, and the CLI command is built
against that file. The bridge and CLI summarizers are asserted to agree.

Run with:  python tests/test_telemetry.py
"""

import json
import os
import sys
import tempfile
import time
import unittest

# The tests live in tests/; the code and the repository are one level up.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bridge_mcp_hydra as bridge  # noqa: E402
from ghydra import telemetry as cli_telemetry  # noqa: E402


def entries(pattern, ok=True, ms=10.0, tokens=50):
    return [{"ts": time.time(), "tool": tool, "ok": ok, "code": None,
             "ms": ms, "tokens": tokens} for tool in pattern]


class RecorderTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.old_state = os.environ.get("GHYDRA_STATE_DIR")
        self.old_enabled = os.environ.get("GHYDRA_TELEMETRY")
        os.environ["GHYDRA_STATE_DIR"] = self.dir.name
        os.environ.pop("GHYDRA_TELEMETRY", None)

    def tearDown(self):
        if self.old_state is None:
            os.environ.pop("GHYDRA_STATE_DIR", None)
        else:
            os.environ["GHYDRA_STATE_DIR"] = self.old_state
        if self.old_enabled is None:
            os.environ.pop("GHYDRA_TELEMETRY", None)
        else:
            os.environ["GHYDRA_TELEMETRY"] = self.old_enabled
        self.dir.cleanup()

    def test_a_call_is_appendable_and_readable(self):
        bridge._telemetry_record("functions_get", True, None, 12.5, 40)
        bridge._telemetry_record("functions_get", False, "TIMEOUT", 900.0, 3)
        rows = bridge._telemetry_read()
        self.assertEqual(2, len(rows))
        self.assertEqual("functions_get", rows[0]["tool"])
        self.assertEqual("TIMEOUT", rows[1]["code"])

    def test_the_log_is_bounded(self):
        for index in range(40):
            bridge._telemetry_record("t", True, None, 1.0, 1)
        self.assertTrue(os.path.exists(bridge._telemetry_path()))
        with open(bridge._telemetry_path(), encoding="utf-8") as handle:
            self.assertEqual(40, len(handle.read().splitlines()))

    def test_telemetry_follows_the_state_dir(self):
        self.assertTrue(bridge._telemetry_path().startswith(self.dir.name))

    def test_disabling_writes_nothing(self):
        os.environ["GHYDRA_TELEMETRY"] = "0"
        bridge._telemetry_record("x", True, None, 1.0, 1)
        self.assertEqual([], bridge._telemetry_read())

    def test_a_corrupt_line_is_skipped(self):
        os.makedirs(self.dir.name, exist_ok=True)
        with open(bridge._telemetry_path(), "w", encoding="utf-8") as handle:
            handle.write("not json\n")
            handle.write(json.dumps({"tool": "ok", "ok": True, "ms": 1}) + "\n")
        self.assertEqual(1, len(bridge._telemetry_read()))

    def test_the_wrapper_records_a_call_without_changing_the_answer(self):
        bridge._telemetry_record("functions_get", True, None, 1.0, 1)
        rows = bridge._telemetry_read()
        self.assertEqual(1, len(rows))
        # the recorder never raises, even with a broken file/dir
        bridge._telemetry_record("x", True, None, 1.0, 1)
        self.assertEqual(2, len(bridge._telemetry_read()))


class SummarizerTests(unittest.TestCase):
    def test_the_two_summarizers_agree(self):
        rows = entries(["functions_get", "functions_decompile",
                        "analysis_callers", "xrefs_list"])
        bridge_rows = bridge._telemetry_recommendations(rows)
        cli_rows = cli_telemetry.recommendations(rows)
        self.assertEqual(bridge_rows, cli_rows)

    def test_four_inspection_calls_recommend_the_context_pack(self):
        rows = entries(["functions_get", "functions_decompile",
                        "analysis_callers", "xrefs_list"])
        text = " ".join(bridge._telemetry_recommendations(rows))
        self.assertIn("analysis_context_pack", text)

    def test_four_listing_calls_recommend_the_overview(self):
        rows = entries(["functions_list", "data_list", "symbols_list",
                        "variables_list"])
        text = " ".join(bridge._telemetry_recommendations(rows))
        self.assertIn("programs_overview", text)

    def test_four_decompiles_recommend_the_batch(self):
        rows = entries(["functions_decompile"] * 4)
        text = " ".join(bridge._telemetry_recommendations(rows))
        self.assertIn("functions_batch_decompile", text)

    def test_a_slow_tool_is_named(self):
        rows = entries(["functions_get"], ms=800.0)
        text = " ".join(bridge._telemetry_recommendations(rows))
        self.assertIn("functions_get took up to", text)

    def test_a_short_log_recommends_nothing(self):
        rows = entries(["functions_get", "functions_get"])
        self.assertEqual([], bridge._telemetry_recommendations(rows))


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.old_state = os.environ.get("GHYDRA_STATE_DIR")
        os.environ["GHYDRA_STATE_DIR"] = self.dir.name

    def tearDown(self):
        if self.old_state is None:
            os.environ.pop("GHYDRA_STATE_DIR", None)
        else:
            os.environ["GHYDRA_STATE_DIR"] = self.old_state
        self.dir.cleanup()

    def test_the_tool_is_registered_and_formatted(self):
        registered = getattr(bridge.mcp._tool_manager, "_tools", {})
        self.assertIn("telemetry_summary", registered)
        self.assertIs(bridge.format_telemetry_summary,
                      bridge.FORMATTERS.get("telemetry_summary"))

    def test_an_empty_window_says_so_without_failing(self):
        raw = bridge.telemetry_summary.__wrapped__(days=7)
        self.assertTrue(raw["success"])
        self.assertEqual(0, raw["result"]["calls"])
        self.assertIn("no telemetry", raw["result"]["message"])

    def test_the_tool_aggregates_what_the_recorder_wrote(self):
        bridge._telemetry_record("functions_get", True, None, 10.0, 100)
        bridge._telemetry_record("functions_get", False, "TIMEOUT", 900.0, 5)
        bridge._telemetry_record("data_list", True, None, 2.0, 30)
        raw = bridge.telemetry_summary.__wrapped__(days=7)
        self.assertTrue(raw["success"])
        self.assertEqual(3, raw["result"]["calls"])
        first = raw["result"]["tools"][0]
        self.assertEqual("functions_get", first["tool"])
        self.assertEqual(2, first["calls"])
        self.assertEqual(1, first["failed"])
        self.assertEqual({"TIMEOUT": 1}, raw["result"]["error_codes"])

    def test_the_formatter_renders_the_report(self):
        bridge._telemetry_record("functions_get", True, None, 10.0, 100)
        text = bridge.format_telemetry_summary(
            bridge.telemetry_summary.__wrapped__())
        self.assertIn("Local telemetry", text)
        self.assertIn("functions_get", text)


class CliTests(unittest.TestCase):
    def test_the_stats_command_exists_and_renders(self):
        from ghydra.cli.stats import stats, _format
        self.assertTrue(callable(stats))
        report = {"calls": 1, "days": 7, "path": "x",
                  "tools": [{"tool": "functions_get", "calls": 1,
                             "failed": 0, "ms_avg": 1.0, "tokens": 10}],
                  "error_codes": {}, "recommendations": []}
        text = _format(report, False)
        self.assertIn("Local telemetry", text)
        self.assertIn("functions_get", text)

    def test_the_cli_reads_the_same_file_the_bridge_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            old = os.environ.get("GHYDRA_STATE_DIR")
            os.environ["GHYDRA_STATE_DIR"] = directory
            try:
                bridge._telemetry_record("data_list", True, None, 3.0, 7)
                rows = cli_telemetry.read_entries()
                self.assertEqual(1, len(rows))
                self.assertEqual("data_list", rows[0]["tool"])
                self.assertEqual(cli_telemetry.telemetry_path(),
                                 bridge._telemetry_path())
            finally:
                if old is None:
                    os.environ.pop("GHYDRA_STATE_DIR", None)
                else:
                    os.environ["GHYDRA_STATE_DIR"] = old


class RawOutputTests(unittest.TestCase):
    """GHYDRA_MCP_OUTPUT=json must not turn failures into successes."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.old = os.environ.get("GHYDRA_STATE_DIR")
        os.environ["GHYDRA_STATE_DIR"] = self.dir.name

    def tearDown(self):
        if self.old is None:
            os.environ.pop("GHYDRA_STATE_DIR", None)
        else:
            os.environ["GHYDRA_STATE_DIR"] = self.old
        self.dir.cleanup()

    def test_an_error_envelope_rendered_as_json_is_recorded_as_failed(self):
        import time as _time
        envelope = {"success": False,
                    "error": {"code": "FUNCTION_NOT_FOUND", "message": "no"}}
        bridge._telemetry_safely("functions_get", _time.perf_counter(),
                                 envelope, '{"success": false, ...}')
        rows = bridge._telemetry_read()
        self.assertEqual(1, len(rows))
        self.assertFalse(rows[0]["ok"])
        self.assertEqual("FUNCTION_NOT_FOUND", rows[0]["code"])

    def test_a_successful_envelope_is_recorded_as_success(self):
        import time as _time
        bridge._telemetry_safely("functions_get", _time.perf_counter(),
                                 {"success": True, "result": {}}, "ok")
        self.assertTrue(bridge._telemetry_read()[0]["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)


