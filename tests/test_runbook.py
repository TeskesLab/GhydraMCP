#!/usr/bin/env python3
"""Tests for reproducible runbooks and analysis_diff (R6).

Needs neither Ghidra nor the network: a fake client answers the API calls, and
the bridge half is driven through its own helpers. The two sides duplicate this
logic by necessity (the bridge ships as one file and must not import ghydra),
so the parity of the digest, the comparison and the diff is asserted here.

Run with:  python tests/test_runbook.py
"""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

# The tests live in tests/; the code and the repository are one level up.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bridge_mcp_hydra as bridge  # noqa: E402
from ghydra import diff as diff_helper  # noqa: E402
from ghydra import runbook as rb  # noqa: E402
from ghydra.cli.runbook_cmd import runbook  # noqa: E402


class FakeClient:
    """Answers the endpoints a runbook or a diff reaches for."""

    def __init__(self, functions=None, imports=None, strings=None,
                 program=None, flip=False):
        self.functions = functions if functions is not None else [
            {"address": "0x401000", "name": "main", "size": 64},
            {"address": "0x401100", "name": "sub_401100", "size": 32},
        ]
        self.imports = imports if imports is not None else ["CreateFileW", "ReadFile"]
        self.strings = strings if strings is not None else ["hello", "/api/v1"]
        self.program = program if program is not None else {
            "name": "sample.exe", "executable_path": "/tmp/sample.exe",
            "image_base": "0x400000"}
        self.flip = flip
        self.calls = []

    def get(self, endpoint, params=None):
        self.calls.append((endpoint, params or {}))
        params = params or {}
        if endpoint == "program":
            return {"success": True, "result": dict(self.program)}
        if endpoint == "functions":
            return self._page(self.functions, params)
        if endpoint == "symbols/imports":
            return self._page([{"name": i} for i in self.imports], params)
        if endpoint == "strings":
            return self._page([{"value": s} for s in self.strings], params)
        return {"success": True, "result": {"echo": endpoint}}

    def _page(self, items, params):
        offset = params.get("offset", 0)
        limit = params.get("limit", 1000)
        page = items[offset:offset + limit]
        return {"success": True, "result": page, "meta": {"total": len(items)}}


class RunbookFormatTests(unittest.TestCase):
    def test_the_digest_ignores_key_order(self):
        self.assertEqual(rb.digest({"a": 1, "b": 2}), rb.digest({"b": 2, "a": 1}))

    def test_volatile_metadata_does_not_change_the_digest(self):
        one = {"success": True, "id": "1", "timestamp": 1,
               "result": {"name": "f", "address": "0x1"}}
        two = {"success": True, "id": "2", "timestamp": 999,
               "result": {"name": "f", "address": "0x1"}}
        self.assertEqual(rb.digest(rb.stable_result(one)),
                         rb.digest(rb.stable_result(two)))

    def test_a_real_change_does_change_the_digest(self):
        one = {"success": True, "result": {"name": "f"}}
        two = {"success": True, "result": {"name": "g"}}
        self.assertNotEqual(rb.digest(rb.stable_result(one)),
                            rb.digest(rb.stable_result(two)))

    def test_load_steps_accepts_a_list_and_a_wrapped_list(self):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                             encoding="utf-8")
        try:
            for payload in ([{"endpoint": "program"}],
                            {"steps": [{"endpoint": "program", "method": "get"}]}):
                handle.seek(0)
                handle.truncate()
                handle.write(json.dumps(payload))
                handle.flush()
                steps = rb.load_steps(handle.name)
                self.assertEqual(1, len(steps))
                self.assertEqual("GET", steps[0]["method"])
        finally:
            handle.close()
            os.unlink(handle.name)

    def test_load_steps_refuses_what_it_cannot_call(self):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                             encoding="utf-8")
        try:
            for payload in ([], [{"method": "GET"}],
                            [{"endpoint": "program", "method": "BREW"}]):
                handle.seek(0)
                handle.truncate()
                handle.write(json.dumps(payload))
                handle.flush()
                with self.assertRaises(rb.RunbookError):
                    rb.load_steps(handle.name)
        finally:
            handle.close()
            os.unlink(handle.name)


class RunbookRoundTripTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "rb.ghydrarb.jsonl")

    def _steps(self):
        return [{"endpoint": "program", "method": "GET"},
                {"endpoint": "functions", "method": "GET",
                 "params": {"limit": 10}}]

    def test_record_then_replay_against_the_same_binary_is_identical(self):
        client = FakeClient()
        document = rb.record(client, self._steps())
        rb.save(document, self.path)
        loaded = rb.load(self.path)
        report = rb.replay(loaded, FakeClient())
        self.assertEqual(0, report["result"]["changed"], report)
        self.assertEqual(2, report["result"]["identical"])
        self.assertTrue(report["result"]["ok"])

    def test_a_changed_answer_is_reported_as_changed(self):
        document = rb.record(FakeClient(), self._steps())
        rb.save(document, self.path)
        # the recorded steps read "program" and "functions", so it is the
        # function list that has to differ for the answer to move
        moved = FakeClient(functions=[{"address": "0x401000", "name": "renamed",
                                       "size": 64}])
        report = rb.replay(rb.load(self.path), moved)
        self.assertEqual(1, report["result"]["changed"])
        self.assertFalse(report["result"]["ok"])

    def test_a_changed_program_fingerprint_is_called_out(self):
        document = rb.record(FakeClient(), self._steps())
        rb.save(document, self.path)
        other = FakeClient(program={"name": "other.exe"})
        report = rb.replay(rb.load(self.path), other)
        self.assertTrue(report["result"]["program_changed"])

    def test_a_failing_step_is_recorded_and_reported(self):
        class Broken(FakeClient):
            def get(self, endpoint, params=None):
                if endpoint == "functions":
                    return {"success": False,
                            "error": {"code": "TIMEOUT", "message": "slow"}}
                return super().get(endpoint, params)

        document = rb.record(Broken(), self._steps())
        self.assertFalse(document["entries"][1]["ok"])
        self.assertEqual("TIMEOUT", document["entries"][1]["code"])
        rb.save(document, self.path)
        report = rb.replay(rb.load(self.path), Broken())
        self.assertEqual(1, report["result"]["failed"])

    def test_the_file_is_jsonl_with_a_header(self):
        rb.save(rb.record(FakeClient(), self._steps()), self.path)
        with open(self.path, encoding="utf-8") as handle:
            lines = [line for line in handle.read().splitlines() if line]
        self.assertEqual(3, len(lines))
        header = json.loads(lines[0])
        self.assertEqual(1, header["runbook"])
        self.assertEqual("sample.exe", header["program"]["name"])

    def test_a_bad_file_is_refused(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write("not a runbook\n")
        with self.assertRaises(rb.RunbookError):
            rb.load(self.path)

    def test_an_unknown_version_is_refused(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"runbook": 99}) + "\n")
        with self.assertRaises(rb.RunbookError):
            rb.load(self.path)


class DiffTests(unittest.TestCase):
    def _snapshots(self):
        a = diff_helper.collect_snapshot(FakeClient())
        b = diff_helper.collect_snapshot(FakeClient(
            functions=[{"address": "0x401000", "name": "entry", "size": 64},
                       {"address": "0x401200", "name": "added", "size": 16}],
            imports=["CreateFileW", "WinExec"],
            strings=["hello", "new string"],
            program={"name": "sample.exe", "executable_path": "/tmp/sample.exe",
                     "image_base": "0x500000"}))
        return a, b

    def test_a_rename_is_not_an_add_plus_a_remove(self):
        a, b = self._snapshots()
        report = diff_helper.diff_snapshots(a, b)
        self.assertEqual(1, len(report["functions"]["renamed"]))
        self.assertEqual("main", report["functions"]["renamed"][0]["from"])
        self.assertEqual("entry", report["functions"]["renamed"][0]["to"])
        self.assertEqual(["0x401200"],
                         [fn["address"] for fn in report["functions"]["added"]])
        self.assertEqual(["0x401100"],
                         [fn["address"] for fn in report["functions"]["removed"]])

    def test_imports_and_strings_are_diffed_by_name(self):
        a, b = self._snapshots()
        report = diff_helper.diff_snapshots(a, b)
        self.assertEqual(["WinExec"], report["imports"]["added"])
        self.assertEqual(["ReadFile"], report["imports"]["removed"])
        self.assertEqual(["new string"], report["strings"]["added"])
        self.assertEqual(["/api/v1"], report["strings"]["removed"])

    def test_the_program_fingerprint_is_compared(self):
        a, b = self._snapshots()
        self.assertTrue(diff_helper.diff_snapshots(a, b)["program_changed"])

    def test_an_identical_pair_changes_nothing(self):
        snapshot = diff_helper.collect_snapshot(FakeClient())
        report = diff_helper.diff_snapshots(snapshot, snapshot)
        self.assertFalse(report["changed"])
        self.assertTrue(report["functions"]["complete"])

    def test_a_truncated_listing_is_not_a_removal(self):
        class Endless(FakeClient):
            def _page(self, items, params):
                page = [{"address": f"0x{i}", "name": f"f{i}"}
                        for i in range(1000)]
                return {"success": True, "result": page,
                        "meta": {"total": 10 ** 9}}

        a = diff_helper.collect_snapshot(Endless())
        b = diff_helper.collect_snapshot(FakeClient())
        report = diff_helper.diff_snapshots(a, b)
        self.assertFalse(report["functions"]["complete"])

    def test_strings_can_be_skipped(self):
        snapshot = diff_helper.collect_snapshot(FakeClient(), include_strings=False)
        self.assertEqual([], snapshot["strings"])

    def test_the_text_render_mentions_every_section(self):
        a, b = self._snapshots()
        text = diff_helper.to_text(diff_helper.diff_snapshots(a, b))
        self.assertIn("functions:", text)
        self.assertIn("imports:", text)
        self.assertIn("strings:", text)
        self.assertIn("renamed", text)


class ParityTests(unittest.TestCase):
    """The bridge duplicates this logic; the two must agree exactly."""

    def test_the_digest_agrees(self):
        for value in ({"a": 1}, [1, 2, 3], "text", {"nested": {"b": [2, 1]}}):
            self.assertEqual(rb.digest(value), bridge._runbook_digest(value))

    def test_the_comparison_view_agrees(self):
        envelope = {"success": True, "id": "x", "timestamp": 5,
                    "instance": 8192, "_links": {"self": {}},
                    "result": {"name": "f", "address": "0x1"}}
        self.assertEqual(rb.stable_result(envelope),
                         bridge._runbook_stable_result(envelope))

    def test_the_diff_agrees_on_the_same_snapshots(self):
        a = {"program": {"name": "a"}, "functions": [
                {"address": "0x1", "name": "main"},
                {"address": "0x2", "name": "gone"}],
             "imports": ["A", "B"], "strings": ["s1"],
             "functions_complete": True, "imports_complete": True,
             "strings_complete": True}
        b = {"program": {"name": "b"}, "functions": [
                {"address": "0x1", "name": "entry"},
                {"address": "0x3", "name": "new"}],
             "imports": ["A", "C"], "strings": ["s1", "s2"],
             "functions_complete": True, "imports_complete": True,
             "strings_complete": True}
        self.assertEqual(diff_helper.diff_snapshots(a, b),
                         bridge._diff_snapshots(a, b))

    def test_step_validation_agrees(self):
        good = [{"endpoint": "program", "method": "get"}]
        self.assertEqual(rb.load_steps.__doc__ is not None, True)
        self.assertEqual(1, len(bridge._runbook_load_steps(json.dumps(good))))
        for bad in ([], [{"method": "GET"}], [{"endpoint": "x", "method": "BREW"}]):
            with self.assertRaises(ValueError):
                bridge._runbook_load_steps(json.dumps(bad))


class BridgeToolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "bridge.ghydrarb.jsonl")

    def _patch(self):
        return mock.patch.object(bridge, "_get_instance_port",
                                 side_effect=lambda port=None: 8192)

    def test_the_three_tools_are_registered_with_a_formatter(self):
        tools = set(getattr(bridge.mcp._tool_manager, "_tools", {}))
        for name in ("runbook_record", "runbook_replay", "analysis_diff"):
            with self.subTest(tool=name):
                self.assertIn(name, tools)
                self.assertIn(name, bridge.FORMATTERS)

    def test_record_writes_a_replayable_file(self):
        answers = {"program": {"success": True, "result": {"name": "x"}},
                   "functions": {"success": True, "result": [], "meta": {"total": 0}}}

        def fake_get(port, endpoint, params=None):
            return answers.get(endpoint, {"success": True, "result": {}})

        steps = json.dumps([{"endpoint": "program"}])
        with self._patch(), mock.patch.object(bridge, "safe_get", side_effect=fake_get):
            result = bridge.runbook_record.__wrapped__(steps, self.path)
        self.assertTrue(result["success"], result)
        self.assertEqual(1, result["result"]["steps"])
        header = json.loads(open(self.path, encoding="utf-8").readline())
        self.assertEqual(1, header["runbook"])

    def test_record_refuses_bad_steps(self):
        with self._patch():
            result = bridge.runbook_record.__wrapped__("[]", self.path)
        self.assertFalse(result["success"])
        self.assertEqual("RUNBOOK_BAD_STEPS", result["error"]["code"])

    def test_replay_reports_identical_answers(self):
        answers = {"program": {"success": True, "result": {"name": "x"}}}
        with self._patch(), mock.patch.object(
                bridge, "safe_get",
                side_effect=lambda p, e, params=None: answers.get(
                    e, {"success": True, "result": {}})):
            bridge.runbook_record.__wrapped__(json.dumps(
                [{"endpoint": "program"}]), self.path)
            report = bridge.runbook_replay.__wrapped__(self.path)
        self.assertTrue(report["success"], report)
        self.assertEqual(1, report["result"]["identical"])

    def test_analysis_diff_compares_two_ports(self):
        left = {"functions": [{"address": "0x1", "name": "main"}]}
        right = {"functions": [{"address": "0x1", "name": "entry"}]}

        def fake_get(port, endpoint, params=None):
            source = left if port == 8192 else right
            if endpoint == "functions":
                return {"success": True, "result": source["functions"],
                        "meta": {"total": 1}}
            if endpoint == "program":
                return {"success": True, "result": {"name": "p"}}
            return {"success": True, "result": []}

        with self._patch(), mock.patch.object(bridge, "safe_get", side_effect=fake_get):
            result = bridge.analysis_diff.__wrapped__(b_port=8193)
        self.assertTrue(result["success"], result)
        self.assertEqual(1, len(result["result"]["functions"]["renamed"]))

    def test_the_formatters_render_both_shapes(self):
        record = {"success": True, "result": {"path": "x.jsonl", "steps": 2,
                                              "failed": [{"step": 2,
                                                          "endpoint": "functions",
                                                          "code": "TIMEOUT"}]}}
        text = bridge.format_runbook_record(record)
        self.assertIn("x.jsonl", text)
        self.assertIn("TIMEOUT", text)

        replay = {"success": True, "result": {
            "total": 1, "identical": 0, "changed": 1, "failed": 0,
            "program_changed": True,
            "steps": [{"step": 1, "endpoint": "program", "status": "changed"}]}}
        text = bridge.format_runbook_replay(replay)
        self.assertIn("[DIFF]", text)
        self.assertIn("fingerprint changed", text)

        diff = {"success": True, "result": {
            "summary": {"functions_added": 1, "functions_removed": 0,
                        "functions_renamed": 1, "imports_added": 0,
                        "imports_removed": 0, "strings_added": 0,
                        "strings_removed": 0},
            "functions": {"added": [{"address": "0x2", "name": "new"}],
                          "removed": [],
                          "renamed": [{"address": "0x1", "from": "a", "to": "b"}],
                          "count_a": 1, "count_b": 2, "complete": True},
            "imports": {"added": [], "removed": []},
            "strings": {"added": [], "removed": []},
            "program_changed": False}}
        text = bridge.format_analysis_diff(diff)
        self.assertIn("+ 0x2 new", text)
        self.assertIn("a -> b", text)

    def test_an_error_answer_renders_as_the_error(self):
        failure = {"success": False,
                   "error": {"code": "RUNBOOK_BAD_FILE", "message": "missing"}}
        self.assertIn("RUNBOOK_BAD_FILE", bridge.format_runbook_replay(failure))


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.steps = os.path.join(self.tmp.name, "steps.json")
        with open(self.steps, "w", encoding="utf-8") as handle:
            json.dump([{"endpoint": "program"}], handle)
        self.path = os.path.join(self.tmp.name, "rb.ghydrarb.jsonl")

    def _invoke(self, args, client=None):
        from click.testing import CliRunner
        return CliRunner().invoke(runbook, args, obj={
            'client': client or FakeClient(),
            'formatter': mock.Mock(),
            'output_json': False,
        })

    def test_record_writes_the_file_and_exits_zero(self):
        result = self._invoke(["record", "-s", self.steps, "-o", self.path])
        self.assertEqual(0, result.exit_code, result.output)
        self.assertTrue(os.path.exists(self.path))
        self.assertIn("Runbook written", result.output)

    def test_replay_is_identical_against_the_same_binary(self):
        self._invoke(["record", "-s", self.steps, "-o", self.path])
        result = self._invoke(["replay", self.path])
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn("1 identical", result.output)

    def test_fail_on_change_exits_one_when_an_answer_moved(self):
        self._invoke(["record", "-s", self.steps, "-o", self.path])
        moved = FakeClient(program={"name": "different.exe"})
        result = self._invoke(["replay", self.path, "--fail-on-change"], moved)
        self.assertEqual(1, result.exit_code, result.output)

    def test_show_lists_the_steps_without_calling_anything(self):
        self._invoke(["record", "-s", self.steps, "-o", self.path])
        never = mock.Mock()
        never.get.side_effect = AssertionError("show must not call the API")
        result = self._invoke(["show", self.path], never)
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn("program", result.output)

    def test_a_missing_runbook_exits_two(self):
        result = self._invoke(["replay", os.path.join(self.tmp.name, "nope.jsonl")])
        self.assertEqual(2, result.exit_code)


class RunbookWireFormatTests(unittest.TestCase):
    """The step goes out as it was recorded: JSON body, query parameters kept.

    `GhidraHTTPClient.post(data=...)` form-encodes a dictionary, so the recorded
    `POST /functions` went out as `address=00401000&name=test` while
    `FunctionResource.create()` parses a JSON `CreateRequest`. The same call
    dropped `step['params']`, so a POST BSim step lost its address and its
    dry-run arguments.

    These tests look at the **prepared request**, not at a fake client's return
    value: the defect was in how the request was built.
    """

    def _client(self):
        from ghydra.client.http_client import GhidraHTTPClient
        client = GhidraHTTPClient("localhost", 8192)
        return client

    def test_a_post_body_is_json_and_not_form_data(self):
        from unittest import mock

        client = self._client()
        with mock.patch.object(client.session, "post",
                               return_value=mock.Mock(
                                   status_code=200,
                                   json=lambda: {"success": True},
                                   text="")) as sender:
            rb._call(client, {"method": "POST", "endpoint": "functions",
                               "payload": {"address": "00401000",
                                           "name": "test"}})
        _, kwargs = sender.call_args
        self.assertEqual({"address": "00401000", "name": "test"},
                         kwargs.get("json"))
        self.assertIsNone(kwargs.get("data"),
                          "the body must not be form-encoded as well")

    def test_a_post_keeps_the_query_parameters(self):
        from unittest import mock

        client = self._client()
        with mock.patch.object(client.session, "post",
                               return_value=mock.Mock(
                                   status_code=200,
                                   json=lambda: {"success": True},
                                   text="")) as sender:
            rb._call(client, {"method": "POST",
                               "endpoint": "bsim/query",
                               "params": {"address": "0x401000",
                                          "dryRun": "true"},
                               "payload": {}})
        _, kwargs = sender.call_args
        self.assertEqual({"address": "0x401000", "dryRun": "true"},
                         kwargs.get("params"))

    def test_a_patch_keeps_the_query_parameters(self):
        from unittest import mock

        client = self._client()
        with mock.patch.object(client.session, "patch",
                               return_value=mock.Mock(
                                   status_code=200,
                                   json=lambda: {"success": True},
                                   text="")) as sender:
            rb._call(client, {"method": "PATCH", "endpoint": "functions/0x1",
                               "params": {"dryRun": "true"},
                               "payload": {"name": "x"}})
        _, kwargs = sender.call_args
        self.assertEqual({"dryRun": "true"}, kwargs.get("params"))

    def test_a_delete_keeps_the_query_parameters(self):
        from unittest import mock

        client = self._client()
        with mock.patch.object(client.session, "delete",
                               return_value=mock.Mock(
                                   status_code=200,
                                   json=lambda: {"success": True},
                                   text="")) as sender:
            rb._call(client, {"method": "DELETE", "endpoint": "functions/0x1",
                               "params": {"force": "true"}})
        _, kwargs = sender.call_args
        self.assertEqual({"force": "true"}, kwargs.get("params"))

    def test_the_bridge_sends_the_same_way(self):
        """The bridge had it right for the body and wrong for the parameters."""
        from unittest import mock

        with mock.patch.object(bridge, "_make_request",
                               return_value={"success": True}) as sender:
            bridge._runbook_call(8192, {
                "method": "POST", "endpoint": "functions",
                "params": {"dryRun": "true"},
                "payload": {"address": "00401000", "name": "test"}})
        _, kwargs = sender.call_args
        self.assertEqual({"dryRun": "true"}, kwargs.get("params"))
        self.assertEqual({"address": "00401000", "name": "test"},
                         kwargs.get("json_data"))


class DiffCompletenessTests(unittest.TestCase):
    """A listing that was not read to its end cannot support a removal.

    The collectors already record `imports_complete` and `strings_complete`, and
    the comparison threw those flags away: a failed listing on one side
    produced a definite "these imports were removed" — an absence claim against
    a list that was never read.
    """

    def test_an_incomplete_imports_listing_makes_no_removal_claim(self):
        a = {"program": {"name": "a.exe"}, "functions": [],
             "imports": ["recv"], "strings": [],
             "functions_complete": True, "imports_complete": True,
             "strings_complete": True}
        b = {"program": {"name": "a.exe"}, "functions": [],
             "imports": [], "strings": [],
             "functions_complete": True, "imports_complete": False,
             "strings_complete": True}
        report = diff_helper.diff_snapshots(a, b)
        self.assertEqual([], report["imports"]["removed"],
                         "a removal was claimed against a list that was not read")
        self.assertEqual(["recv"], report["imports"]["removed_not_seen"])
        self.assertFalse(report["imports"]["complete"])

    def test_an_incomplete_strings_listing_makes_no_removal_claim(self):
        a = {"program": {"name": "a.exe"}, "functions": [],
             "imports": [], "strings": ["password"],
             "functions_complete": True, "imports_complete": True,
             "strings_complete": True}
        b = {"program": {"name": "a.exe"}, "functions": [],
             "imports": [], "strings": [],
             "functions_complete": True, "imports_complete": True,
             "strings_complete": False}
        report = diff_helper.diff_snapshots(a, b)
        self.assertEqual([], report["strings"]["removed"])
        self.assertEqual(["password"], report["strings"]["removed_not_seen"])

    def test_the_overall_verdict_covers_every_section(self):
        a = {"program": {"name": "a.exe"}, "functions": [],
             "imports": [], "strings": [],
             "functions_complete": True, "imports_complete": True,
             "strings_complete": True}
        b = {"program": {"name": "a.exe"}, "functions": [],
             "imports": [], "strings": [],
             "functions_complete": True, "imports_complete": False,
             "strings_complete": True}
        report = diff_helper.diff_snapshots(a, b)
        self.assertFalse(report["complete"])
        self.assertEqual(["imports"], report["incomplete_sections"])

    def test_a_complete_pair_is_still_complete(self):
        a = {"program": {"name": "a.exe"}, "functions": [], "imports": ["x"],
             "strings": [], "functions_complete": True,
             "imports_complete": True, "strings_complete": True}
        report = diff_helper.diff_snapshots(a, a)
        self.assertTrue(report["complete"])
        self.assertEqual([], report["incomplete_sections"])


if __name__ == "__main__":
    unittest.main(verbosity=2)