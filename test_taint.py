#!/usr/bin/env python3
"""Tests for the source-to-sink hypothesis engine (R5).

No Ghidra and no network: a fake client answers the four endpoints the engine
composes (a function by name, the xrefs to a name, a function's pcode and the
call path). The bridge duplicates the logic by necessity, so the parity of the
report is asserted here as well.

Run with:  python test_taint.py
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bridge_mcp_hydra as bridge  # noqa: E402
from ghydra import taint  # noqa: E402
from ghydra.cli.analysis import taint_cmd  # noqa: E402


def call(at, target):
    """A CALL pcode operation aimed at a target."""
    return {"address": at, "opcode": 57, "output": "",
            "inputs": [target, "1"]}


def other(at):
    """A non-call operation, which the engine must ignore."""
    return {"address": at, "opcode": 19, "output": "uVar1", "inputs": ["0x1"]}


class FakeClient:
    """The four endpoints the engine reads, answered from dictionaries."""

    def __init__(self, names=None, pcode=None, paths=None, containing=None):
        # names: {name: {address, refs: [{from_address, function}]}}
        self.names = names or {}
        self.pcode = pcode or {}
        self.paths = paths or {}
        self.containing = containing or {}

    def get(self, endpoint, params=None):
        params = params or {}
        if endpoint.startswith("functions/by-name/"):
            name = endpoint.rsplit("/", 1)[-1]
            entry = self.names.get(name)
            if not entry:
                return {"success": False, "error": {"code": "FUNCTION_NOT_FOUND"}}
            return {"success": True, "result": {"name": name,
                                                "address": entry["address"]}}
        if endpoint.startswith("xrefs/to-name/"):
            name = endpoint.rsplit("/", 1)[-1]
            entry = self.names.get(name) or {}
            return {"success": True, "result": entry.get("refs") or []}
        if endpoint.endswith("/pcode"):
            address = endpoint.split("/")[1]
            return {"success": True,
                    "result": {"operations": self.pcode.get(address, [])}}
        if endpoint.startswith("functions/containing/"):
            address = endpoint.rsplit("/", 1)[-1]
            found = self.containing.get(address)
            if not found:
                return {"success": False, "error": {"code": "FUNCTION_NOT_FOUND"}}
            return {"success": True, "result": {"address": found}}
        if endpoint == "analysis/call-path":
            key = (str(params.get("from")), str(params.get("to")))
            return {"success": True, "result": self.paths.get(
                key, {"path": None, "reason": "no path"})}
        return {"success": False, "error": {"code": "UNEXPECTED"}}


def direct_client():
    """The source and the sink are called in the same function, in order."""
    return FakeClient(
        names={"recv": {"address": "0x5000",
                        "refs": [{"from_address": "0x401010",
                                  "function": "0x401000"}]},
               "system": {"address": "0x6000",
                          "refs": [{"from_address": "0x401020",
                                    "function": "0x401000"}]}},
        pcode={"0x401000": [other("0x401008"), call("0x401010", "recv"),
                            call("0x401020", "system")]})


class ResolveTests(unittest.TestCase):
    def test_a_name_resolves_to_its_address_and_its_sites(self):
        info = taint.resolve_name(direct_client(), "recv")
        self.assertEqual(["0x5000"], info["addresses"])
        self.assertEqual(1, len(info["references"]))
        self.assertEqual("0x401010", info["references"][0]["from_address"])

    def test_an_unknown_name_resolves_to_nothing(self):
        info = taint.resolve_name(direct_client(), "nope")
        self.assertEqual([], info["addresses"])

    def test_only_call_opcodes_are_returned(self):
        calls = taint.calls_in_function(direct_client(), "0x401000")
        self.assertEqual(2, len(calls))
        self.assertEqual(["0x401010", "0x401020"], [c["at"] for c in calls])
        self.assertEqual("recv", calls[0]["target"])

    def test_a_function_without_pcode_yields_nothing(self):
        self.assertEqual([], taint.calls_in_function(direct_client(), "0x999"))


class HypothesisTests(unittest.TestCase):
    def _report(self, client):
        return taint.find_hypotheses(client, "recv", "system")

    def test_a_sink_after_the_source_in_one_function_is_direct(self):
        report = self._report(direct_client())
        self.assertEqual(1, len(report["hypotheses"]))
        hypothesis = report["hypotheses"][0]
        self.assertEqual("direct", hypothesis["confidence"])
        self.assertEqual("0x401010", hypothesis["source_call"])
        self.assertEqual("0x401020", hypothesis["sink_call"])

    def test_a_sink_before_the_source_is_not_a_flow(self):
        client = FakeClient(
            names={"recv": {"address": "0x5000",
                            "refs": [{"from_address": "0x401020",
                                      "function": "0x401000"}]},
                   "system": {"address": "0x6000",
                              "refs": [{"from_address": "0x401010",
                                        "function": "0x401000"}]}},
            pcode={"0x401000": [call("0x401010", "system"),
                                call("0x401020", "recv")]})
        report = self._report(client)
        self.assertEqual("weak", report["hypotheses"][0]["confidence"])
        self.assertFalse(taint.summarize(report)["found"])

    def test_two_functions_connected_by_a_call_path_are_reachable(self):
        client = FakeClient(
            names={"recv": {"address": "0x5000",
                            "refs": [{"from_address": "0x401010",
                                      "function": "0x401000"}]},
                   "system": {"address": "0x6000",
                              "refs": [{"from_address": "0x402010",
                                        "function": "0x402000"}]}},
            paths={("0x401000", "0x402000"): {"path": ["0x401000", "0x402000"]}})
        report = self._report(client)
        self.assertEqual(1, len(report["hypotheses"]))
        self.assertEqual("reachable", report["hypotheses"][0]["confidence"])
        self.assertTrue(taint.summarize(report)["found"])

    def test_a_truncated_search_is_reported_as_weak_not_as_a_path(self):
        client = FakeClient(
            names={"recv": {"address": "0x5000",
                            "refs": [{"from_address": "0x401010",
                                      "function": "0x401000"}]},
                   "system": {"address": "0x6000",
                              "refs": [{"from_address": "0x402010",
                                        "function": "0x402000"}]}},
            paths={("0x401000", "0x402000"): {"path": ["0x401000"],
                                              "truncated": True}})
        report = self._report(client)
        self.assertEqual("weak", report["hypotheses"][0]["confidence"])
        self.assertIn("cap", report["hypotheses"][0]["reason"])

    def test_no_path_is_reported_without_claiming_safety(self):
        client = FakeClient(
            names={"recv": {"address": "0x5000",
                            "refs": [{"from_address": "0x401010",
                                      "function": "0x401000"}]},
                   "system": {"address": "0x6000",
                              "refs": [{"from_address": "0x402010",
                                        "function": "0x402000"}]}})
        report = self._report(client)
        self.assertEqual([], report["hypotheses"])
        text = taint.to_text(report)
        self.assertIn("not proof of safety", text)

    def test_the_report_always_carries_the_disclaimer(self):
        report = self._report(direct_client())
        self.assertEqual(taint.DISCLAIMER, report["disclaimer"])
        self.assertIn("not proof of exploitability", taint.to_text(report))

    def test_the_summary_counts_each_confidence(self):
        report = {"hypotheses": [{"confidence": "direct"},
                                 {"confidence": "reachable"},
                                 {"confidence": "weak"}]}
        counts = taint.summarize(report)
        self.assertEqual((3, 1, 1, 1), (counts["total"], counts["direct"],
                                       counts["reachable"], counts["weak"]))
        self.assertTrue(counts["found"])

    def test_a_function_found_through_containing_is_used(self):
        client = FakeClient(
            names={"recv": {"address": "0x5000",
                            "refs": [{"from_address": "0x401010"}]},
                   "system": {"address": "0x6000",
                              "refs": [{"from_address": "0x401020"}]}},
            containing={"0x401010": "0x401000", "0x401020": "0x401000"},
            pcode={"0x401000": [call("0x401010", "recv"),
                                call("0x401020", "system")]})
        report = self._report(client)
        self.assertEqual("direct", report["hypotheses"][0]["confidence"])


class ParityTests(unittest.TestCase):
    """The bridge duplicates the engine; both must produce the same report."""

    def _both(self, client, source="recv", sink="system"):
        with mock.patch.object(
                bridge, "safe_get",
                side_effect=lambda port, endpoint, params=None: client.get(
                    endpoint, params)):
            from_bridge = bridge._taint_find_hypotheses(8192, source, sink)
        from_cli = taint.find_hypotheses(client, source, sink)
        return from_cli, from_bridge

    def test_the_direct_report_agrees(self):
        cli, br = self._both(direct_client())
        self.assertEqual(cli, br)

    def test_the_reachable_report_agrees(self):
        client = FakeClient(
            names={"recv": {"address": "0x5000",
                            "refs": [{"from_address": "0x401010",
                                      "function": "0x401000"}]},
                   "system": {"address": "0x6000",
                              "refs": [{"from_address": "0x402010",
                                        "function": "0x402000"}]}},
            paths={("0x401000", "0x402000"): {"path": ["0x401000", "0x402000"]}})
        cli, br = self._both(client)
        self.assertEqual(cli, br)

    def test_the_empty_report_agrees(self):
        cli, br = self._both(FakeClient())
        self.assertEqual(cli, br)

    def test_the_summary_agrees(self):
        report = taint.find_hypotheses(direct_client(), "recv", "system")
        self.assertEqual(taint.summarize(report), bridge._taint_summarize(report))


class BridgeToolTests(unittest.TestCase):
    def test_the_tool_is_registered_with_a_formatter(self):
        tools = set(getattr(bridge.mcp._tool_manager, "_tools", {}))
        self.assertIn("analysis_taint", tools)
        self.assertIn("analysis_taint", bridge.FORMATTERS)

    def test_the_tool_answers_through_the_api(self):
        client = direct_client()
        with mock.patch.object(bridge, "_get_instance_port",
                               side_effect=lambda port=None: 8192), \
                mock.patch.object(bridge, "safe_get",
                                  side_effect=lambda port, endpoint, params=None:
                                  client.get(endpoint, params)):
            result = bridge.analysis_taint.__wrapped__("recv", "system")
        self.assertTrue(result["success"], result)
        self.assertEqual("direct", result["result"]["hypotheses"][0]["confidence"])

    def test_the_formatter_renders_confidence_and_evidence(self):
        report = {"success": True, "result": taint.find_hypotheses(
            direct_client(), "recv", "system")}
        text = bridge.format_analysis_taint(report)
        self.assertIn("recv -> system", text)
        self.assertIn("[direct]", text)
        self.assertIn("0x401010", text)
        self.assertIn("not proof of exploitability", text)

    def test_the_formatter_says_when_nothing_was_found(self):
        report = {"success": True, "result": taint.find_hypotheses(
            FakeClient(), "recv", "system")}
        text = bridge.format_analysis_taint(report)
        self.assertIn("no source-to-sink path was found", text)

    def test_an_error_answer_renders_as_the_error(self):
        failure = {"success": False,
                   "error": {"code": "TAINT_READ_FAILED", "message": "down"}}
        self.assertIn("TAINT_READ_FAILED", bridge.format_analysis_taint(failure))


class CliTests(unittest.TestCase):
    def _invoke(self, args, client=None):
        from click.testing import CliRunner
        return CliRunner().invoke(taint_cmd, args, obj={
            'client': client or direct_client(),
            'formatter': mock.Mock(),
            'config': mock.Mock(page_output=False),
            'output_json': False,
        })

    def test_a_direct_hypothesis_is_reported(self):
        result = self._invoke(["--source", "recv", "--sink", "system"])
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn("[direct]", result.output)

    def test_nothing_found_still_exits_zero(self):
        result = self._invoke(["-s", "recv", "-t", "system"], FakeClient())
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn("not proof of safety", result.output)

    def test_the_depth_option_reaches_the_search(self):
        result = self._invoke(["-s", "recv", "-t", "system", "--max-depth", "3"])
        self.assertEqual(0, result.exit_code, result.output)


if __name__ == "__main__":
    unittest.main(verbosity=2)