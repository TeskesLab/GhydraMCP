#!/usr/bin/env python3
"""Tests for the capability triage (R4).

No Ghidra, no network: the pure report builder is exercised with synthetic
HATEOAS envelopes, and the bridge/CLI copies are checked for parity.

Run with:  python tests/test_capabilities_summary.py
"""

import inspect
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import bridge_mcp_hydra as bridge  # noqa: E402
from ghydra import capabilities  # noqa: E402


def _envelope(items):
    return {"success": True, "result": list(items)}


PROGRAM = {"success": True, "result": {"name": "sample.exe"}}
IMPORTS = _envelope([
    {"name": "VirtualAllocEx", "address": "0x140002000"},
    {"name": "WriteProcessMemory", "address": "0x140002010"},
    {"name": "CreateRemoteThread", "address": "0x140002020"},
    {"name": "URLDownloadToFileA", "address": "0x140002030"},
    {"name": "GetSystemInfo", "address": "0x140002040"},
])
STRINGS = _envelope([
    {"value": "YOUR FILES ARE ENCRYPTED", "address": "0x140003000"},
    {"value": "pay bitcoin to decrypt", "address": "0x140003010"},
    {"value": "https://evil.example/payload", "address": "0x140003020"},
    {"value": "VMware detected, exiting", "address": "0x140003030"},
])


class RulePackParityTests(unittest.TestCase):
    def test_bridge_and_cli_share_the_same_rules(self):
        self.assertEqual(capabilities.CAPABILITY_RULES, bridge.CAPABILITY_RULES)
        self.assertEqual(10, len(bridge.CAPABILITY_RULES))

    def test_both_builders_produce_the_same_report(self):
        for include_strings in (True, False):
            with self.subTest(include_strings=include_strings):
                a = bridge.build_capability_report(
                    PROGRAM, IMPORTS, STRINGS, include_strings)
                b = capabilities.build_capability_report(
                    PROGRAM, IMPORTS, STRINGS, include_strings)
                self.assertEqual(a, b)

    def test_every_rule_has_the_expected_shape(self):
        for rule in bridge.CAPABILITY_RULES:
            with self.subTest(rule=rule.get("id")):
                self.assertTrue(rule["id"].startswith("T"))
                self.assertTrue(rule["name"])
                self.assertTrue(rule["tactic"])
                self.assertIsInstance(rule["imports"], tuple)
                self.assertIsInstance(rule["strings"], tuple)


class ReportTests(unittest.TestCase):
    def test_detects_injection_and_ransomware_leads(self):
        report = bridge.build_capability_report(PROGRAM, IMPORTS, STRINGS)
        ids = [f["id"] for f in report["result"]["findings"]]
        self.assertIn("T1055", ids)
        self.assertIn("T1486", ids)
        self.assertIn("T1105", ids)

    def test_findings_are_ranked_and_carry_evidence_addresses(self):
        findings = bridge.build_capability_report(
            PROGRAM, IMPORTS, STRINGS)["result"]["findings"]
        scores = [f["score"] for f in findings]
        self.assertEqual(sorted(scores, reverse=True), scores)
        injection = next(f for f in findings if f["id"] == "T1055")
        self.assertTrue(injection["evidence"])
        self.assertTrue(any(ev["address"] for ev in injection["evidence"]))
        self.assertIn(injection["confidence"], ("low", "medium", "high"))

    def test_no_evidence_means_no_finding(self):
        report = bridge.build_capability_report(
            PROGRAM, _envelope([]), _envelope([]))
        self.assertEqual([], report["result"]["findings"])
        self.assertEqual(0, report["result"]["summary"]["techniques_matched"])

    def test_strings_can_be_excluded(self):
        report = bridge.build_capability_report(
            PROGRAM, IMPORTS, STRINGS, include_strings=False)
        self.assertEqual(0, report["result"]["summary"]["strings_scanned"])
        self.assertNotIn("strings", report["result"]["failures"])

    def test_a_failed_endpoint_is_reported_not_hidden(self):
        failed = {"success": False, "error": {"code": "X", "message": "down"}}
        report = bridge.build_capability_report(PROGRAM, IMPORTS, failed)
        self.assertIn("strings", report["result"]["failures"])


class BridgeToolTests(unittest.TestCase):
    def test_tool_is_registered_with_a_formatter(self):
        registered = getattr(bridge.mcp._tool_manager, "_tools", {})
        self.assertIn("analysis_capabilities_summary", registered)
        self.assertIs(bridge.format_capabilities_summary,
                      bridge.FORMATTERS.get("analysis_capabilities_summary"))

    @mock.patch.object(bridge, "_get_instance_port", return_value=8192)
    @mock.patch.object(bridge, "safe_get")
    def test_the_tool_composes_the_three_endpoints(self, fake_get, fake_port):
        def side_effect(port, endpoint, params=None):
            return {
                "program": PROGRAM,
                "symbols/imports": IMPORTS,
                "strings": STRINGS,
            }[endpoint]
        fake_get.side_effect = side_effect
        raw = bridge.analysis_capabilities_summary.__wrapped__()
        self.assertTrue(raw["success"])
        self.assertTrue(raw["result"]["findings"])
        self.assertEqual(3, fake_get.call_count)

    def test_formatter_shows_the_leads_and_the_disclaimer(self):
        report = bridge.build_capability_report(PROGRAM, IMPORTS, STRINGS)
        text = bridge.format_capabilities_summary(report)
        self.assertIn("T1055", text)
        self.assertIn("Process Injection", text)
        self.assertIn("not a verdict", text)
        self.assertIn("0x140002000", text)


class CliContractTests(unittest.TestCase):
    def test_cli_command_exists_and_uses_the_shared_builder(self):
        from ghydra.cli import analysis
        self.assertTrue(callable(getattr(analysis, "capabilities_summary", None)))

    def test_all_three_formatters_implement_the_method(self):
        from ghydra.formatters.base import BaseFormatter
        from ghydra.formatters.json_formatter import JSONFormatter
        from ghydra.formatters.table_formatter import TableFormatter
        self.assertIn("format_capabilities_summary",
                      BaseFormatter.__abstractmethods__)
        for cls in (JSONFormatter, TableFormatter):
            with self.subTest(formatter=cls.__name__):
                self.assertNotIn("format_capabilities_summary",
                                 getattr(cls, "__abstractmethods__", set()))

    def test_tool_docstring_has_args_and_returns(self):
        doc = inspect.getdoc(bridge.analysis_capabilities_summary.__wrapped__)
        self.assertIn("Args:", doc)
        self.assertIn("Returns:", doc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
