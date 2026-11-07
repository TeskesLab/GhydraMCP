#!/usr/bin/env python3
"""Tests for the context pack (R3) and the actionable links (I8).

No Ghidra, no network: the pack builder is exercised with synthetic sections
and mocked envelopes, and the link translation with fixture envelopes.

Run with:  python test_context_pack.py
"""

import inspect
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bridge_mcp_hydra as bridge  # noqa: E402
from ghydra import contextpack  # noqa: E402


LONG_CODE = "int f(void) { return 1; }\n" * 400  # ~3600 tokens

SECTIONS = [
    {"title": "function", "body": "sub_401000  entry  0x401000",
     "citations": ["0x401000"]},
    {"title": "decompilation", "body": LONG_CODE, "citations": ["0x401000"]},
    {"title": "callers", "body": "main calls it from 0x401200",
     "citations": ["0x401200"]},
    {"title": "callees", "body": "calls CreateFileW at 0x401400",
     "citations": ["0x401400"]},
]


class ParityTests(unittest.TestCase):
    def test_the_builders_agree(self):
        a = contextpack.build_context_pack(
            "o que faz?", "what_it_does", "x.exe", SECTIONS, 4000)
        b = bridge.build_context_pack(
            "o que faz?", "what_it_does", "x.exe", SECTIONS, 4000)
        self.assertEqual(a, b)

    def test_the_classifier_agrees(self):
        for question in ("o que faz esta função?", "where is this written?",
                         "o que mudou", "anything else"):
            with self.subTest(question=question):
                self.assertEqual(contextpack.classify_question(question),
                                 bridge._ctx_classify_question(question))


class ClassifierTests(unittest.TestCase):
    def test_the_three_templates_are_recognised(self):
        cases = {
            "what_it_does": ("o que faz esta função?",
                             "what does sub_401000 do?",
                             "descompila pra mim"),
            "data_origin": ("de onde vem este dado?",
                            "where is this data written?",
                            "quem escreve aqui? xrefs"),
            "what_changed": ("o que mudou desde ontem?",
                             "what changed in this binary?"),
        }
        for template, questions in cases.items():
            for question in questions:
                with self.subTest(question=question):
                    self.assertEqual(template,
                                     contextpack.classify_question(question))

    def test_an_unmatched_question_gets_the_overview(self):
        self.assertEqual("overview",
                         contextpack.classify_question("liste tudo"))


class BudgetTests(unittest.TestCase):
    def test_the_first_section_is_truncated_never_dropped(self):
        pack = contextpack.build_context_pack(
            "q", "what_it_does", "x", SECTIONS, budget_tokens=300)
        titles = [s["title"] for s in pack["result"]["sections"]]
        self.assertEqual("function", titles[0])
        self.assertTrue(pack["result"]["omitted"])

    def test_over_budget_sections_are_dropped_with_a_reason(self):
        pack = contextpack.build_context_pack(
            "q", "what_it_does", "x", SECTIONS, budget_tokens=500)
        dropped = {o["section"]: o["reason"] for o in pack["result"]["omitted"]}
        self.assertIn("budget", " ".join(dropped.values()))

    def test_citations_are_deduplicated(self):
        pack = contextpack.build_context_pack(
            "q", "what_it_does", "x", SECTIONS, budget_tokens=100000)
        self.assertEqual(["0x401000", "0x401200", "0x401400"],
                         pack["result"]["citations"])

    def test_the_pack_stays_under_the_budget(self):
        pack = contextpack.build_context_pack(
            "q", "what_it_does", "x", SECTIONS, budget_tokens=600)
        self.assertLessEqual(pack["result"]["used_tokens"], 600)

    def test_a_small_budget_is_clamped_not_negative(self):
        pack = contextpack.build_context_pack(
            "q", "what_it_does", "x", SECTIONS, budget_tokens=1)
        self.assertEqual(200, pack["result"]["budget_tokens"])


class BridgeToolTests(unittest.TestCase):
    def test_tool_and_formatter_are_registered(self):
        registered = getattr(bridge.mcp._tool_manager, "_tools", {})
        self.assertIn("analysis_context_pack", registered)
        self.assertIs(bridge.format_context_pack,
                      bridge.FORMATTERS.get("analysis_context_pack"))

    def test_template_questions_need_an_address(self):
        raw = bridge.analysis_context_pack.__wrapped__(
            question="o que faz esta função?")
        self.assertFalse(raw["success"])
        self.assertEqual("MISSING_PARAMETER", raw["error"]["code"])

    @mock.patch.object(bridge, "_get_instance_port", return_value=8192)
    @mock.patch.object(bridge, "safe_get")
    def test_what_it_does_composes_the_right_endpoints(self, fake_get, fake_port):
        def side_effect(port, endpoint, params=None):
            if endpoint == "program":
                return {"success": True, "result": {"name": "x.exe"}}
            if endpoint.endswith("/decompile"):
                return {"success": True, "result": {"ccode": "int f(){}"}}
            if endpoint.startswith("functions/"):
                return {"success": True, "result": {"name": "sub_401000"}}
            return {"success": True, "result": []}
        fake_get.side_effect = side_effect
        raw = bridge.analysis_context_pack.__wrapped__(
            question="o que faz esta função?", address="0x401000",
            budget_tokens=2000)
        self.assertTrue(raw["success"])
        self.assertEqual("what_it_does", raw["result"]["template"])
        titles = [s["title"] for s in raw["result"]["sections"]]
        self.assertEqual(["function", "decompilation", "callers", "callees"],
                         titles)
        self.assertIn("0x401000", raw["result"]["citations"])
        called = [c.args[1] for c in fake_get.call_args_list]
        self.assertIn("functions/0x401000", called)
        self.assertIn("analysis/callers/0x401000", called)

    @mock.patch.object(bridge, "_get_instance_port", return_value=8192)
    @mock.patch.object(bridge, "safe_get")
    def test_a_failed_section_is_reported_not_hidden(self, fake_get, fake_port):
        def side_effect(port, endpoint, params=None):
            if endpoint == "program":
                return {"success": True, "result": {"name": "x.exe"}}
            if endpoint.startswith("functions/"):
                return {"success": True, "result": {"name": "sub"}}
            return {"success": False,
                    "error": {"code": "TIMEOUT", "message": "slow"}}
        fake_get.side_effect = side_effect
        raw = bridge.analysis_context_pack.__wrapped__(
            question="what does it do?", address="0x401000")
        bodies = [s["body"] for s in raw["result"]["sections"]]
        self.assertTrue(any("TIMEOUT" in b for b in bodies))

    def test_the_formatter_shows_citations_and_omissions(self):
        pack = contextpack.build_context_pack(
            "o que faz?", "what_it_does", "x.exe", SECTIONS, 400)
        text = bridge.format_context_pack(pack)
        self.assertIn("## function", text)
        self.assertIn("Citations:", text)
        self.assertIn("Omitted:", text)


class ActionableLinksTests(unittest.TestCase):
    """I8: the envelope's links become calls the agent can make."""

    def test_a_link_becomes_a_registered_call(self):
        envelope = {"success": True, "result": {},
                    "_links": {
                        "self": {"href": "/functions/00401000"},
                        "cfg": {"href": "/functions/00401000/cfg"},
                        "decompile": {"href": "/functions/00401000/decompile"},
                    }}
        suggestions = bridge._suggested_calls(envelope)
        self.assertIn("functions_get_cfg(address=\"00401000\")", suggestions)
        self.assertIn("functions_decompile(address=\"00401000\")", suggestions)
        # self is the call that just happened — never suggested
        self.assertTrue(all("self" not in s for s in suggestions))

    def test_a_pagination_link_becomes_the_next_page(self):
        envelope = {"success": True, "result": [],
                    "_links": {"next": {
                        "href": "/functions?offset=100&limit=100"}}}
        suggestions = bridge._suggested_calls(envelope)
        self.assertEqual(["functions_list(offset=100, limit=100)"],
                         suggestions)

    def test_an_unmappable_link_is_not_guessed(self):
        envelope = {"success": True, "result": [],
                    "_links": {"weird": {"href": "/nope/1/mystery"}}}
        self.assertEqual([], bridge._suggested_calls(envelope))

    def test_text_output_appends_the_next_block(self):
        with mock.patch.dict(bridge.FORMATTERS,
                             {"_probe_i8": lambda r, **k: "FN"}):
            @bridge.mcp.tool()
            @bridge.text_output
            def _probe_i8(port=None):
                return {"success": True, "result": {"name": "f"},
                        "_links": {"decompile":
                                   {"href": "/functions/00401000/decompile"}}}
            try:
                text = _probe_i8()
                self.assertIn("FN", text)
                self.assertIn("Next: functions_decompile(address=\"00401000\")",
                              text)
            finally:
                bridge.mcp._tool_manager._tools.pop("_probe_i8", None)
                bridge.FORMATTERS.pop("_probe_i8", None)


class CliContractTests(unittest.TestCase):
    def test_the_cli_command_exists(self):
        from ghydra.cli import analysis
        self.assertTrue(callable(getattr(analysis, "context_pack", None)))

    def test_all_formatters_implement_the_pack(self):
        from ghydra.formatters.base import BaseFormatter
        from ghydra.formatters.json_formatter import JSONFormatter
        from ghydra.formatters.table_formatter import TableFormatter
        self.assertIn("format_context_pack", BaseFormatter.__abstractmethods__)
        for cls in (JSONFormatter, TableFormatter):
            with self.subTest(formatter=cls.__name__):
                self.assertNotIn("format_context_pack",
                                 getattr(cls, "__abstractmethods__", set()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
