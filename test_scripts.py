#!/usr/bin/env python3
"""Regression tests for ad-hoc Java/Python script execution (PyGhidra fix).

v3.0.0's merge removed /script/execute; the replacement always wrote a .java
file and demanded "extends GhidraScript", so ad-hoc Python 3 stopped working.
These tests need neither Ghidra nor PyGhidra: they check the language plumbing
on all three surfaces plus the pure argument parser. The live Python run is
covered by src/test/ghidra/TestPyGhidraScript.java under analyzeHeadless.

Run with:  python test_scripts.py
"""

import inspect
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bridge_mcp_hydra as bridge

ROOT = os.path.dirname(os.path.abspath(__file__))
JAVA = "src/main/java/eu/starsong/ghidra"


def _read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as handle:
        return handle.read()


class RestContractTests(unittest.TestCase):
    def test_service_selects_the_runtime_and_keeps_the_extension(self):
        service = _read(f"{JAVA}/service/ScriptService.java")
        self.assertIn("normalizeLanguage(String language, String filename)", service)
        self.assertIn("extensionFor(String language)", service)
        self.assertIn('"python"', service)
        self.assertIn('stem + extensionFor(lang)', service)
        self.assertIn("PyGhidra", service)
        self.assertIn("language=python", service)

    def test_resource_forwards_language_and_filename(self):
        resource = _read(f"{JAVA}/resource/ScriptResource.java")
        self.assertIn("public String language;", resource)
        self.assertIn("public String filename;", resource)
        self.assertIn("req.language, req.filename", resource)

    def test_live_python_regression_script_exists(self):
        path = os.path.join(ROOT, "src/test/ghidra/TestPyGhidraScript.java")
        self.assertTrue(os.path.isfile(path))
        text = _read("src/test/ghidra/TestPyGhidraScript.java")
        self.assertIn('"python", "probe.py"', text)
        self.assertIn('endsWith(".py")', text)
        self.assertIn("PYGHIDRA_OK", text)
        self.assertIn("SKIP", text)


class BridgeContractTests(unittest.TestCase):
    def test_scripts_run_exposes_language_and_filename(self):
        sig = inspect.signature(bridge.scripts_run.__wrapped__)
        for name in ("language", "filename", "args"):
            self.assertIn(name, sig.parameters)

    def test_args_is_text_not_a_nested_object(self):
        """Some MCP clients flatten nested lists; the schema must ask for text."""
        annotation = inspect.signature(bridge.scripts_run.__wrapped__).parameters["args"].annotation
        text = str(annotation)
        self.assertNotIn("list", text)
        self.assertIn("Annotated[str", text)
        self.assertIn("BeforeValidator", text)

    def test_both_script_tools_are_actually_wrapped_by_text_output(self):
        # Without @text_output the FORMATTERS entries are dead and the answer is
        # a raw dict instead of the formatted text/error envelope.
        for name in ("scripts_list", "scripts_run"):
            with self.subTest(tool=name):
                fn = getattr(bridge, name)
                self.assertTrue(hasattr(fn, "__wrapped__"),
                                f"{name} is missing @text_output")
                self.assertIn(name, bridge.FORMATTERS)

    def test_parse_script_args(self):
        parse = bridge._parse_script_args
        self.assertEqual([], parse(None))
        self.assertEqual([], parse(""))
        self.assertEqual(["a", "b"], parse('["a","b"]'))
        self.assertEqual(["a", "b"], parse("a, b"))
        self.assertEqual(["one"], parse("one"))
        self.assertEqual(["1"], parse("[1]"))


class CliContractTests(unittest.TestCase):
    def test_cli_offers_language_filename_and_inline_code(self):
        cli = _read("ghydra/cli/scripts.py")
        for needle in ("--language", "--filename", "--code", "os.path.basename",
                       "endswith('.py')", "payload['language']", "payload['filename']"):
            with self.subTest(needle=needle):
                self.assertIn(needle, cli)

    def test_skill_no_longer_teaches_removed_pyghidra_commands(self):
        skill = _read("skills/ghydra-cli/SKILL.md")
        self.assertNotIn("ghydra script execute", skill)
        self.assertNotIn("ghydra script capabilities", skill)
        self.assertIn("ghydra scripts run", skill)
        self.assertIn("--language python", skill)
        self.assertIn("pyghidraRun", skill)


if __name__ == "__main__":
    unittest.main(verbosity=2)
