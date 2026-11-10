"""`ghydra target` at the level the user runs it: the real Click commands.

The helpers behind these commands were tested, but the commands themselves were
not: nothing drove `describe`, `locate` or `decompile` through Click. That is
how a `NameError` in an `except` clause survived — the failure handler named a
class it did not import, and no test ever reached it, because the tests called
the helper and the helper raises its own errors.

These tests drive the root command the way the shell does, and they check two
things a helper-level test cannot:

* the answer reaches the user as JSON on stdout, and
* a failure is **reported** — with its code, and a non-zero exit — instead of
  being raised out of the command.
"""

import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ghydra.client.exceptions import GhidraAPIError  # noqa: E402
from ghydra.cli.main import cli  # noqa: E402

IMAGE_BASE = 0x140000000
MODULE_BASE = 0x7FF7A1230000

#: The shape `ProgramResource.getCurrentProgram()` emits.
PROGRAM = {"path": r"C:\bin\sample.exe", "name": "sample.exe",
           "imageBase": f"{IMAGE_BASE:x}", "language": "x86:LE:64:default"}

#: The shape `FunctionDto` emits: the address is unprefixed hexadecimal.
FUNCTION = {"name": "main", "address": "140001234",
            "signature": "int main(void)"}


class FakeDebugger:
    """The dynamic side, recording every call."""

    def __init__(self, path=r"C:\bin\sample.exe"):
        self.path = path
        self.calls = []

    def call_tool(self, name, arguments=None):
        self.calls.append((name, arguments))
        if name == "ListModules":
            return f"0x{MODULE_BASE:x} | 0x25000 | {self.path}"
        if name == "GetAllRegisters":
            return "RAX=0x1"
        return "[state] ok"


class TargetCommandTests(unittest.TestCase):
    """The five commands, through the root command."""

    def _answer(self, endpoint, params=None):
        """The Ghidra side, in the producer's shape."""
        route = str(endpoint).lstrip("/")
        if route == "program":
            return {"success": True, "result": PROGRAM}
        if route.endswith("/decompile"):
            return {"success": True,
                    "result": {"functionName": "main",
                               "functionAddress": "140001234",
                               "decompilation": "int main(void) { return 0; }"}}
        return {"success": True, "result": FUNCTION}

    def _invoke(self, arguments, debugger=None, answer=None):
        """Run a command with both sides faked, and return (result, debugger)."""
        from click.testing import CliRunner

        debugger = debugger if debugger is not None else FakeDebugger()
        answer = answer or self._answer
        with mock.patch("ghydra.cli.target_cmd._debugger",
                        return_value=debugger):
            with mock.patch("ghydra.client.http_client.GhidraHTTPClient.get",
                            side_effect=answer):
                result = CliRunner().invoke(cli, arguments)
        return result, debugger

    def _document(self, result):
        """The JSON the command printed, and the raw output for a failure."""
        return json.JSONDecoder().raw_decode(result.output)[0]

    # ----------------------------------------------------------------- describe
    def test_describe_answers_with_the_descriptor(self):
        result, _ = self._invoke(["target", "describe"])
        self.assertEqual(0, result.exit_code, result.output)
        document = self._document(result)
        self.assertEqual("sample.exe", document["binary_name"])
        self.assertTrue(document["correlatable"])
        self.assertEqual("path", document["identity"]["match"])

    def test_describe_says_when_the_two_sides_are_not_the_same_file(self):
        """The same file name in another directory is a copy, not the file."""
        result, _ = self._invoke(
            ["target", "describe"],
            debugger=FakeDebugger(path=r"D:\builds\sample.exe"))
        self.assertEqual(0, result.exit_code, result.output)
        document = self._document(result)
        self.assertFalse(document["correlatable"])
        self.assertEqual("name-only", document["identity"]["match"])

    def test_describe_refuses_when_the_debugger_has_no_such_binary(self):
        """A different file entirely: there is no module to correlate."""
        result, _ = self._invoke(["target", "describe"],
                                 debugger=FakeDebugger(path=r"D:\other.exe"))
        self.assertEqual(1, result.exit_code, result.output)
        self.assertIn("TARGET_NOT_LOADED", result.output)

    # ------------------------------------------------------------------- locate
    def test_locate_answers_with_the_static_address(self):
        result, _ = self._invoke(["target", "locate", "main"])
        self.assertEqual(0, result.exit_code, result.output)
        document = self._document(result)
        self.assertEqual("0x140001234", document["static_address"])
        self.assertEqual("name", document["matched_by"])

    # --------------------------------------------------------------- breakpoint
    def test_breakpoint_sets_the_translated_address(self):
        result, debugger = self._invoke(["target", "breakpoint", "main"])
        self.assertEqual(0, result.exit_code, result.output)
        document = self._document(result)
        self.assertEqual("0x140001234", document["static_address"])
        self.assertIn("SetBreakpoint", [name for name, _ in debugger.calls])
        self.assertEqual(hex(0x140001234 - IMAGE_BASE + MODULE_BASE),
                         document["runtime_address"])

    def test_breakpoint_of_another_build_refuses_and_touches_nothing(self):
        """The refusal is the property the whole address model exists for."""
        result, debugger = self._invoke(
            ["target", "breakpoint", "main"],
            debugger=FakeDebugger(path=r"D:\builds\sample.exe"))
        self.assertEqual(1, result.exit_code, result.output)
        self.assertIn("TARGET_NOT_SAME_BINARY", result.output)
        self.assertNotIn("SetBreakpoint", [name for name, _ in debugger.calls])

    # ------------------------------------------------------------------- run-to
    def test_run_to_resumes_and_reports_the_registers(self):
        result, debugger = self._invoke(["target", "run-to", "main"])
        self.assertEqual(0, result.exit_code, result.output)
        document = self._document(result)
        self.assertIn("RunToAddress", [name for name, _ in debugger.calls])
        self.assertIn("GetAllRegisters", [name for name, _ in debugger.calls])
        self.assertIsNotNone(document["registers"])

    # ---------------------------------------------------------------- decompile
    def test_decompile_answers_with_the_code(self):
        result, _ = self._invoke(["target", "decompile", "main"])
        self.assertEqual(0, result.exit_code, result.output)
        document = self._document(result)
        self.assertIn("int main(void)", document["code"])
        self.assertEqual("0x140001234", document["static_address"])

    # -------------------------------------------------------------- the failures
    def test_an_unknown_function_is_reported_with_its_code(self):
        def answer(endpoint, params=None):
            route = str(endpoint).lstrip("/")
            if route == "program":
                return {"success": True, "result": PROGRAM}
            return {"success": False,
                    "error": {"code": "FUNCTION_NOT_FOUND", "message": "no"}}

        result, _ = self._invoke(["target", "locate", "nope"], answer=answer)
        self.assertEqual(1, result.exit_code, result.output)
        self.assertIn("TARGET_NOT_FOUND", result.output)

    def test_a_ghidra_failure_is_reported_and_not_raised(self):
        """The failure handler names a class it imports — that has to hold.

        The handler used to name `GhidraError` without importing it, and no
        test reached the handler, so the mistake survived.
        """
        from ghydra.client.exceptions import GhidraConnectionError

        def answer(endpoint, params=None):
            raise GhidraConnectionError("no Ghidra here")

        result, _ = self._invoke(["target", "describe"], answer=answer)
        self.assertEqual(1, result.exit_code, result.output)
        self.assertIn("no Ghidra here", result.output)
        self.assertNotIsInstance(result.exception, GhidraConnectionError)

    def test_an_api_error_carries_its_code(self):
        def answer(endpoint, params=None):
            raise GhidraAPIError("the server said no", code="SERVER_BUSY")

        result, _ = self._invoke(["target", "describe"], answer=answer)
        self.assertEqual(1, result.exit_code, result.output)
        self.assertIn("SERVER_BUSY", result.output)

    def test_a_debugger_without_a_token_is_reported_with_its_code(self):
        """The debugger has its own error, and it reaches the user as a code."""
        from ghydra.cli import target_cmd
        from ghydra.x64dbg import X64dbgError

        def refuse(ctx):
            raise X64dbgError("no bearer token for the x64dbg MCP server",
                              code="X64DBG_DISABLED")

        with mock.patch.object(target_cmd, "_debugger", side_effect=refuse):
            from click.testing import CliRunner
            result = CliRunner().invoke(cli, ["target", "describe"])
        self.assertEqual(1, result.exit_code, result.output)
        self.assertIn("X64DBG_DISABLED", result.output)


if __name__ == "__main__":
    unittest.main()
