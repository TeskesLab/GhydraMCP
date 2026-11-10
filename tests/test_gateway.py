"""The `--gateway` suite: the five-step chain as MCP tools.

What is proven:

* the server registers the five tools, and their names follow the contract's
  vocabulary (`namespace_verb`, snake_case) — the plan's workflow names are mapped,
  not used as tool names;
* every tool answers with a **structured** result: `success`, plus `code` and
  `reason` on a failure — an MCP tool that raises turns a contract code into
  unstructured noise;
* the refusals hold through the gateway exactly as they do in the CLI: a breakpoint
  or a run over two different files is refused with `TARGET_NOT_SAME_BINARY`, and
  the fake debugger is not touched;
* the client factory is what the tools use, so a client that cannot be built (no
  debugger token) is reported as a code, not as a crash.

No Ghidra, no debugger, no network: the factory hands the tools fakes.
"""

import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ghydra import gateway  # noqa: E402
from ghydra import target as target_helper  # noqa: E402

IMAGE_BASE = 0x140000000
MODULE_BASE = 0x7FF7A1230000
NAME_PATTERN = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)+$")


class FakeGhidra:
    def __init__(self, path=r"C:\bin\sample.exe"):
        self.program = {"path": path, "image_base": hex(IMAGE_BASE),
                        "language": "x86:LE:64:default"}
        self.calls = []

    def get(self, endpoint, params=None):
        self.calls.append(endpoint)
        if endpoint == "program":
            return {"success": True, "result": self.program}
        if endpoint.endswith("/decompile"):
            return {"success": True,
                    "result": {"functionName": "main",
                               "functionAddress": "0x140001234",
                               "decompilation": "int main(void) { return 0; }"}}
        if endpoint.startswith("functions/by-name/"):
            if endpoint.rsplit("/", 1)[-1] == "main":
                return {"success": True,
                        "result": {"name": "main", "address": "0x140001234",
                                   "signature": "int main(void)"}}
            return {"success": False, "result": None}
        return {"success": True,
                "result": {"name": "main", "address": "0x140001234",
                           "signature": "int main(void)"}}


class FakeDebugger:
    def __init__(self, path=r"C:\bin\sample.exe"):
        self.path = path
        self.calls = []

    def call_tool(self, name, arguments=None):
        self.calls.append((name, arguments))
        if name == "ListModules":
            return f"0x{MODULE_BASE:x} | 0x25000 | {self.path}"
        if name == "GetAllRegisters":
            return "RAX=0x1"
        return "ok"


def factory(path=r"C:\bin\sample.exe"):
    return FakeGhidra(path), (lambda: FakeDebugger(path))


class RegistryTests(unittest.TestCase):

    def test_the_server_registers_the_five_tools(self):
        server = gateway.build_server(factory)
        names = sorted(server._tool_manager._tools)
        self.assertEqual(sorted(name for _step, name in gateway.GATEWAY_STEPS),
                         names)

    def test_the_tool_names_follow_the_contract(self):
        for _step, name in gateway.GATEWAY_STEPS:
            with self.subTest(name=name):
                self.assertRegex(name, NAME_PATTERN)
                self.assertEqual("target", name.split("_")[0])

    def test_every_step_of_the_plan_has_a_tool(self):
        steps = {step for step, _name in gateway.GATEWAY_STEPS}
        self.assertEqual({"analyze_open", "function_locate", "breakpoint_set",
                          "run_to", "decompile"}, steps)


class ToolTests(unittest.TestCase):
    """The tools, called through the server (so the factory wiring is covered)."""

    def tool(self, server, name):
        return server._tool_manager._tools[name].fn

    def test_target_open_reports_the_descriptor(self):
        server = gateway.build_server(factory)
        answer = self.tool(server, "target_open")()
        self.assertTrue(answer["success"], answer)
        self.assertTrue(answer["correlatable"])
        self.assertEqual("0x140000000", answer["image_base"])

    def test_target_open_reports_a_binary_the_debugger_does_not_have(self):
        """Not loaded at all is a failure to report, not a bad identity."""
        server = gateway.build_server(lambda: (FakeGhidra(),
                                               lambda: FakeDebugger(r"D:\copy.exe")))
        answer = self.tool(server, "target_open")()
        self.assertFalse(answer["success"])
        self.assertEqual(target_helper.ERROR_NOT_LOADED, answer["code"])

    def test_target_open_reports_a_copy_as_a_successful_analysis(self):
        """The same name in another directory is a *reported* mismatch."""
        server = gateway.build_server(
            lambda: (FakeGhidra(), lambda: FakeDebugger(r"D:\builds\sample.exe")))
        answer = self.tool(server, "target_open")()
        self.assertTrue(answer["success"], answer)
        self.assertFalse(answer["correlatable"])
        self.assertEqual("name-only", answer["identity"]["match"])
        self.assertIn("copy", answer["identity"]["reason"])

    def test_target_locate_returns_the_static_address(self):
        server = gateway.build_server(factory)
        answer = self.tool(server, "target_locate")("main")
        self.assertTrue(answer["success"], answer)
        self.assertEqual("0x140001234", answer["static_address"])

    def test_target_locate_reports_a_missing_function(self):
        server = gateway.build_server(factory)
        answer = self.tool(server, "target_locate")("nope")
        self.assertFalse(answer["success"])
        self.assertEqual(target_helper.ERROR_NOT_FOUND, answer["code"])

    def test_target_breakpoint_translates_the_address(self):
        server = gateway.build_server(factory)
        answer = self.tool(server, "target_breakpoint")("main")
        self.assertTrue(answer["success"], answer)
        expected = hex(0x140001234 - IMAGE_BASE + MODULE_BASE)
        self.assertEqual(expected, answer["runtime_address"])

    def test_target_breakpoint_refuses_without_touching_the_debugger(self):
        debugger = FakeDebugger(r"D:\builds\sample.exe")
        server = gateway.build_server(lambda: (FakeGhidra(), lambda: debugger))
        answer = self.tool(server, "target_breakpoint")("main")
        self.assertFalse(answer["success"])
        self.assertEqual(target_helper.ERROR_NOT_SAME_BINARY, answer["code"])
        self.assertEqual([("ListModules", None)], debugger.calls)

    def test_target_run_to_returns_the_registers(self):
        server = gateway.build_server(factory)
        answer = self.tool(server, "target_run_to")("main")
        self.assertTrue(answer["success"], answer)
        self.assertIn("RAX", answer["registers"])

    def test_target_decompile_returns_the_code(self):
        server = gateway.build_server(factory)
        answer = self.tool(server, "target_decompile")("main")
        self.assertTrue(answer["success"], answer)
        self.assertIn("int main(void)", answer["code"])

    def test_a_client_that_cannot_be_built_is_a_code_not_a_crash(self):
        def broken_factory():
            raise RuntimeError("no bearer token for the x64dbg MCP server")
        server = gateway.build_server(broken_factory)
        answer = self.tool(server, "target_open")()
        self.assertFalse(answer["success"])
        self.assertEqual("GATEWAY_ERROR", answer["code"])
        self.assertIn("token", answer["reason"])


class ResultShapeTests(unittest.TestCase):
    """Every answer carries `success`; a failure carries a code."""

    def _answer(self, call):
        try:
            return call()
        except Exception as exc:  # noqa: BLE001 - the point of the test
            self.fail(f"the tool raised instead of answering: {exc}")

    def test_every_tool_answers_with_success(self):
        server = gateway.build_server(factory)
        calls = {
            "target_open": lambda: server._tool_manager._tools["target_open"].fn(),
            "target_locate": lambda: server._tool_manager._tools["target_locate"].fn("main"),
            "target_breakpoint": lambda: server._tool_manager._tools["target_breakpoint"].fn("main"),
            "target_run_to": lambda: server._tool_manager._tools["target_run_to"].fn("main"),
            "target_decompile": lambda: server._tool_manager._tools["target_decompile"].fn("main"),
        }
        for name, call in calls.items():
            with self.subTest(tool=name):
                answer = self._answer(call)
                self.assertIn("success", answer)

class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    """The server over stdio: initialize, tools/list, and a call that fails cleanly.

    The in-process tests prove the tools; this proves the *server* — framing, the
    schemas the client sees, and a failure that is a code inside a successful
    protocol answer rather than a protocol error.
    """

    async def test_the_gateway_speaks_mcp(self):
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "ghydra.gateway"],
            env={**os.environ, "PYTHONPATH": root},
        )
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                listed = await session.list_tools()
                names = sorted(tool.name for tool in listed.tools)
                self.assertEqual(
                    ["target_breakpoint", "target_decompile", "target_locate",
                     "target_open", "target_run_to"], names)

                answer = await session.call_tool("target_locate", {"name": "main"})
                text = answer.content[0].text if answer.content else ""
                document = json.loads(text)
                self.assertFalse(document["success"], document)
                self.assertTrue(str(document["code"]).startswith("TARGET_"),
                                document)


if __name__ == "__main__":
    unittest.main(verbosity=2)