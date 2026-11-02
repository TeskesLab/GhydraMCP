"""The x64dbg integration: the client, the address model and the tools.

None of this needs x64dbg: a small HTTP server that answers the way the
plugin does stands in for it, so the JSON-RPC round trip, the bearer token
and the failure paths are all exercised for real.
"""

import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bridge_mcp_hydra as bridge
from ghydra import x64dbg as x64dbg_helper


MODULES_TEXT = (
    "0x7FF7A1230000 | 0x100000 | C:\\Windows\\System32\\cmd.exe\n"
    "0x7FF7B2220000 | 0x50000 | C:\\Windows\\System32\\ntdll.dll\n"
)

CATALOGUE = [
    {
        "name": "SetBreakpoint",
        "description": "Sets a software execution breakpoint.",
        "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}}},
        "annotations": {"readOnlyHint": False, "openWorldHint": False},
    },
    {
        "name": "ListModules",
        "description": "Lists all loaded modules.",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
]


class _Handler(BaseHTTPRequestHandler):
    """Answers like the x64dbg plugin does."""

    def log_message(self, *_args):
        """Keep the test output quiet."""

    def _reply(self, request_id, result):
        body = json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _fail(self, code, message):
        body = json.dumps({
            "jsonrpc": "2.0", "id": None,
            "error": {"code": code, "message": message},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            self._handle()
        except (BrokenPipeError, ConnectionResetError) as exc:
            # The client hung up first. A reset on the way in is a fact of
            # this machine - measured at 7% of the loopback connections - so
            # it is recorded and not raised.
            self.server.errors.append(f"{type(exc).__name__}: {exc}")
        except Exception as exc:  # pragma: no cover - a bug in the fake
            self.server.errors.append(f"{type(exc).__name__}: {exc}")
            raise

    def _handle(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        try:
            request = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._fail(-32700, "Parse error")
            return

        expected = self.server.expected_token
        if expected and self.headers.get("Authorization", "") != f"Bearer {expected}":
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        method = request.get("method")
        request_id = request.get("id")

        if method == "initialize":
            self._reply(request_id, {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "x64dbg-mcp-server", "version": "1.6"},
                "capabilities": {"tools": {"listChanged": True}},
            })
            return

        if method == "tools/list":
            self._reply(request_id, {"tools": CATALOGUE})
            return

        if method == "tools/call":
            params = request.get("params") or {}
            name = params.get("name")
            arguments = params.get("arguments") or {}
            self.server.calls.append((name, arguments))
            if name == "ListModules":
                self._reply(request_id, {
                    "content": [{"type": "text", "text": MODULES_TEXT}],
                })
                return
            if name == "SetBreakpoint":
                self._reply(request_id, {
                    "content": [{
                        "type": "text",
                        "text": f"Breakpoint set at {arguments.get('target')}",
                    }],
                })
                return
            if name == "NoSession":
                self._fail(-32602, "Error: No active debug session.")
                return
            self._reply(request_id, {
                "content": [{"type": "text", "text": f"called {name}"}],
            })
            return

        self._fail(-32601, "Method not found")


class FakeX64dbg:
    """The fake plugin, running on a port of its own."""

    def __init__(self, token="test-token"):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.expected_token = token
        self.server.calls = []
        self.server.errors = []
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        if self.server.errors:
            # The server-side view of a reset: worth keeping, because the
            # client only ever sees that the connection died.
            log = os.environ.get("GHYDRA_X64DBG_TEST_LOG")
            if log:
                with open(log, "a", encoding="utf-8") as handle:
                    handle.write(f"port {self.port}: " + " | ".join(self.server.errors) + "\n")
            else:
                print(f"[fake x64dbg {self.port}] " + " | ".join(self.server.errors),
                      file=sys.stderr)

    @property
    def port(self):
        return self.server.server_address[1]

    @property
    def calls(self):
        return self.server.calls


class X64dbgClientTests(unittest.TestCase):
    """The client against a server that answers like the plugin."""

    def test_the_client_speaks_json_rpc(self):
        with FakeX64dbg() as fake:
            client = x64dbg_helper.Client("127.0.0.1", fake.port, "test-token")
            result = client.initialize()
            self.assertEqual(result["protocolVersion"], "2024-11-05")
            self.assertEqual(len(client.list_tools()), 2)
            self.assertIn("0x7FF7A1230000", client.call_tool("ListModules", {}))

    def test_the_bearer_token_is_sent(self):
        with FakeX64dbg(token="secret") as fake:
            client = x64dbg_helper.Client("127.0.0.1", fake.port, "secret")
            client.initialize()  # would be a 401 with the wrong token

            wrong = x64dbg_helper.Client("127.0.0.1", fake.port, "not-it")
            with self.assertRaises(x64dbg_helper.X64dbgError) as caught:
                wrong.initialize()
            self.assertEqual(caught.exception.code, "X64DBG_UNAUTHORIZED")

    def test_a_missing_server_is_reported(self):
        # A closed local port is refused about two seconds later on Windows,
        # so the timeout has to be longer than that for the refusal - rather
        # than the timeout - to be what comes back.
        client = x64dbg_helper.Client("127.0.0.1", 9099, "x", timeout=5.0)
        with self.assertRaises(x64dbg_helper.X64dbgError) as caught:
            client.initialize()
        self.assertEqual(caught.exception.code, "X64DBG_MISSING")

    def test_a_tool_error_keeps_its_reason(self):
        with FakeX64dbg() as fake:
            client = x64dbg_helper.Client("127.0.0.1", fake.port, "test-token")
            with self.assertRaises(x64dbg_helper.X64dbgError) as caught:
                client.call_tool("NoSession", {})
            self.assertEqual(caught.exception.code, "X64DBG_NO_SESSION")


class X64dbgAddressTests(unittest.TestCase):
    """The address model: Ghidra's file and x64dbg's process."""

    def test_a_static_address_becomes_a_runtime_one(self):
        # cmd.exe: image base 0x140000000 in the file, loaded at 0x7FF7A1230000.
        runtime = x64dbg_helper.to_runtime(0x140001234, 0x140000000, 0x7FF7A1230000)
        self.assertEqual(runtime, 0x7FF7A1231234)

    def test_the_translation_is_reversible(self):
        runtime = x64dbg_helper.to_runtime(0x140001234, 0x140000000, 0x7FF7A1230000)
        back = x64dbg_helper.to_static(runtime, 0x140000000, 0x7FF7A1230000)
        self.assertEqual(back, 0x140001234)

    def test_the_modules_are_parsed(self):
        modules = x64dbg_helper.parse_modules(MODULES_TEXT)
        self.assertEqual(len(modules), 2)
        self.assertEqual(modules[0]["base"], 0x7FF7A1230000)
        self.assertEqual(modules[0]["size"], 0x100000)
        self.assertEqual(modules[0]["path"], "C:\\Windows\\System32\\cmd.exe")

    def test_a_module_is_matched_by_its_path(self):
        modules = x64dbg_helper.parse_modules(MODULES_TEXT)
        module = x64dbg_helper.find_module(modules, "C:\\Windows\\System32\\cmd.exe")
        self.assertIsNotNone(module)
        self.assertEqual(module["base"], 0x7FF7A1230000)

    def test_a_module_is_matched_by_its_name(self):
        """The two sides can disagree about the directory, not about the file."""
        modules = x64dbg_helper.parse_modules(MODULES_TEXT)
        module = x64dbg_helper.find_module(modules, "D:\\copy\\cmd.exe")
        self.assertIsNotNone(module)
        self.assertEqual(module["base"], 0x7FF7A1230000)

    def test_the_extended_length_prefix_is_stripped(self):
        modules = x64dbg_helper.parse_modules(MODULES_TEXT)
        module = x64dbg_helper.find_module(
            modules, "\\\\?\\C:\\Windows\\System32\\cmd.exe")
        self.assertIsNotNone(module)

    def test_a_binary_that_is_not_loaded_matches_nothing(self):
        modules = x64dbg_helper.parse_modules(MODULES_TEXT)
        self.assertIsNone(x64dbg_helper.find_module(modules, "C:\\other\\app.exe"))

    def test_an_address_is_parsed_however_it_is_written(self):
        self.assertEqual(x64dbg_helper.parse_int("0x140001234"), 0x140001234)
        self.assertEqual(x64dbg_helper.parse_int("140001234"), 0x140001234)
        self.assertEqual(x64dbg_helper.parse_int(0x140001234), 0x140001234)
        self.assertIsNone(x64dbg_helper.parse_int("not an address"))
        self.assertIsNone(x64dbg_helper.parse_int(""))


class X64dbgConfigTests(unittest.TestCase):
    """Where the server is, and the token to talk to it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_the_config_file_wins_over_the_environment(self):
        with mock.patch.dict(os.environ, {
            "GHYDRA_X64DBG_HOST": "10.0.0.1",
            "GHYDRA_X64DBG_PORT": "1234",
            "GHYDRA_X64DBG_TOKEN": "from-env",
        }):
            settings = x64dbg_helper.resolve_config({
                "host": "10.0.0.2", "port": 4321, "token": "from-file",
            })
        self.assertEqual(settings["host"], "10.0.0.2")
        self.assertEqual(settings["port"], 4321)
        self.assertEqual(settings["token"], "from-file")

    def test_the_environment_is_used_without_a_config(self):
        with mock.patch.dict(os.environ, {"GHYDRA_X64DBG_TOKEN": "from-env"}):
            settings = x64dbg_helper.resolve_config({})
        self.assertEqual(settings["token"], "from-env")

    def test_the_token_is_read_from_the_plugin_configuration(self):
        """Pointing at the installation is enough: the plugin wrote the token."""
        plugins = os.path.join(self.tmp.name, "x64", "plugins")
        os.makedirs(plugins)
        with open(os.path.join(plugins, "mcp_config.json"), "w", encoding="utf-8") as handle:
            json.dump({"IpAddress": "127.0.0.1", "Port": 9094,
                       "AuthToken": "plugin-token"}, handle)

        settings = x64dbg_helper.resolve_config({"path": self.tmp.name})
        self.assertEqual(settings["token"], "plugin-token")
        self.assertEqual(settings["port"], 9094)

    def test_a_missing_plugin_configuration_leaves_the_token_empty(self):
        settings = x64dbg_helper.resolve_config({"path": self.tmp.name})
        self.assertEqual(settings["token"], "")


class X64dbgBridgeTests(unittest.TestCase):
    """The bridge tools against the fake server."""

    def setUp(self):
        self.fake = FakeX64dbg()
        self.fake.__enter__()
        self.addCleanup(self.fake.__exit__)

        patches = [
            mock.patch.dict(os.environ, {
                "GHYDRA_X64DBG_HOST": "127.0.0.1",
                "GHYDRA_X64DBG_PORT": str(self.fake.port),
                "GHYDRA_X64DBG_TOKEN": "test-token",
            }),
            mock.patch.object(bridge, "_x64dbg_settings", side_effect=lambda: {
                "host": "127.0.0.1", "port": self.fake.port,
                "token": "test-token", "path": "",
            }),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_the_status_reports_the_server(self):
        result = bridge.x64dbg_status.__wrapped__()
        self.assertTrue(result["success"], result)
        self.assertEqual(result["result"]["tools"], 2)
        self.assertEqual(len(result["result"]["modules"]), 2)

    def test_the_catalogue_is_listed(self):
        result = bridge.x64dbg_tools.__wrapped__()
        self.assertTrue(result["success"], result)
        self.assertEqual(result["result"]["count"], 2)
        names = [tool["name"] for tool in result["result"]["tools"]]
        self.assertIn("SetBreakpoint", names)

    def test_a_tool_is_called_by_name(self):
        result = bridge.x64dbg_call.__wrapped__(tool="ListModules")
        self.assertTrue(result["success"], result)
        self.assertIn("0x7FF7A1230000", result["result"]["text"])

    def test_the_address_is_translated_for_the_breakpoint(self):
        """The whole point: a Ghidra address becomes a live breakpoint."""
        program = {
            "success": True,
            "result": {"path": "C:\\Windows\\System32\\cmd.exe",
                       "imageBase": "0x140000000"},
        }
        with mock.patch.object(bridge, "safe_get", return_value=program):
            with mock.patch.object(bridge, "_get_instance_port", return_value=8192):
                result = bridge.x64dbg_breakpoint_at.__wrapped__(address="0x140001234")

        self.assertTrue(result["success"], result)
        self.assertEqual(result["result"]["static_address"], "0x140001234")
        self.assertEqual(result["result"]["runtime_address"], "0x7ff7a1231234")
        self.assertIn(("SetBreakpoint", {"target": "0x7ff7a1231234"}), self.fake.calls)

    def test_the_target_reports_both_bases(self):
        program = {
            "success": True,
            "result": {"path": "C:\\Windows\\System32\\cmd.exe",
                       "imageBase": "0x140000000"},
        }
        with mock.patch.object(bridge, "safe_get", return_value=program):
            with mock.patch.object(bridge, "_get_instance_port", return_value=8192):
                result = bridge.x64dbg_target.__wrapped__()

        self.assertTrue(result["success"], result)
        self.assertEqual(result["result"]["image_base"], 0x140000000)
        self.assertEqual(result["result"]["module_base"], 0x7FF7A1230000)

    def test_a_binary_that_is_not_loaded_is_reported(self):
        program = {
            "success": True,
            "result": {"path": "C:\\other\\app.exe", "imageBase": "0x140000000"},
        }
        with mock.patch.object(bridge, "safe_get", return_value=program):
            with mock.patch.object(bridge, "_get_instance_port", return_value=8192):
                result = bridge.x64dbg_target.__wrapped__()

        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["code"], "X64DBG_NO_MATCH")

    def test_an_address_that_is_not_one_is_refused(self):
        result = bridge.x64dbg_breakpoint_at.__wrapped__(address="not an address")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["code"], "X64DBG_BAD_ARGS")

    def test_the_error_code_reaches_the_agent(self):
        text = bridge.FORMATTERS["x64dbg_call"]({
            "success": False,
            "error": {"code": "X64DBG_NO_SESSION", "message": "no debug session"},
        })
        self.assertIn("X64DBG_NO_SESSION", text)


class X64dbgErrorTaxonomyTests(unittest.TestCase):
    """One taxonomy of failure reasons, on both sides."""

    def test_the_bridge_and_the_module_carry_the_same_codes(self):
        self.assertEqual(set(bridge.X64DBG_ERROR_CODES), set(x64dbg_helper.ERROR_CODES))

    def test_every_x64dbg_tool_has_a_formatter(self):
        for name in ("x64dbg_status", "x64dbg_tools", "x64dbg_call",
                     "x64dbg_target", "x64dbg_breakpoint_at", "x64dbg_go_to"):
            with self.subTest(tool=name):
                self.assertIn(name, bridge.FORMATTERS)

    def test_the_tools_are_registered(self):
        names = {tool.name for tool in bridge.mcp._tool_manager.list_tools()}
        for name in ("x64dbg_status", "x64dbg_tools", "x64dbg_call",
                     "x64dbg_target", "x64dbg_breakpoint_at", "x64dbg_go_to"):
            self.assertIn(name, names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
