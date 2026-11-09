"""The x64dbg integration: the client, the address model and the tools.

None of this needs x64dbg: a small HTTP server that answers the way the
plugin does stands in for it, so the JSON-RPC round trip, the bearer token
and the failure paths are all exercised for real.
"""

import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
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
    {
        "name": "GetDebugState",
        "description": "Returns the current debugger state.",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "NoSession",
        "description": "Fails when there is no debug session.",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "Disassemble",
        "description": "Disassembles the instructions at an address.",
        "inputSchema": {"type": "object", "properties": {
            "address": {"type": "string"},
            "count": {"type": "integer"},
        }},
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
            # The call is recorded before the answer: the delivery is what
            # matters, not the reply.
            self.server.calls.append((name, arguments))
            if self.server.reset_first and not self.server.reset_done:
                # Hang up without answering: the connection dies the way the
                # local network stack makes it die.
                self.server.reset_done = True
                self.connection.setsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                self.connection.close()
                return
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


class _QuietServer(ThreadingHTTPServer):
    """A server that can take a burst, and that the next test can rebind.

    `request_queue_size` is the listen backlog: the default of 5 refuses SYNs
    under a burst of connections, and a refused SYN is indistinguishable from a
    dead server at the client.
    """

    request_queue_size = 128
    allow_reuse_address = True
    daemon_threads = True


class FakeX64dbg:
    """The fake plugin, running on a port of its own."""

    def __init__(self, token="test-token", reset_first=False):
        self.server = _QuietServer(("127.0.0.1", 0), _Handler)
        self.server.expected_token = token
        self.server.calls = []
        self.server.errors = []
        self.server.reset_first = reset_first
        self.server.reset_done = False
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def _wait_until_ready(self, timeout=5.0):
        """Wait until the port actually answers a connect."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.settimeout(0.2)
            try:
                probe.connect(("127.0.0.1", self.port))
                return
            except OSError:
                time.sleep(0.01)
            finally:
                probe.close()
        raise RuntimeError(f"the fake plugin never started listening on {self.port}")

    def __enter__(self):
        self.thread.start()
        self._wait_until_ready()
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


# The reasons that mean the transport ate the answer, not that the debugger
# said no. The local network stack on this machine resets about one loopback
# connection in fourteen, and the client never repeats a mutating tool - that
# is the rule under test in X64dbgRetryTests. Here, in the test, repeating is
# harmless: the fake server only records the calls.
LOST_ANSWER_CODES = ("X64DBG_MISSING", "X64DBG_TIMEOUT", "X64DBG_UNCERTAIN")


def _lost_answer(result) -> str:
    """The code of a lost answer, or an empty string.

    The call comes back as the envelope of the bridge, as the text the bridge
    formats, or as the content of an MCP tool call - and the code is in one
    of the three.
    """
    texts = []
    if isinstance(result, dict):
        error = result.get("error")
        if isinstance(error, dict) and error.get("code"):
            return str(error["code"])
        texts.append(json.dumps(result))
    elif isinstance(result, str):
        texts.append(result)
    elif isinstance(result, (list, tuple)):
        for item in result:
            if isinstance(item, dict):
                texts.append(str(item.get("text", "")))
            else:
                texts.append(str(getattr(item, "text", "")))
    for code in LOST_ANSWER_CODES:
        if any(code in text for text in texts):
            return code
    return ""


def retry_on_lost_answer(action, attempts=3):
    """Run the action again when the transport ate the answer."""
    result = action()
    for _ in range(attempts - 1):
        if not _lost_answer(result):
            return result
        result = action()
    return result


def tool_result(name, **kwargs):
    """Call a bridge x64dbg tool, retrying when the transport ate the answer.

    The fake plugin is stateless, so a repeat costs nothing and cannot change an
    answer. This is the test's rule, not the product's: `_x64dbg_request` never
    repeats a mutating tool, and `X64dbgRetryTests` is what proves it.
    """
    function = getattr(bridge, name).__wrapped__
    return retry_on_lost_answer(lambda: function(**kwargs))


class X64dbgClientTests(unittest.TestCase):
    """The client against a server that answers like the plugin."""

    def test_the_client_speaks_json_rpc(self):
        with FakeX64dbg() as fake:
            client = x64dbg_helper.Client("127.0.0.1", fake.port, "test-token")
            result = client.initialize()
            self.assertEqual(result["protocolVersion"], "2024-11-05")
            self.assertEqual(len(client.list_tools()), len(CATALOGUE))
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

    def test_a_number_that_came_as_text_is_put_back(self):
        """A "--arg count=3" reaches the plugin as the string "3".

        The plugin ignores a parameter it cannot read and answers with its
        default, so the count has to be the number the caller asked for.
        """
        with FakeX64dbg() as fake:
            client = x64dbg_helper.Client("127.0.0.1", fake.port, "test-token")
            client.call_tool("Disassemble", {"address": "0x7FF7A1234000", "count": "3"})
            self.assertIn(
                ("Disassemble", {"address": "0x7FF7A1234000", "count": 3}),
                fake.calls,
            )


class X64dbgRetryTests(unittest.TestCase):
    """What happens when the connection dies in the middle of a call.

    The plugin hangs up after every response and the local network stack
    resets a connection every now and then, so the client has to try again -
    but only when the request is safe to repeat.
    """

    def test_a_read_only_tool_is_tried_again(self):
        """Nothing was changed, so trying again is safe."""
        with FakeX64dbg(reset_first=True) as fake:
            client = x64dbg_helper.Client("127.0.0.1", fake.port, "test-token")
            text = client.call_tool("ListModules")
        self.assertIn("0x7FF7A1230000", text)

    def test_a_mutating_tool_is_not_delivered_twice(self):
        """The server may already have set the breakpoint."""
        with FakeX64dbg(reset_first=True) as fake:
            client = x64dbg_helper.Client("127.0.0.1", fake.port, "test-token")
            with self.assertRaises(x64dbg_helper.X64dbgError) as caught:
                client.call_tool("SetBreakpoint", {"target": "0x7FF7A1234000"})
            self.assertEqual(caught.exception.code, "X64DBG_UNCERTAIN")
            self.assertIn("may already have acted", str(caught.exception))
            self.assertEqual(
                [name for name, _ in fake.calls], ["SetBreakpoint"],
                "the mutating tool was delivered more than once")

    def test_the_bridge_does_not_repeat_a_mutating_tool(self):
        """The same rule on the bridge side."""
        with FakeX64dbg(reset_first=True) as fake:
            with mock.patch.object(bridge, "_x64dbg_settings", return_value={
                "host": "127.0.0.1", "port": fake.port,
                "token": "test-token", "path": "",
            }):
                with self.assertRaises(bridge._X64dbgFailure) as caught:
                    bridge._x64dbg_call_tool(
                        {"host": "127.0.0.1", "port": fake.port,
                         "token": "test-token", "path": ""},
                        "SetBreakpoint", {"target": "0x7FF7A1234000"})
            self.assertEqual(caught.exception.code, "X64DBG_UNCERTAIN")
            self.assertEqual(
                [name for name, _ in fake.calls], ["SetBreakpoint"],
                "the mutating tool was delivered more than once")

    def test_a_request_that_never_left_says_the_server_is_missing(self):
        """Nothing was sent, so nothing may have happened: the server is gone.

        This is the other half of the pair. A connection that never came up
        is not the same as a connection that died on the way back, and the
        two deserve different codes: the first one means "the debugger is
        not there", the second one means "the debugger may already have
        acted". urllib3 names the two cases, and the client reads the name.
        """
        class NewConnectionError(Exception):
            """The name urllib3 gives the failure of the connect phase."""

        failure = x64dbg_helper.requests.ConnectionError("connection refused")
        failure.__cause__ = NewConnectionError("refused")
        with mock.patch.object(x64dbg_helper.requests, "post", side_effect=failure):
            client = x64dbg_helper.Client("127.0.0.1", 9094, "test-token")
            with self.assertRaises(x64dbg_helper.X64dbgError) as caught:
                client.call_tool("SetBreakpoint", {"target": "0x7FF7A1234000"})
        self.assertEqual(caught.exception.code, "X64DBG_MISSING")


class X64dbgCliTests(unittest.TestCase):
    """The CLI: the code reaches the user, and nothing escapes."""

    def _run(self, args):
        """Run the CLI and return what the user would see."""
        from click.testing import CliRunner
        from ghydra.cli.main import cli
        result = CliRunner().invoke(cli, args)
        return result, result.output + (getattr(result, "stderr", "") or "")

    def test_a_missing_server_is_reported_with_its_code(self):
        with mock.patch.object(x64dbg_helper, "resolve_config", return_value={
                "host": "127.0.0.1", "port": 9094, "token": "t", "path": ""}):
            with mock.patch.object(x64dbg_helper, "discover", return_value=None):
                result, output = self._run(["x64dbg", "status"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("X64DBG_MISSING", output)

    def test_the_plugin_text_keeps_its_state_marker(self):
        """Rich reads a bracketed word as a style.

        The plugin writes a "[state]" line with every answer, and without the
        escape the formatter swallows it as an unknown style: the agent loses
        the line that says what the debugger is doing.
        """
        from ghydra.formatters.table_formatter import TableFormatter
        formatter = TableFormatter(use_colors=False)
        text = formatter.format_x64dbg({
            "kind": "call",
            "data": {"tool": "Disassemble",
                     "text": "0x1000: sub rsp, 0x28\n[state] PAUSED at 0x2000"},
        })
        self.assertIn("[state] PAUSED at 0x2000", text)

    def test_a_missing_token_is_reported_with_its_code(self):
        with mock.patch.object(x64dbg_helper, "resolve_config", return_value={
                "host": "127.0.0.1", "port": 9094, "token": "", "path": ""}):
            result, output = self._run(["x64dbg", "status"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("X64DBG_DISABLED", output)

    def test_a_ghidra_failure_is_reported_not_raised(self):
        """The Ghidra client raises; the command has to report it."""
        from ghydra.client.exceptions import GhidraConnectionError
        with mock.patch.object(x64dbg_helper, "resolve_config", return_value={
                "host": "127.0.0.1", "port": 9094, "token": "t", "path": ""}):
            with mock.patch.object(x64dbg_helper, "discover", return_value={
                    "host": "127.0.0.1", "port": 9094, "token": "t", "path": "",
                    "unauthorized": False}):
                with mock.patch("ghydra.client.http_client.GhidraHTTPClient.get",
                                side_effect=GhidraConnectionError("no Ghidra here")):
                    result, output = self._run(["x64dbg", "target"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("no Ghidra here", output)
        self.assertNotIsInstance(result.exception, GhidraConnectionError)


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

    def test_the_file_name_is_read_on_any_platform(self):
        """os.path.basename only knows this machine's separators; ours does not."""
        self.assertEqual("cmd.exe",
                         x64dbg_helper.path_name("C:\\Windows\\System32\\cmd.exe"))
        self.assertEqual("cmd.exe", x64dbg_helper.path_name("\\\\?\\C:\\Windows\\System32\\cmd.exe"))
        self.assertEqual("cmd.exe", x64dbg_helper.path_name("/usr/bin/cmd.exe"))
        self.assertEqual("", x64dbg_helper.path_name(""))

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

    def test_the_installation_can_come_from_the_environment(self):
        """The token is the one thing that cannot be guessed, so the path to
        the installation is worth having in the environment: it is what makes
        the integration usable without editing a configuration file."""
        plugins = os.path.join(self.tmp.name, "x64", "plugins")
        os.makedirs(plugins)
        with open(os.path.join(plugins, "mcp_config.json"), "w", encoding="utf-8") as handle:
            json.dump({"IpAddress": "127.0.0.1", "Port": 9094,
                       "AuthToken": "plugin-token"}, handle)

        with mock.patch.dict(os.environ, {"GHYDRA_X64DBG_PATH": self.tmp.name}):
            settings = x64dbg_helper.resolve_config({})
        self.assertEqual(settings["token"], "plugin-token")
        self.assertEqual(settings["path"], self.tmp.name)

    def test_the_config_file_wins_over_the_environment_path(self):
        with mock.patch.dict(os.environ, {"GHYDRA_X64DBG_PATH": "C:/from-env"}):
            settings = x64dbg_helper.resolve_config({"path": "C:/from-file"})
        self.assertEqual(settings["path"], "C:/from-file")

    def test_the_environment_host_and_port_beat_the_plugin_file(self):
        """The plugin file fills the blanks; a host or a port the user set is
        not a blank.

        The plugin's own file says which address it listens on, but a host or
        a port that came from the config file or from the environment is a
        decision the user made, and the file does not get to overrule it.
        """
        root = os.path.join(self.tmp.name, "x64dbg")
        folder = os.path.join(root, "release", "x64")
        os.makedirs(folder)
        with open(os.path.join(folder, "mcp_config.json"), "w", encoding="utf-8") as handle:
            json.dump({"IpAddress": "10.9.9.9", "Port": 9999,
                       "AuthToken": "plugin-token"}, handle)

        with mock.patch.dict(os.environ, {
            "GHYDRA_X64DBG_HOST": "127.0.0.2",
            "GHYDRA_X64DBG_PORT": "1234",
            "GHYDRA_X64DBG_PATH": root,
        }):
            settings = x64dbg_helper.resolve_config({})
        self.assertEqual(settings["host"], "127.0.0.2")
        self.assertEqual(settings["port"], 1234)
        self.assertEqual(settings["token"], "plugin-token")

    def test_the_walk_starts_from_the_configured_port(self):
        """The fixed plugin walks up from the port it was told to use, so the
        walk has to start there too."""
        likely, others = x64dbg_helper.candidate_ports(9200)
        self.assertIn(9200, likely)
        self.assertIn(9201, others)

        bridge_likely, bridge_others = bridge._x64dbg_candidate_ports(9200)
        self.assertIn(9200, bridge_likely)
        self.assertIn(9201, bridge_others)

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

    def test_the_token_is_found_in_the_release_folder(self):
        """The layout x64dbg ships: release/x64/x64dbg.exe, and the file beside it."""
        root = os.path.join(self.tmp.name, "x64dbg")
        folder = os.path.join(root, "release", "x64")
        os.makedirs(folder)
        with open(os.path.join(folder, "mcp_config.json"), "w", encoding="utf-8") as handle:
            json.dump({"IpAddress": "127.0.0.1", "Port": 9094,
                       "AuthToken": "plugin-token"}, handle)

        settings = x64dbg_helper.resolve_config({"path": root})
        self.assertEqual(settings["token"], "plugin-token")
        self.assertEqual(settings["port"], 9094)


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

    def _deliver(self, tool, **kwargs):
        """Run a bridge call, and run it again if the transport ate it.

        The local network stack on this machine resets about one loopback
        connection in fourteen - with curl and with plain sockets alike, and
        with the server seeing nothing at all - so a single request is not a
        reliable way to reach the fake plugin. The bridge does not repeat a
        mutating tool, which is the rule under test in X64dbgRetryTests, so
        the retry belongs here, in the test, where repeating is harmless:
        the fake server only records the calls.
        """
        result = {}
        for _ in range(3):
            result = tool(**kwargs)
            if result.get("success"):
                return result
            code = ((result.get("error") or {}).get("code")) or ""
            if code not in ("X64DBG_MISSING", "X64DBG_TIMEOUT", "X64DBG_UNCERTAIN"):
                # A real reason - a bad token, no session, a bad address -
                # must not be papered over by a retry.
                return result
        return result

    def test_the_status_reports_the_server(self):
        # The status goes through the port scan, and the scan asks the
        # server whether it is there - so a lost answer would say "the
        # debugger is gone" for a debugger that is running.
        result = self._deliver(bridge.x64dbg_status.__wrapped__)
        self.assertTrue(result["success"], result)
        self.assertEqual(result["result"]["tools"], len(CATALOGUE))
        self.assertEqual(len(result["result"]["modules"]), 2)

    def test_the_catalogue_is_listed(self):
        result = tool_result("x64dbg_tools", )
        self.assertTrue(result["success"], result)
        self.assertEqual(result["result"]["count"], len(CATALOGUE))
        names = [tool["name"] for tool in result["result"]["tools"]]
        self.assertIn("SetBreakpoint", names)

    def test_a_tool_is_called_by_name(self):
        result = tool_result("x64dbg_call", tool="ListModules")
        self.assertTrue(result["success"], result)
        self.assertIn("0x7FF7A1230000", result["result"]["text"])

    def test_without_a_token_the_bridge_says_it_is_disabled(self):
        """There is no way to talk to the server without a token.

        That is not the same thing as the server being gone, and an agent
        that cannot tell the two apart ends up retrying a call that can
        never work.
        """
        with mock.patch.object(bridge, "_x64dbg_settings", return_value={
                "host": "127.0.0.1", "port": self.fake.port,
                "token": "", "path": ""}):
            result = tool_result("x64dbg_status", )
        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["code"], "X64DBG_DISABLED")

    def test_the_arguments_reach_the_plugin_through_the_mcp_binding(self):
        """The arguments have to survive the protocol, not just the call.

        Calling the function directly is not the same thing: the MCP layer
        binds the parameters, and the schema says what shape they arrive in.
        The arguments are therefore JSON text, which every client delivers
        as it is.
        """
        import asyncio

        async def call(arguments):
            return await bridge.mcp.call_tool("x64dbg_call", arguments)

        content = retry_on_lost_answer(lambda: asyncio.run(call({
            "tool": "SetBreakpoint",
            "tool_arguments": '{"target": "0x7FF7A1234000"}',
        })))
        text = "\n".join(
            item.get("text", "") if isinstance(item, dict)
            else getattr(item, "text", "")
            for item in content
        )
        self.assertIn(("SetBreakpoint", {"target": "0x7FF7A1234000"}), self.fake.calls,
                      "the arguments did not reach the plugin")
        self.assertIn("Breakpoint set", text)

    def test_an_object_reaches_the_plugin_through_the_mcp_binding(self):
        """An object is accepted too, for the clients that deliver one."""
        import asyncio

        retry_on_lost_answer(lambda: asyncio.run(bridge.mcp.call_tool("x64dbg_call", {
            "tool": "SetBreakpoint",
            "tool_arguments": {"target": "0x7FF7A1234000"},
        })))
        self.assertIn(("SetBreakpoint", {"target": "0x7FF7A1234000"}), self.fake.calls,
                      "the object did not reach the plugin")

    def test_the_types_a_client_flattened_are_restored(self):
        """The bug this desktop showed: a client that re-encodes the
        container the protocol uses for the parameters turns every value of a
        nested object into a string.

        The plugin ignores a parameter it cannot read and does something
        else - the call came back with the default count instead of the one
        that was asked for. The plugin's own schema says what each parameter
        is, so the type is put back here.
        """
        import asyncio

        asyncio.run(bridge.mcp.call_tool("x64dbg_call", {
            "tool": "Disassemble",
            "tool_arguments": {"address": "0x7FF7A1234000", "count": "3"},
        }))
        self.assertIn(
            ("Disassemble", {"address": "0x7FF7A1234000", "count": 3}),
            self.fake.calls,
            "the count reached the plugin as text instead of a number",
        )

    def test_the_schema_asks_for_the_text_and_not_for_an_object(self):
        """The schema is what the agent reads, so it has to ask for the form
        that survives the client."""
        import asyncio

        tools = asyncio.run(bridge.mcp.list_tools())
        schema = next(t.inputSchema for t in tools if t.name == "x64dbg_call")
        declared = schema["properties"]["tool_arguments"]
        kinds = [part.get("type") for part in declared.get("anyOf", [])]
        self.assertIn("string", kinds)
        self.assertNotIn("object", kinds,
                         "the schema asks for an object, and a client flattens it")

    def test_an_object_is_accepted_when_the_call_is_made_directly(self):
        result = retry_on_lost_answer(lambda: tool_result("x64dbg_call", 
            tool="SetBreakpoint", tool_arguments={"target": "0x7FF7A1234000"}))
        self.assertTrue(result["success"], result)
        self.assertIn(("SetBreakpoint", {"target": "0x7FF7A1234000"}), self.fake.calls)

    def test_arguments_that_are_not_json_are_refused(self):
        result = tool_result("x64dbg_call", 
            tool="SetBreakpoint", tool_arguments="not json at all")
        self.assertFalse(result["success"], result)
        self.assertEqual(result["error"]["code"], "X64DBG_BAD_ARGS")

    def test_no_tool_declares_a_parameter_the_protocol_reserves(self):
        """"arguments" is the container the protocol uses for the parameters.

        A tool parameter with that name is a hazard: a client that flattens
        the two drops the value, and the tool does something else instead of
        failing.
        """
        reserved = ("arguments",)
        for tool in bridge.mcp._tool_manager.list_tools():
            schema = getattr(tool, "parameters", None) or {}
            properties = list((schema.get("properties") or {}).keys())
            with self.subTest(tool=tool.name):
                for name in properties:
                    self.assertNotIn(name, reserved)

    def test_the_address_is_translated_for_the_breakpoint(self):
        """The whole point: a Ghidra address becomes a live breakpoint."""
        program = {
            "success": True,
            "result": {"path": "C:\\Windows\\System32\\cmd.exe",
                       "imageBase": "0x140000000"},
        }
        with mock.patch.object(bridge, "safe_get", return_value=program):
            with mock.patch.object(bridge, "_get_instance_port", return_value=8192):
                result = self._deliver(bridge.x64dbg_breakpoint_at.__wrapped__,
                                       address="0x140001234")

        self.assertTrue(result["success"], result)
        self.assertEqual(result["result"]["static_address"], "0x140001234")
        self.assertEqual(result["result"]["runtime_address"], "0x7ff7a1231234")
        self.assertIn(("SetBreakpoint", {"target": "0x7ff7a1231234"}), self.fake.calls)

    def test_the_address_moves_the_instruction_pointer(self):
        """"Go to" moves the IP: it is not a read."""
        program = {
            "success": True,
            "result": {"path": "C:\\Windows\\System32\\cmd.exe",
                       "imageBase": "0x140000000"},
        }
        with mock.patch.object(bridge, "safe_get", return_value=program):
            with mock.patch.object(bridge, "_get_instance_port", return_value=8192):
                result = self._deliver(bridge.x64dbg_go_to.__wrapped__,
                                       address="0x140001234")

        self.assertTrue(result["success"], result)
        self.assertEqual(result["result"]["runtime_address"], "0x7ff7a1231234")
        self.assertIn(
            ("SetRegister", {"register": "cip", "value": "0x7ff7a1231234"}),
            self.fake.calls,
        )

    def test_the_target_reports_both_bases(self):
        program = {
            "success": True,
            "result": {"path": "C:\\Windows\\System32\\cmd.exe",
                       "imageBase": "0x140000000"},
        }
        with mock.patch.object(bridge, "safe_get", return_value=program):
            with mock.patch.object(bridge, "_get_instance_port", return_value=8192):
                result = tool_result("x64dbg_target", )

        self.assertTrue(result["success"], result)
        self.assertEqual(result["result"]["image_base"], 0x140000000)
        self.assertEqual(result["result"]["module_base"], 0x7FF7A1230000)

    def test_the_token_stays_out_of_the_payload(self):
        """The descriptor is handed to the agent as it is, so it holds no token."""
        program = {
            "success": True,
            "result": {"path": "C:\\Windows\\System32\\cmd.exe",
                       "imageBase": "0x140000000"},
        }
        with mock.patch.object(bridge, "safe_get", return_value=program):
            with mock.patch.object(bridge, "_get_instance_port", return_value=8192):
                result = tool_result("x64dbg_target", )

        self.assertTrue(result["success"], result)
        self.assertNotIn("test-token", json.dumps(result))

    def test_a_binary_that_is_not_loaded_is_reported(self):
        program = {
            "success": True,
            "result": {"path": "C:\\other\\app.exe", "imageBase": "0x140000000"},
        }
        with mock.patch.object(bridge, "safe_get", return_value=program):
            with mock.patch.object(bridge, "_get_instance_port", return_value=8192):
                result = tool_result("x64dbg_target", )

        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["code"], "X64DBG_NO_MATCH")

    def test_an_address_that_is_not_one_is_refused(self):
        result = tool_result("x64dbg_breakpoint_at", address="not an address")
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
