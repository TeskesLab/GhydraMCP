#!/usr/bin/env python3
"""Consumer-visible scripting regressions, without Ghidra or PyGhidra.

A bounded loopback REST fixture runs only the Python snippets defined here in
isolated subprocesses. It models the script service's captured output and
nested execution outcome, not Ghidra's Python provider or program bindings.
MCP calls and CLI commands use their real HTTP transports and formatters.

Run with: python tests/test_scripts.py
"""

import asyncio
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast
from unittest import mock

from click.testing import CliRunner

# The tests live in tests/; the code and the repository are one level up.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# The fixture answers in milliseconds, but it runs a real Python subprocess for
# each script, and a loaded machine stretches that: measured, one run in ten
# took over 20 s to answer. The bridge's default transport timeout is the one a
# real Ghidra needs (900 s), and a fixture that misses a reply would hold the
# suite for that long - the suite was measured hanging about one run in eight.
# The timeout is read when the bridge is imported, so it is set here.
os.environ.setdefault("GHIDRA_TIMEOUT", "60")

import bridge_mcp_hydra as bridge
from ghydra.cli.main import cli


OUTPUT_SOURCE = 'print("PYTHON_RESULT", 6 * 7)\nprint("second line: café 雪")'
ARGS_SOURCE = (
    'import hashlib, json, sys\n'
    'args = sys.argv[1:]\n'
    'data = json.dumps(args, ensure_ascii=False).encode("utf-8")\n'
    'print("argc=" + str(len(args)))\n'
    'print("sha256=" + hashlib.sha256(data).hexdigest())'
)
ERROR_SOURCE = 'print("before failure")\nraise RuntimeError("script exploded: 雪")'
SCRIPT_SOURCES = {OUTPUT_SOURCE, ARGS_SOURCE, ERROR_SOURCE}


class _ScriptHTTPServer(ThreadingHTTPServer):
    allow_scripts = True

    # The bridge opens a connection per call (one session per thread, and a
    # fresh event loop for every call_tool), so a burst can arrive faster
    # than the server accepts it. With the default backlog of 5 Windows
    # refuses the excess outright, and every retry lands in the same closed
    # window - which reached the tests as an unretryable CONNECTION_ERROR.
    request_queue_size = 128
    allow_reuse_address = True


class _ScriptHandler(BaseHTTPRequestHandler):
    # HTTP/1.0 closes the connection after every answer, and the bridge keeps
    # one keep-alive session per thread: the next request then travels on a
    # socket the server has already closed, which on this machine does not read
    # as a reset - it waits for an answer that will never come. Measured: the
    # suite failed two runs in six, each on a request that timed out against a
    # fixture that had answered the one before. With HTTP/1.1 the connection
    # stays open, and `Content-Length` on every reply (set in `_reply`) is what
    # makes the reuse correct.
    protocol_version = "HTTP/1.1"
    def setup(self):
        super().setup()
        self.connection.settimeout(3)

    def log_message(self, format: str, *args: object) -> None:
        pass

    def _reply(self, status, response):
        body = json.dumps(response, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status, code, message):
        self._reply(status, {
            "success": False,
            "error": {"code": code, "message": message},
        })

    def do_GET(self):
        if self.path != "/scripts":
            self._error(404, "NOT_FOUND", "Unknown endpoint")
            return
        self._reply(200, {"success": True, "result": [
            {"name": "Probe.py", "path": "/scripts/Probe.py", "category": "Tests"},
            {"name": "Rename.java", "path": "/scripts/Rename.java", "category": "Tests"},
        ]})

    def do_POST(self):
        # Drain the body before replying. An early 403/404/400 that leaves
        # unread bytes in the socket makes Windows reset the connection
        # (WSAECONNRESET), so the client sees a transport error instead of the
        # structured REST error this fixture is meant to model.
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length > 0 else b""
        if self.path != "/scripts/run":
            self._error(404, "NOT_FOUND", "Unknown endpoint")
            return
        if not cast(_ScriptHTTPServer, self.server).allow_scripts:
            self._error(403, "SCRIPTS_DISABLED", "Script execution is disabled")
            return
        if not 0 < length <= 16384:
            self._error(400, "BAD_REQUEST", "Invalid request size")
            return
        request = json.loads(body)
        source = request.get("source")
        filename = request.get("filename", "adhoc.java")
        language = request.get("language")
        if language not in ("python", "python3") and not (
                language is None and filename.endswith(".py")):
            self._error(400, "INVALID_LANGUAGE", "Python source needs a Python runtime")
            return
        if source not in SCRIPT_SOURCES:
            self._error(400, "INVALID_SOURCE", "Only fixture snippets are executable")
            return
        args = request.get("args", [])
        if not isinstance(args, list) or any(not isinstance(arg, str) for arg in args):
            self._error(400, "INVALID_ARGS", "Script arguments must be an array of strings")
            return
        # No shell, no arbitrary source, bounded runtime and fixed-size output.
        run = subprocess.run(
            [sys.executable, "-I", "-X", "utf8", "-c", source, *args],
            capture_output=True, text=True, encoding="utf-8", timeout=3,
        )
        error = run.stderr.strip().splitlines()[-1] if run.returncode else None
        self._reply(200, {"success": True, "result": {
            "script": filename,
            "output": run.stdout,
            "success": run.returncode == 0,
            "error": error,
        }})


class ScriptServer:
    def __enter__(self):
        self.server = _ScriptHTTPServer(("127.0.0.1", 0), _ScriptHandler)
        self.server.daemon_threads = True
        self.server.allow_scripts = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        # serve_forever() starts accepting on its own thread; a connection
        # attempted in that gap reads as the same CONNECTION_ERROR as a
        # reset, so wait until the port actually answers.
        self._wait_until_ready()
        return self

    def _wait_until_ready(self, timeout: float = 5.0) -> None:
        import socket
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port),
                                              timeout=0.25):
                    return
            except OSError:
                time.sleep(0.01)
        raise RuntimeError(
            f"the fixture on port {self.port} never accepted a connection")

    def __exit__(self, *_exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class ScriptProtocolTests(unittest.TestCase):
    def setUp(self):
        self.fixture = self.enterContext(ScriptServer())
        self.enterContext(mock.patch.dict(bridge.active_instances, {
            self.fixture.port: {"url": f"http://127.0.0.1:{self.fixture.port}"},
        }))
        self.enterContext(mock.patch.object(bridge, "RAW_OUTPUT", False))

    def call(self, tool="scripts_run", **arguments):
        # This machine resets roughly one loopback connection in fourteen
        # (documented in AGENTS.md). A connection that never reached the
        # fixture is always safe to repeat, so retry the transport failure
        # instead of letting a random test fail on the machine's timing.
        last = ""
        for attempt in range(8):
            content = asyncio.run(bridge.mcp.call_tool(tool, {
                "port": self.fixture.port, **arguments,
            }))
            last = "\n".join(
                item.get("text", "") if isinstance(item, dict)
                else getattr(item, "text", "")
                for item in content
            )
            if "CONNECTION_ERROR" not in last:
                return last
            if attempt < 7:
                # 0.05 up to 0.8 s: a cold window on this machine outlasts
                # one immediate retry, and a full suite leaves it cold.
                time.sleep(min(0.8, 0.05 * (2 ** attempt)))
        return last

    def test_python_output_survives_mcp_text_formatting(self):
        for runtime in ({"language": "python"}, {"filename": "probe.py"}):
            with self.subTest(runtime=runtime):
                text = self.call(source=OUTPUT_SOURCE, **runtime)
                self.assertIn("PYTHON_RESULT 42\nsecond line: café 雪\n", text)

    def test_json_arguments_reach_the_executing_script_without_splitting_or_loss(self):
        cases = [
            (["a,b", "雪 café", "", 'a"b', "two\nlines"], "json"),
            (["a,b", "雪 café", ""], "array"),
            ([], "json"),
            ([""], "json"),
        ]
        for args, shape in cases:
            with self.subTest(args=args, shape=shape):
                supplied = json.dumps(args, ensure_ascii=False) if shape == "json" else args
                text = self.call(source=ARGS_SOURCE, language="python", args=supplied)
                digest = hashlib.sha256(json.dumps(args, ensure_ascii=False).encode("utf-8")).hexdigest()
                self.assertIn(f"argc={len(args)}\nsha256={digest}\n", text)

    def test_empty_and_legacy_comma_arguments_remain_usable(self):
        for supplied, expected in ((None, []), ("", []), (" alpha, beta ,, ", ["alpha", "beta"])):
            with self.subTest(args=supplied):
                arguments = {} if supplied is None else {"args": supplied}
                text = self.call(source=ARGS_SOURCE, language="python", **arguments)
                digest = hashlib.sha256(json.dumps(expected).encode("utf-8")).hexdigest()
                self.assertIn(f"argc={len(expected)}\nsha256={digest}\n", text)

    def test_execution_error_keeps_partial_output_and_diagnostic(self):
        text = self.call(source=ERROR_SOURCE, language="python")
        self.assertIn("before failure\n", text)
        self.assertIn("RuntimeError: script exploded: 雪", text)
        self.assertNotIn("Done", text)

    def test_disabled_script_execution_reports_rest_error(self):
        self.fixture.server.allow_scripts = False
        text = self.call(source=OUTPUT_SOURCE, language="python")
        self.assertIn("SCRIPTS_DISABLED", text)
        self.assertIn("Script execution is disabled", text)

    def test_missing_source_reports_actionable_error(self):
        text = self.call()
        self.assertIn("MISSING_PARAMETER", text)
        self.assertIn("Either name or source is required", text)

    def test_script_catalogue_is_readable_mcp_text(self):
        text = self.call("scripts_list")
        self.assertIn("Probe.py", text)
        self.assertIn("Rename.java", text)


class ScriptCliTests(unittest.TestCase):
    def setUp(self):
        self.fixture = self.enterContext(ScriptServer())
        self.runner = CliRunner()
        # Keep user configuration and terminal styling out of command results.
        self.home = self.enterContext(tempfile.TemporaryDirectory())

    def invoke(self, *arguments):
        options = ["--host", "127.0.0.1", "--port", str(self.fixture.port), "--no-color"]
        env = {"HOME": self.home, "XDG_CONFIG_HOME": self.home, "NO_COLOR": "1"}
        # The CLI is a fresh process per attempt, so a connection that never
        # reached the fixture leaves nothing behind to repeat.
        result = None
        for attempt in range(8):
            result = self.runner.invoke(
                cli, [*options, "scripts", "run", *arguments], env=env)
            if "CONNECTION_ERROR" not in (result.output or ""):
                return result
            if attempt < 7:
                time.sleep(min(0.8, 0.05 * (2 ** attempt)))
        return result

    def test_python_file_selects_runtime_and_prints_captured_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "probe.py")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(OUTPUT_SOURCE)
            result = self.invoke("--file", path)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("PYTHON_RESULT 42\nsecond line: café 雪\n", result.output)

    def test_script_failure_exits_nonzero_and_preserves_output_and_error(self):
        result = self.invoke("--code", ERROR_SOURCE, "--language", "python")
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("before failure\n", result.output)
        self.assertIn("script exploded: 雪", result.output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
