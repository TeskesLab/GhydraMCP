#!/usr/bin/env python3
"""Tests for the error contract (I9) and the CLI entrypoint (I4).

No Ghidra, no network. The Java half is a static scan: every Response.error
call site must pass a non-empty, code-shaped string as its first literal
argument, so no handler can ship an error an agent cannot branch on.

Run with:  python tests/test_errors.py
"""

import os
import re
import subprocess
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import bridge_mcp_hydra as bridge  # noqa: E402

# Response.error("CODE", ...) or Response.error(ctx, port, "CODE", ...) — the
# leading arguments are identifiers, so the FIRST string literal after the
# paren must be the code.
ERROR_CALL = re.compile(r"Response\.error\(")
CODE_LITERAL = re.compile(r'"([^"]*)"')
CODE_FROM_EXCEPTION = re.compile(r"\.errorCode\(\)\s*,")
CODE_SHAPE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _java_error_call_sites():
    java_root = os.path.join(ROOT, "src", "main", "java")
    sites = []
    for dirpath, _dirs, files in os.walk(java_root):
        for name in files:
            if not name.endswith(".java"):
                continue
            path = os.path.join(dirpath, name)
            with open(path, encoding="utf-8") as handle:
                source = handle.read()
            rel = os.path.relpath(path, ROOT)
            for match in ERROR_CALL.finditer(source):
                # The call's arguments start after the paren; look at the next
                # 200 characters, which is enough for the leading ctx/port
                # arguments and the opening quote of the code.
                window = source[match.end():match.end() + 200]
                sites.append((rel, source[:match.end()].count("\n") + 1, window))
    return sites


class JavaErrorCodeTests(unittest.TestCase):
    def test_every_response_error_call_passes_a_code_shaped_literal(self):
        sites = _java_error_call_sites()
        self.assertGreater(len(sites), 10, "the scan found no call sites — "
                                          "the regex and the code disagree")
        problems = []
        for rel, line, window in sites:
            if CODE_FROM_EXCEPTION.search(window):
                # The exception carries its own machine-readable code
                # (e.errorCode()); the handler forwards it, which is the
                # same contract with the code defined at the throw site.
                continue
            literal = CODE_LITERAL.search(window)
            if literal is None:
                problems.append(f"{rel}:{line}: no string literal in the call")
                continue
            code = literal.group(1)
            if not code:
                problems.append(f"{rel}:{line}: empty error code")
            elif not CODE_SHAPE.match(code):
                problems.append(
                    f"{rel}:{line}: '{code}' is not CODE_SHAPED "
                    f"(uppercase, digits, underscores)")
        self.assertEqual([], problems,
                          "every Response.error must carry a machine-readable "
                          "code as its first literal:\n" + "\n".join(problems))

    def test_the_known_codes_are_still_there(self):
        text = ""
        for rel, _line, window in _java_error_call_sites():
            text += window
        for code in ("SCRIPTS_DISABLED", "SHUTDOWN_DISABLED",
                     "TRANSACTION_FAILED", "HEADLESS_LIMITATION"):
            with self.subTest(code=code):
                self.assertIn(code, text)


class FormatErrorTests(unittest.TestCase):
    def test_a_code_is_kept_in_the_text(self):
        text = bridge.format_error({
            "success": False,
            "error": {"code": "FUNCTION_NOT_FOUND", "message": "no such fn"},
        })
        self.assertIn("[FUNCTION_NOT_FOUND]", text)
        self.assertIn("no such fn", text)

    def test_the_request_id_is_kept_in_the_text(self):
        text = bridge.format_error({
            "success": False,
            "id": "req-abc-123",
            "error": {"code": "INTERNAL_ERROR", "message": "boom"},
        })
        self.assertIn("request id: req-abc-123", text)

    def test_without_an_id_no_handle_is_invented(self):
        text = bridge.format_error({
            "success": False,
            "error": {"code": "X", "message": "m"},
        })
        self.assertNotIn("request id", text)

    def test_a_string_error_still_renders(self):
        self.assertIn("plain message",
                      bridge.format_error({"error": "plain message"}))


class CliEntrypointTests(unittest.TestCase):
    """I4: UTF-8 streams and --json in any position."""

    def _run(self, *args, env_extra=None):
        env = os.environ.copy()
        # Force the encoding that used to break Rich on a Western pipe.
        env["PYTHONIOENCODING"] = "cp1252"
        env.pop("GHYDRA_JSON", None)
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            # The package's own entry, not the module: `ghydra/cli/__init__.py`
            # imports `main`, so `-m ghydra.cli.main` runs it twice and Python
            # warns about it on stderr.
            [sys.executable, "-m", "ghydra.cli", *args],
            cwd=ROOT, capture_output=True, text=True, env=env,
            encoding="utf-8", errors="replace", timeout=120,
        )

    def test_the_module_entry_prints_no_warning(self):
        """The double execution used to warn on every run."""
        result = self._run("version")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertNotIn("RuntimeWarning", result.stderr)
        self.assertNotIn("sys.modules", result.stderr)

    def test_help_survives_a_cp1252_stream(self):
        result = self._run("--help")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("Usage", result.stdout)

    def test_version_survives_a_cp1252_stream(self):
        result = self._run("version")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_json_is_accepted_after_the_subcommand(self):
        # The old behaviour: a usage error, because Click only parses the
        # root's options before the subcommand name.
        result = self._run("version", "--json")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertNotIn("Usage", result.stdout)
        self.assertNotIn("Error", result.stderr)

    def test_json_before_the_subcommand_still_works(self):
        result = self._run("--json", "version")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_the_env_var_selects_json_too(self):
        result = self._run("version", env_extra={"GHYDRA_JSON": "1"})
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

class ConnectionRetryTests(unittest.TestCase):
    """A connection that never came up is safe to repeat; a reset is not.

    This machine refuses or resets a loopback connection every now and then
    (measured ~7%). Only the refusal means nothing was sent, so only the refusal
    may be retried - including for a POST, which is otherwise never repeated.
    """

    def _refused(self):
        from requests.exceptions import ConnectionError as RequestConnectionError
        import urllib3
        return RequestConnectionError(
            "Failed to establish a new connection: [WinError 10061] No connection "
            "could be made",
            urllib3.exceptions.NewConnectionError(None, "refused"))

    def _reset(self):
        from requests.exceptions import ConnectionError as RequestConnectionError
        return RequestConnectionError("Connection aborted.",
                                      ConnectionResetError(10054, "reset"))

    def test_a_refused_connection_is_recognised(self):
        self.assertTrue(bridge._connection_never_established(self._refused()))

    def test_a_mid_flight_reset_is_not(self):
        self.assertFalse(bridge._connection_never_established(self._reset()))

    def test_the_refusal_is_retried_and_can_succeed(self):
        session = mock.Mock()
        session.request.side_effect = [self._refused(), "the answer"]
        with mock.patch.object(bridge, "_http_session", return_value=session), \
                mock.patch.object(bridge.time, "sleep"):
            result = bridge._request_with_connection_retry("POST", "http://x/y")
        self.assertEqual("the answer", result)
        self.assertEqual(2, session.request.call_count)

    def test_the_reset_is_not_retried(self):
        session = mock.Mock()
        session.request.side_effect = self._reset()
        with mock.patch.object(bridge, "_http_session", return_value=session), \
                mock.patch.object(bridge.time, "sleep"):
            with self.assertRaises(Exception):
                bridge._request_with_connection_retry("POST", "http://x/y")
        self.assertEqual(1, session.request.call_count)

    def test_the_attempts_are_bounded(self):
        session = mock.Mock()
        session.request.side_effect = self._refused()
        with mock.patch.object(bridge, "_http_session", return_value=session), \
                mock.patch.object(bridge.time, "sleep"):
            with self.assertRaises(Exception):
                bridge._request_with_connection_retry("GET", "http://x/y")
        self.assertEqual(3, session.request.call_count)


if __name__ == "__main__":
    unittest.main(verbosity=2)
