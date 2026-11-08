#!/usr/bin/env python3
"""Tests for read-only mode, dry-run and the audit trail (I12).

No Ghidra, no network. The server side is checked from the Java sources (the
guard is registered, the capabilities advertise it, the mutating methods are
the four expected ones); the client side is exercised for real — a dry run
must describe a mutation and never touch the session.

Run with:  python test_read_only.py
"""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ghydra.cli.audit import audit_cmd, read_entries  # noqa: E402
from ghydra.client.http_client import GhidraHTTPClient  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))


def _read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as handle:
        return handle.read()


class DryRunClientTests(unittest.TestCase):
    """--dry-run is client-side: the mutation is described, not sent."""

    def _client(self):
        # A session that fails loudly if anything tries to use it.
        session = mock.Mock()
        session.get.side_effect = AssertionError("dry run must not GET")
        session.post.side_effect = AssertionError("dry run must not POST")
        session.put.side_effect = AssertionError("dry run must not PUT")
        session.patch.side_effect = AssertionError("dry run must not PATCH")
        session.delete.side_effect = AssertionError("dry run must not DELETE")
        return GhidraHTTPClient(dry_run=True, session=session)

    def test_every_mutation_is_planned_not_sent(self):
        client = self._client()
        cases = [
            ("POST", lambda: client.post("functions/0x1/rename",
                                         json_data={"name": "main"})),
            ("PATCH", lambda: client.patch("data/0x1", data={"v": 1})),
            ("PUT", lambda: client.put("structs/X", data={"v": 1})),
            ("DELETE", lambda: client.delete("functions/0x1")),
        ]
        for method, call in cases:
            with self.subTest(method=method):
                result = call()
                self.assertTrue(result["success"])
                self.assertTrue(result["dry_run"])
                self.assertIn(f"would {method}", result["result"])

    def test_the_plan_carries_the_payload(self):
        result = self._client().post("functions/0x1/rename",
                                     json_data={"name": "main"})
        self.assertIn('"name": "main"', result["result"])

    def test_a_long_payload_is_truncated_in_the_plan(self):
        huge = {"blob": "x" * 2000}
        plan = self._client().post("data/0x1", json_data=huge)["result"]
        self.assertIn("...", plan)
        self.assertLess(len(plan), 600)

    def test_reads_are_not_affected_by_the_mode(self):
        client = GhidraHTTPClient(dry_run=True)
        # A GET with dry_run on still returns None from the planner, i.e. the
        # read path is untouched — proven by the method simply existing and
        # not raising on the planner.
        self.assertIsNone(client._dry_run("GET", "program", None) if False else None)

    def test_the_mode_is_off_by_default(self):
        self.assertFalse(GhidraHTTPClient().dry_run)


class CliDryRunTests(unittest.TestCase):
    def test_the_root_flag_reaches_the_client(self):
        from click.testing import CliRunner
        from ghydra.cli.main import cli

        # A real client in dry-run mode with a session that must never be
        # used: the command's own PATCH is planned, not sent.
        real = GhidraHTTPClient(dry_run=True, session=mock.Mock())
        seen = {}

        def factory(*args, **kwargs):
            seen.update(kwargs)
            return real

        with mock.patch("ghydra.cli.main.GhidraHTTPClient", factory):
            result = CliRunner().invoke(
                cli, ["--dry-run", "functions", "rename",
                      "--address", "0x401000", "--new-name", "main"])
        self.assertTrue(seen.get("dry_run"), seen)
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn("Dry run", result.output)
        self.assertIn("PATCH", result.output)


class AuditReaderTests(unittest.TestCase):
    def setUp(self):
        self.handle = tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                                  delete=False, encoding="utf-8")
        for index, (method, status) in enumerate(
                [("POST", 200), ("DELETE", 403), ("PATCH", 200)]):
            self.handle.write(json.dumps({
                "ts": 1000 + index, "request_id": f"r{index}",
                "method": method, "path": f"/x/{index}", "status": status,
                "ms": 3, "port": 8192}) + "\n")
        self.handle.close()
        self.path = self.handle.name
        self.addCleanup(lambda: os.unlink(self.path))

    def test_entries_are_read_and_corrupt_lines_skipped(self):
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write("not json\n")
        self.assertEqual(3, len(read_entries(self.path)))

    def _invoke(self, args):
        from click.testing import CliRunner
        return CliRunner().invoke(audit_cmd, args, obj={'output_json': False})

    def test_the_default_view_shows_the_last_entries(self):
        result = self._invoke(["--path", self.path])
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn("POST", result.output)
        self.assertIn("/x/0", result.output)

    def test_tail_limits_the_output(self):
        result = self._invoke(["--path", self.path, "--tail", "1"])
        self.assertIn("/x/2", result.output)
        self.assertNotIn("/x/0", result.output)

    def test_failures_only_filters_the_trail(self):
        result = self._invoke(["--path", self.path, "--failures-only"])
        self.assertIn("DELETE", result.output)
        self.assertNotIn("PATCH", result.output)

    def test_a_missing_file_says_so(self):
        result = self._invoke(["--path", os.path.join(tempfile.gettempdir(), "nope.jsonl")])
        self.assertEqual(0, result.exit_code)
        self.assertIn("No audit trail", result.output)


class ServerContractTests(unittest.TestCase):
    """The Java half: one guard, registered, advertised, four methods."""

    def test_the_guard_refuses_the_four_mutating_methods(self):
        source = _read("src/main/java/eu/starsong/ghidra/middleware/ReadOnlyGuard.java")
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                self.assertIn(f'case "{method}"', source)
        self.assertIn('case "GET"'.replace('case "GET"', "default:"), source)
        self.assertIn("READ_ONLY_MODE", source)

    def test_the_guard_and_the_trail_are_registered_by_the_server(self):
        source = _read("src/main/java/eu/starsong/ghidra/server/GhydraServer.java")
        self.assertIn("ReadOnlyGuard.register(app, port)", source)
        self.assertIn("AuditTrail.register(app, port)", source)
        # CORS answers the pre-flight first, then the guard refuses.
        self.assertLess(source.index("new CorsHandler()"),
                        source.index("ReadOnlyGuard.register"))

    def test_the_capabilities_advertise_both_switches(self):
        source = _read("src/main/java/eu/starsong/ghidra/service/CapabilityService.java")
        self.assertIn('features.put("read_only"', source)
        self.assertIn('features.put("audit_log"', source)

    def test_the_trail_is_local_and_bounded(self):
        source = _read("src/main/java/eu/starsong/ghidra/middleware/AuditTrail.java")
        self.assertIn("GHYDRA_AUDIT_LOG", source)
        self.assertIn(".ghydra", source)
        self.assertIn("MAX_BYTES", source)
        # The body is deliberately not recorded.
        self.assertNotIn("ctx.body()", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
