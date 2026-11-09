#!/usr/bin/env python3
"""Tests for `ghydra assert` (I16).

No Ghidra, no network: a fake client answers the REST calls, and the pure
evaluator/renderers are exercised directly. The honesty rules matter as much
as the happy path: a truncated listing must never read as a pass.

Run with:  python test_assertions.py
"""

import json
import os
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ghydra import assertions as A  # noqa: E402
from ghydra.cli.assertions_cmd import assert_cmd  # noqa: E402


class FakeClient:
    """Answers the handful of endpoints the assertions use."""

    def __init__(self, imports=(), strings=(), functions=(),
                 xrefs=0, path=None, total=None, fail_404=False):
        self.imports = [{"name": i} if isinstance(i, str) else i for i in imports]
        self.strings = list(strings)
        self.functions = set(functions)
        self.xrefs = xrefs
        self.path = path
        self.total = total
        self.fail_404 = fail_404
        self.calls = []

    def get(self, endpoint, params=None):
        self.calls.append(endpoint)
        params = params or {}
        if endpoint == "symbols/imports":
            return self._listing(self.imports, params)
        if endpoint == "strings":
            return self._listing([{"value": s} for s in self.strings], params)
        if endpoint.startswith("functions/by-name/"):
            name = endpoint.rsplit("/", 1)[-1]
            if name in self.functions:
                return {"success": True, "result": {"name": name,
                                                    "address": "0x401000"}}
            raise _NotFound("FUNCTION_NOT_FOUND")
        if endpoint.startswith("xrefs/to-name/"):
            return {"success": True, "result": [{"address": "0x1"}] * self.xrefs,
                    "meta": {"total": self.xrefs}}
        if endpoint == "analysis/call-path":
            return {"success": True, "result": {"path": self.path,
                                                "reason": None if self.path else "no path"}}
        raise AssertionError(f"unexpected endpoint {endpoint}")

    def _listing(self, items, params):
        offset = params.get("offset", 0)
        limit = params.get("limit", 1000)
        page = items[offset:offset + limit]
        total = self.total if self.total is not None else len(items)
        return {"success": True, "result": page, "meta": {"total": total}}


class _NotFound(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class LoadTests(unittest.TestCase):
    def _write(self, payload):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                             encoding="utf-8")
        handle.write(json.dumps(payload))
        handle.close()
        self.addCleanup(lambda: os.unlink(handle.name))
        return handle.name

    def test_a_bare_list_and_a_wrapped_list_both_load(self):
        for payload in ([{"kind": "has_import", "name": "CreateFileW"}],
                        {"assertions": [{"kind": "has_import", "name": "CreateFileW"}]}):
            with self.subTest(payload=payload):
                loaded = A.load_assertions(self._write(payload))
                self.assertEqual(1, len(loaded))
                self.assertEqual("A1", loaded[0]["id"])

    def test_an_unknown_kind_is_refused(self):
        with self.assertRaises(A.AssertionError_) as caught:
            A.load_assertions(self._write([{"kind": "smells_bad", "name": "x"}]))
        self.assertEqual(A.ERROR_UNKNOWN_KIND, caught.exception.code)

    def test_missing_fields_are_refused(self):
        for payload in ([{"kind": "has_import"}],
                        [{"kind": "reaches", "from": "main"}],
                        ["not an object"]):
            with self.subTest(payload=payload):
                with self.assertRaises(A.AssertionError_):
                    A.load_assertions(self._write(payload))

    def test_a_missing_file_is_reported(self):
        with self.assertRaises(A.AssertionError_) as caught:
            A.load_assertions(os.path.join(tempfile.gettempdir(), "nope-xyz.json"))
        self.assertEqual(A.ERROR_BAD_FILE, caught.exception.code)


class EvaluationTests(unittest.TestCase):
    def _one(self, client, kind, name=None, **extra):
        spec = {"id": "A1", "kind": kind, "name": name, **extra}
        return A.evaluate(client, [spec])["result"]["assertions"][0]

    def test_has_import_passes_on_a_match(self):
        item = self._one(FakeClient(imports=["CreateFileW"]), "has_import", "createfilew")
        self.assertEqual("pass", item["status"])
        self.assertIn("CreateFileW", item["evidence"])

    def test_no_import_passes_only_after_reading_the_whole_list(self):
        item = self._one(FakeClient(imports=["CreateFileW"]), "no_import",
                         "CreateRemoteThread")
        self.assertEqual("pass", item["status"])

    def test_a_truncated_listing_is_inconclusive_not_a_pass(self):
        # A listing longer than the page cap: every page is full, so the scan
        # never ends within the cap and absence cannot be proven.
        class Endless(FakeClient):
            def _listing(self, items, params):
                page = [{"name": f"api{i}"} for i in range(1000)]
                return {"success": True, "result": page,
                        "meta": {"total": 10 ** 9}}

        item = self._one(Endless(), "no_import", "CreateRemoteThread")
        self.assertEqual("inconclusive", item["status"])
        self.assertIn("truncated", item["evidence"])

    def test_a_match_in_a_truncated_listing_still_fails_no_import(self):
        client = FakeClient(imports=["CreateRemoteThread"] + [f"a{i}" for i in range(999)],
                            total=5000)
        item = self._one(client, "no_import", "CreateRemoteThread")
        self.assertEqual("fail", item["status"])

    def test_has_string_matches_a_substring(self):
        item = self._one(FakeClient(strings=["GET /api/v1/telemetry HTTP/1.1"]),
                         "has_string", "/api/v1/telemetry")
        self.assertEqual("pass", item["status"])

    def test_has_function_handles_a_404_as_the_answer(self):
        item = self._one(FakeClient(functions=set()), "has_function", "main")
        self.assertEqual("fail", item["status"])
        self.assertIn("does not exist", item["evidence"])

    def test_no_function_passes_when_it_is_absent(self):
        item = self._one(FakeClient(functions=set()), "no_function", "execve")
        self.assertEqual("pass", item["status"])

    def test_a_transport_error_is_not_turned_into_a_verdict(self):
        class Broken(FakeClient):
            def get(self, endpoint, params=None):
                raise RuntimeError("connection reset")
        with self.assertRaises(RuntimeError):
            self._one(Broken(), "has_function", "main")

    def test_reaches_passes_with_a_path(self):
        item = self._one(FakeClient(path=[{"from": "main", "to": "strcmp"}]),
                         "reaches", **{"from": "main", "to": "strcmp"})
        self.assertEqual("pass", item["status"])
        self.assertIn("1 hop", item["evidence"])

    def test_reaches_fails_and_keeps_the_reason(self):
        item = self._one(FakeClient(path=None), "reaches", **{"from": "a", "to": "b"})
        self.assertEqual("fail", item["status"])
        self.assertIn("no path", item["evidence"])

    def test_has_xref_to_counts_references(self):
        self.assertEqual("pass", self._one(FakeClient(xrefs=3),
                                           "has_xref_to", "strlen")["status"])
        self.assertEqual("fail", self._one(FakeClient(xrefs=0),
                                           "has_xref_to", "strlen")["status"])

    def test_the_report_counts_every_status(self):
        report = A.evaluate(FakeClient(imports=["A"]), [
            {"id": "1", "kind": "has_import", "name": "A"},
            {"id": "2", "kind": "no_import", "name": "A"},
            {"id": "3", "kind": "has_function", "name": "main"},
        ])
        result = report["result"]
        self.assertEqual(3, result["total"])
        self.assertEqual(1, result["passed"])
        self.assertEqual(2, result["failed"])
        self.assertFalse(result["ok"])


class RendererTests(unittest.TestCase):
    def _report(self):
        return A.evaluate(FakeClient(imports=["A"]), [
            {"id": "1", "kind": "has_import", "name": "A"},
            {"id": "2", "kind": "no_import", "name": "A", "message": "must not be there"},
            {"id": "3", "kind": "has_function", "name": "main"},
        ])

    def test_text_marks_every_assertion(self):
        text = A.to_text(self._report())
        self.assertIn("[PASS] 1 has_import A", text)
        self.assertIn("[FAIL] 2 no_import A", text)
        self.assertIn("must not be there", text)

    def test_junit_is_valid_xml_with_the_right_counts(self):
        root = ET.fromstring(A.to_junit(self._report()))
        self.assertEqual("testsuite", root.tag)
        self.assertEqual("3", root.get("tests"))
        self.assertEqual("2", root.get("failures"))
        self.assertEqual(3, len(root.findall("testcase")))

    def test_junit_escapes_markup_in_messages(self):
        report = {"result": {"assertions": [
            {"id": "1", "kind": "has_string", "name": "a<b&c",
             "status": "fail", "evidence": "<script>", "message": 'q"q'}]}}
        root = ET.fromstring(A.to_junit(report))
        self.assertEqual(1, len(root.findall("testcase")))

    def test_sarif_has_one_result_per_failure(self):
        document = json.loads(A.to_sarif(self._report()))
        self.assertEqual("2.1.0", document["version"])
        run = document["runs"][0]
        self.assertEqual("ghydra-assert", run["tool"]["driver"]["name"])
        self.assertEqual(2, len(run["results"]))
        self.assertEqual({"has_import", "no_import", "has_function"},
                         {rule["id"] for rule in run["tool"]["driver"]["rules"]})

    def test_an_all_green_report_has_no_sarif_results(self):
        report = A.evaluate(FakeClient(imports=["A"]),
                            [{"id": "1", "kind": "has_import", "name": "A"}])
        document = json.loads(A.to_sarif(report))
        self.assertEqual([], document["runs"][0]["results"])


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                                  encoding="utf-8")
        json.dump([{"id": "1", "kind": "has_import", "name": "A"},
                   {"id": "2", "kind": "no_import", "name": "A"}], self.handle)
        self.handle.close()
        self.path = self.handle.name
        self.addCleanup(lambda: os.unlink(self.path))

    def _invoke(self, args, client=None):
        from click.testing import CliRunner
        return CliRunner().invoke(assert_cmd, args,
                                  obj={'client': client or FakeClient(imports=["A"])})

    def test_a_failure_exits_one(self):
        result = self._invoke(["-f", self.path])
        self.assertEqual(1, result.exit_code, result.output)
        self.assertIn("[FAIL]", result.output)

    def test_an_all_green_report_exits_zero(self):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                             encoding="utf-8")
        json.dump([{"id": "1", "kind": "no_import", "name": "CreateRemoteThread"}],
                  handle)
        handle.close()
        self.addCleanup(lambda: os.unlink(handle.name))
        result = self._invoke(["-f", handle.name], client=FakeClient(imports=[]))
        self.assertEqual(0, result.exit_code, result.output)

    def test_a_bad_file_exits_two(self):
        result = self._invoke(["-f", os.path.join(tempfile.gettempdir(), "nope.json")])
        self.assertEqual(2, result.exit_code)
        self.assertIn("ASSERTION_BAD_FILE", result.output)

    def test_the_junit_report_is_written_to_a_file(self):
        target = self.path + ".xml"
        self.addCleanup(lambda: os.path.exists(target) and os.unlink(target))
        result = self._invoke(["-f", self.path, "--format", "junit", "-o", target])
        self.assertEqual(1, result.exit_code)
        root = ET.parse(target).getroot()
        self.assertEqual("2", root.get("tests"))

    def test_the_sarif_report_is_written_to_a_file(self):
        target = self.path + ".sarif"
        self.addCleanup(lambda: os.path.exists(target) and os.unlink(target))
        self._invoke(["-f", self.path, "--format", "sarif", "-o", target])
        document = json.loads(open(target, encoding="utf-8").read())
        self.assertEqual("2.1.0", document["version"])

class MissingNameTests(unittest.TestCase):
    """A name that is not in the binary is a verdict, not a crash.

    Found by running `examples/asserts.json` against a live instance: the 404
    escaped `reaches` and `has_xref_to` and turned the whole run into exit 2.
    """

    class Missing(Exception):
        def __init__(self, code="FUNCTION_NOT_FOUND"):
            super().__init__("No function at address or named 'x'")
            self.code = code

    def _assert(self, kind, name, **extra):
        class Client:
            def get(self, endpoint, params=None):
                raise MissingNameTests.Missing()
        spec = {"id": "X1", "kind": kind, "name": name, **extra}
        return A.evaluate(Client(), [spec])["result"]["assertions"][0]

    def test_has_function_reports_a_missing_function(self):
        item = self._assert("has_function", "main")
        self.assertEqual("fail", item["status"])
        self.assertIn("does not exist", item["evidence"])

    def test_reaches_reports_a_missing_end(self):
        item = self._assert("reaches", "main", **{"from": "main", "to": "strcmp"})
        self.assertEqual("fail", item["status"])
        self.assertIn("not in the binary", item["evidence"])

    def test_has_xref_reports_a_missing_name(self):
        item = self._assert("has_xref_to", "GetProcAddress")
        self.assertEqual("fail", item["status"])
        self.assertIn("not present", item["evidence"])

    def test_a_transport_error_still_raises(self):
        class Broken:
            def get(self, endpoint, params=None):
                raise RuntimeError("connection reset")
        with self.assertRaises(RuntimeError):
            A.evaluate(Broken(), [{"id": "X", "kind": "has_xref_to",
                                   "name": "strlen"}])


class ExampleTests(unittest.TestCase):
    """`examples/` must keep working: it is the thing people copy."""

    ROOT = os.path.dirname(os.path.abspath(__file__))

    def test_the_example_assertions_load_and_cover_the_kinds(self):
        items = A.load_assertions(os.path.join(self.ROOT, "examples", "asserts.json"))
        self.assertEqual(8, len(items))
        self.assertEqual(len({item["id"] for item in items}), len(items))
        self.assertIn("reaches", {item["kind"] for item in items})
        for item in items:
            self.assertTrue(item["message"], item["id"])

    def test_a_reaches_assertion_is_labelled_with_the_pair(self):
        items = A.load_assertions(os.path.join(self.ROOT, "examples", "asserts.json"))
        reaches = [item for item in items if item["kind"] == "reaches"][0]
        self.assertEqual("main -> strcmp", reaches["name"])

    def test_the_example_workflow_runs_the_cli_and_stops_the_run(self):
        """Structural checks that need no YAML parser (the project has none)."""
        path = os.path.join(self.ROOT, "examples", "ci", "analyze.yml")
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        for expected in ("ghydra assert", "--format sarif",
                         "ghydra headless start", "ghydra headless stop",
                         "upload-sarif", "if: always()", "jobs:",
                         "examples/asserts.json".replace("examples/asserts.json",
                                                         "asserts.json")):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)
        # A workflow that does not mention a stop step leaks the project lock.
        self.assertLess(text.index("ghydra headless start"),
                        text.index("ghydra headless stop"))

    def test_the_example_workflow_parses_when_a_yaml_parser_is_available(self):
        """PyYAML is not a dependency, so this is a bonus check, not a gate."""
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML is not installed (it is not a dependency)")
        path = os.path.join(self.ROOT, "examples", "ci", "analyze.yml")
        with open(path, encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
        self.assertIsInstance(document, dict)
        self.assertIn("jobs", document)


if __name__ == "__main__":
    unittest.main(verbosity=2)
